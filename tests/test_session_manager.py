import unittest
from http import cookies

import requests
from lxml import html

import urllib.parse as up

import functions.SessionManager.session_manager as sm
import tests.helpers as th


class TestSessionManager(unittest.TestCase):
    system = None
    ddb_container = None
    password = None
    cognito_url_prefix = None

    @classmethod
    def setUpClass(cls) -> None:
        stack = th.deploy_barrier_test_resources_stack()
        user_pool_domain = stack['user_pool_domain']
        cls.cognito_url_prefix = f'https://{user_pool_domain}'
        cls.password = th.ensure_forge_test_user(stack)
        cls.ddb_container = th.run_dynamodb_container()
        cls.system = sm.System(
            ddb=th.ddb_test_client(ddb_container=cls.ddb_container),
            session_table=th.TEST_SESSION_TABLE,
            cookie_name=th.TEST_COOKIE_NAME,
            user_pool_client_id=stack['user_pool_client_id'],
            user_pool_domain=user_pool_domain,
            cloudfront_domain='barrier.forge-test.ch'
        )
        th.try_create_session_table(ddb=cls.system.ddb)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.ddb_container.stop()

    def test_login(self):
        system = TestSessionManager.system
        login_redirect_response = system.handler({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/login',
            'httpMethod': 'GET',
            'queryStringParameters': {
                'path': '/path'
            },
        }, None)
        self.assertEqual(307, login_redirect_response['statusCode'])
        cookie = cookies.SimpleCookie(login_redirect_response['headers']['Set-Cookie'])
        session_id = cookie.get(system.login_cookie_name).value
        self.assertIsNotNone(system.fetch_and_delete_login_session(session_id))

    def test_is_state_valid_correctness(self):
        system = TestSessionManager.system
        login_session_id = system.new_login_session('secret')
        self.assertTrue(system.is_secret_valid({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/auth',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {
                'Cookie': [
                    sm.cookie(system.login_cookie_name, cookie_value=login_session_id,
                              max_age=sm.FIVE_MINUTES_IN_SECONDS)
                ]
            },
        }, 'secret'))

    def test_is_state_valid_completness_1(self):
        system = TestSessionManager.system
        login_session_id = system.new_login_session('secret1')
        self.assertFalse(system.is_secret_valid({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/auth',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {
                'Cookie': [
                    sm.cookie(system.login_cookie_name, cookie_value=login_session_id,
                              max_age=sm.FIVE_MINUTES_IN_SECONDS)
                ]
            },
        }, 'secret2'))

    def test_is_state_valid_completness_2(self):
        system = TestSessionManager.system
        self.assertFalse(system.is_secret_valid({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/auth',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {
                'Cookie': [
                    sm.cookie(system.login_cookie_name, cookie_value='login_session_id',
                              max_age=sm.FIVE_MINUTES_IN_SECONDS)
                ]
            },
        }, 'secret'))

    def test_is_state_valid_completness_3(self):
        system = TestSessionManager.system
        self.assertFalse(system.is_secret_valid({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/auth',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {}
        }, 'secret'))

    def test_session_creation(self):
        system = TestSessionManager.system
        test_identity = 'test'
        redirect_response = system.auth_response(test_identity, '/')
        self.assertEqual(307, redirect_response['statusCode'])
        set_cookies = redirect_response['multiValueHeaders']['Set-Cookie']
        cookie = cookies.SimpleCookie(set_cookies[0])
        session_id = cookie.get(system.cookie_name).value
        session = system.ddb.get_item(
            TableName=system.session_table,
            Key=sm.session_key(session_id)
        )['Item']
        self.assertEqual(test_identity, session['user_identity']['S'])

    def test_logout_1(self):
        system = TestSessionManager.system
        logout_response = system.handler({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/logout',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {}
        }, None)
        self.assert_logout_response(system, logout_response)

    def test_logout_2(self):
        system = TestSessionManager.system
        session_id = system.new_session('test')
        cookie = sm.cookie(system.cookie_name, session_id, sm.DAY_IN_SECOND)
        logout_response = system.handler({
            'body': '',
            'resource': '/{proxy+}',
            'path': '/_identity/logout',
            'httpMethod': 'GET',
            'isBase64Encoded': True,
            'multiValueHeaders': {'Cookie': [cookie]}
        }, None)
        self.assert_logout_response(system, logout_response)

    def assert_logout_response(self, system, logout_response):
        self.assertEqual(307, logout_response['statusCode'])
        cookie = cookies.SimpleCookie(logout_response['headers']['Set-Cookie']).get(system.cookie_name)
        self.assertEqual('invalid', cookie.value)
        self.assertEqual('-1', cookie['max-age'])

    class AuthHelper:
        def __init__(self, tc):
            system = TestSessionManager.system
            login_response = system.handle_login({})
            self.login_session_id = cookies.SimpleCookie(login_response['headers']['Set-Cookie']).get(
                'TestCookieLogin').value
            login_url = login_response['headers']['Location']
            session = requests.session()
            tree = html.fromstring(session.get(login_url).content)
            login_post_url = tree.xpath('//form[@name="cognitoSignInForm"]')[0].get("action")
            login_csrf = tree.xpath('//form[@name="cognitoSignInForm"]//input[@name="_csrf"]')[0].get('value')
            load = {'_csrf': login_csrf, 'username': th.TEST_USER, 'password': TestSessionManager.password,
                    'cognitoAsfData': '', 'signInSubmitButton': 'Sign in'}
            login_response = session.post(f'{TestSessionManager.cognito_url_prefix}{login_post_url}', data=load,
                                          allow_redirects=False)
            tc.assertEqual(302, login_response.status_code)
            location = login_response.headers.get('Location')
            location_params = up.parse_qs(up.urlparse(location).query)
            self.code = location_params['code'][0]
            self.state = up.quote(location_params['state'][0])

        def event(self, cookie):
            return {
                'body': '',
                'resource': '/{proxy+}',
                'path': '/_identity/auth',
                'httpMethod': 'GET',
                'isBase64Encoded': True,
                'multiValueHeaders': {'Cookie': [cookie]},
                'queryStringParameters': {
                    'code': self.code,
                    'state': self.state
                }
            }

        def valid_cookie(self):
            return sm.cookie(TestSessionManager.system.login_cookie_name, self.login_session_id,
                             sm.FIVE_MINUTES_IN_SECONDS)

        def invalid_cookie(self):
            return sm.cookie('Invalid', 'invalid', sm.FIVE_MINUTES_IN_SECONDS)

        def handle_auth(self, cookie):
            return TestSessionManager.system.handler(self.event(cookie), None)

    def test_assert_auth_valid(self):
        ah = TestSessionManager.AuthHelper(self)
        response = ah.handle_auth(ah.valid_cookie())
        self.assertEqual(307, response['statusCode'])
        self.assertEqual(2, len(response['multiValueHeaders']['Set-Cookie']))

    def test_assert_auth_invalid(self):
        ah = TestSessionManager.AuthHelper(self)
        response = ah.handle_auth(ah.invalid_cookie())
        self.assertEqual(307, response['statusCode'])
        self.assertIsNotNone(response['headers']['Set-Cookie'])


if __name__ == '__main__':
    unittest.main()
