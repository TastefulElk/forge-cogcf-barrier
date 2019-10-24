import secrets
import time
import unittest

import functions.SessionChecker.session_checker as sc
import tests.helpers as th


class TestSessionCheckerIntegration(unittest.TestCase):
    system = None
    ddb_container = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.ddb_container = th.run_dynamodb_container()
        cls.system = sc.System(
            ddb=th.ddb_test_client(ddb_container=cls.ddb_container),
            session_table=th.TEST_SESSION_TABLE,
            cookie_name=th.TEST_COOKIE_NAME,
            login_url='http://localhost/login'
        )
        th.try_create_session_table(ddb=cls.system.ddb)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.ddb_container.stop()

    def base_event(self, *, with_cookie_value):
        event = {
            "Records": [
                {
                    "cf": {
                        "config": {
                            "distributionId": "EXAMPLE"
                        },
                        "request": {
                            "uri": "/test",
                            "method": "GET",
                            "clientIp": "2001:cdba::3257:9652",
                            "headers": {
                                "host": [
                                    {
                                        "key": "Host",
                                        "value": "d123.cf.net"
                                    }
                                ]
                            }
                        }
                    }
                }
            ]
        }
        if with_cookie_value:
            event['Records'][0]['cf']['request']['headers']['cookie'] = [{'key': 'Cookie',
                                                                          'value': f'{th.TEST_COOKIE_NAME}={with_cookie_value}'}]
        return event

    def test_session_valid(self):
        session_id = secrets.token_urlsafe(64)
        self.put_session(session_id, 300)
        event = self.base_event(with_cookie_value=session_id)
        response = self.handle_event(event)
        self.assertEqual('GET', response['method'])
        session_id_header = response['headers']['x-barrier-session-id'][0]
        self.assertEqual('X-Barrier-Session-Id', session_id_header['key'])
        self.assertEqual(session_id, session_id_header['value'])

    def test_session_invalid_without_header(self):
        event = self.base_event(with_cookie_value=None)
        response = self.handle_event(event)
        self.assertEqual('307', response['status'])

    def test_session_invalid_with_unexisting_session(self):
        event = self.base_event(with_cookie_value='abcd')
        response = self.handle_event(event)
        self.assertEqual('307', response['status'])

    def test_session_invalid_in_the_past(self):
        session_id = secrets.token_urlsafe(64)
        self.put_session(session_id, -300)
        event = self.base_event(with_cookie_value=session_id)
        response = self.handle_event(event)
        self.assertEqual('307', response['status'])

    def handle_event(self, event):
        return TestSessionCheckerIntegration.system.handler(event, None)

    def put_session(self, session_id, delta_to_now):
        TestSessionCheckerIntegration.system.ddb.put_item(
            TableName=th.TEST_SESSION_TABLE,
            Item={
                'session_id': {'S': session_id},
                'valid_until': {'N': str(time.time() + delta_to_now)},
                'user_identity': {'S': 'test'}
            },
            ReturnValues='NONE'
        )


if __name__ == '__main__':
    unittest.main()
