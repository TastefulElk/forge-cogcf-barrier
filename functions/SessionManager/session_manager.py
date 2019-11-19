import base64
import json
import logging
import secrets
import urllib.parse
from http import cookies

import requests
import time

FIVE_MINUTES_IN_SECONDS = 60 * 5
DAY_IN_SECOND = 60 * 60 * 24
DAY_IN_MILLISECONDS = DAY_IN_SECOND * 1000

logging.getLogger().setLevel(20)


class System:

    def __init__(self, *, ddb, session_table, cookie_name, user_pool_client_id, user_pool_domain, cloudfront_domain):
        self.ddb = ddb
        self.session_table = session_table
        self.cookie_name = cookie_name
        self.user_pool_client_id = user_pool_client_id
        self.login_cookie_name = f'{self.cookie_name}Login'
        self.user_pool_domain = user_pool_domain
        self.cloudfront_domain = cloudfront_domain
        self.redirect_uri = f'https://{cloudfront_domain}/_identity/auth'

    def handler(self, event, _):
        path = event['path']
        if path == '/_identity/login':
            return self.handle_login(event)
        elif path == '/_identity/logout':
            return self.handle_logout(event)
        elif path == '/_identity/auth':
            return self.handle_auth(event)
        else:
            raise ValueError(f'unknown path {path}')

    def handle_login(self, event):
        query_strings = event.get('queryStringParameters')
        path = query_strings.get('path', '/') if query_strings else '/'
        return self.redirect_to_login(user_requested_path=path)

    def redirect_to_login(self, user_requested_path):
        secret = new_secret()
        login_session_id = self.new_login_session(secret)
        state = base64.urlsafe_b64encode(json.dumps({
            'secret': secret,
            'path': user_requested_path
        }).encode()).decode()
        return {
            'statusCode': 307,
            'body': None,
            'headers': {
                'Set-Cookie': cookie(self.login_cookie_name, cookie_value=login_session_id,
                                     max_age=FIVE_MINUTES_IN_SECONDS),
                'Location': f'https://{self.user_pool_domain}/login?response_type=code&client_id={self.user_pool_client_id}&redirect_uri={self.redirect_uri}&state={state}'
            }
        }

    def new_login_session(self, secret):
        return self.put_new_session(valid_until=str(time.time() + FIVE_MINUTES_IN_SECONDS),
                                    secret={'S': secret})

    def handle_logout(self, event):
        session_id = find_cookie(self.cookie_name, event=event)
        self.delete_session(session_id)
        return self.logout_response()

    def logout_response(self):
        return {
            'statusCode': 307,
            'body': None,
            'headers': {
                'Set-Cookie': f'{self.cookie_name}=invalid; HttpOnly; Max-Age=-1; Path=/; Secure; SameSite=Lax',
                'Location': f'https://{self.cloudfront_domain}'
            },
        }

    def handle_auth(self, event):
        params = event['queryStringParameters']
        code = params['code']
        event_state = json.loads(base64.urlsafe_b64decode(params['state']).decode())
        secret = event_state['secret']
        event_path = urllib.parse.unquote(event_state['path'])
        identity = self.verify_identity(event=event, code=code, secret=secret)
        if identity:
            return self.auth_response(identity, event_path)
        else:
            return self.logout_response()

    def auth_response(self, identity, path):
        session_id = self.new_session(identity)
        return {
            'statusCode': 307,
            'body': None,
            'headers': {
                'Location': f'https://{self.cloudfront_domain}{path}'
            },
            'multiValueHeaders': {
                'Set-Cookie': [
                    cookie(self.cookie_name, cookie_value=session_id, max_age=DAY_IN_SECOND),
                    cookie(self.login_cookie_name, cookie_value='invalid', max_age=-1)
                ]
            }
        }

    def new_session(self, identity):
        return self.put_new_session(valid_until=str(time.time() + DAY_IN_MILLISECONDS),
                                    user_identity={'S': identity})

    def verify_identity(self, event, code, secret):
        is_valid = self.is_secret_valid(event, secret)
        if is_valid:
            return self.fetch_identity(code=code)
        else:
            return None

    def fetch_identity(self, code):
        try:
            token = requests.post(f'https://{self.user_pool_domain}/oauth2/token', data={
                'grant_type': 'authorization_code',
                'client_id': self.user_pool_client_id,
                'redirect_uri': self.redirect_uri,
                'code': code,
            })
            access_token = token.json()['access_token']
            identity = requests.get(f'https://{self.user_pool_domain}/oauth2/userInfo',
                                    headers={'Authorization': 'Bearer ' + access_token})
            return identity.content.decode('utf-8')
        except Exception as e:
            logging.info(str(e))
        return None

    def is_secret_valid(self, event, event_secret):
        login_session_id = find_cookie(self.login_cookie_name, event=event)
        if login_session_id:
            try:
                session = self.fetch_and_delete_login_session(login_session_id)
                session_secret = session['secret']['S']
                return session_secret == event_secret and time.time() < float(session['valid_until']['N'])
            except Exception as e:
                logging.info('could not compare event session to session secret due to %s; secret is invalid', str(e))
        return False

    def fetch_and_delete_login_session(self, session_id):
        logging.info('fetching %s', session_id)
        item = self.ddb.delete_item(
            TableName=self.session_table,
            Key=session_key(session_id),
            ReturnValues='ALL_OLD'
        )['Attributes']
        return item

    def put_new_session(self, valid_until, **kwargs):
        session_id = new_secret()
        item = {
            'session_id': {'S': session_id},
            'valid_until': {'N': valid_until},
        }
        item.update(kwargs)
        self.ddb.put_item(
            TableName=self.session_table,
            Item=item,
            ReturnValues='NONE'
        )
        return session_id

    def delete_session(self, session_id):
        try:
            self.ddb.delete_item(
                TableName=self.session_table,
                Key=session_key(session_id)
            )
        except Exception as e:
            logging.info('could not delete the session %s due to %s; skipping', session_id, e)


def find_cookie(name, *, event):
    for cookie in event['multiValueHeaders'].get('Cookie', []):
        if name in cookie:
            simple_cookie = cookies.SimpleCookie(input=cookie)
            return simple_cookie.get(name).value
    return None


def cookie(cookie_name, cookie_value, max_age):
    return f'{cookie_name}={cookie_value}; HttpOnly; Max-Age={max_age}; Path=/; Secure; SameSite=Lax'


def session_key(session_id):
    return {'session_id': {'S': session_id}}


def new_secret():
    return secrets.token_urlsafe(64)
