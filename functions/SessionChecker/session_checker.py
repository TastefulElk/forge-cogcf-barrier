import logging
import time
from http import cookies
import urllib.parse

from cachetools import cached, TTLCache

logging.getLogger().setLevel(20)

FAILURE = {'body': '',
           'bodyEncoding': 'text',
           'status': '500',
           'statusDescription': 'Internal Server Error'}


class System:
    def __init__(self, *, ddb, session_table, cookie_name, login_url):
        self.ddb = ddb
        self.session_table = session_table
        self.cookie_name = cookie_name
        self.login_url = login_url

    def handler(self, event, _):
        request = event['Records'][0]['cf']['request']
        session_id = self.request_session_id(request)
        if session_id:
            request['headers']['x-barrier-session-id'] = [{'key': 'X-Barrier-Session-Id', 'value': session_id}]
            return request
        else:
            return self.redirect_to_login(request)

    def request_session_id(self, request):
        try:
            for cookie in request['headers'].get('cookie', []):
                cookie_value = cookie['value']
                if self.cookie_name in cookie_value:
                    simple_cookie = cookies.SimpleCookie(input=cookie_value)
                    session_id = simple_cookie.get(self.cookie_name).value
                    session_valid_until = self.fetch_session_valid_until(session_id)
                    now = time.time()
                    return session_id if session_valid_until > now else None
        except Exception as e:
            logging.info("exception for user_identity: %s", e)
        return None

    @cached(cache=TTLCache(maxsize=1024, ttl=300))
    def fetch_session_valid_until(self, session_id):
        item = self.ddb.get_item(
            TableName=self.session_table,
            Key=session_key(session_id),
            ConsistentRead=True,
            ProjectionExpression='valid_until'
        )
        return float(item['Item']['valid_until']['N'])

    def redirect_to_login(self, request):
        querystring = request.get('querystring')
        query = f'?{querystring}' if querystring else ''
        path = urllib.parse.quote(f"{request.get('uri', '/')}{query}")
        return {'body': '',
                'bodyEncoding': 'text',
                'headers': {
                    'location': [{
                        'key': 'Location',
                        'value': f'{self.login_url}?path={path}'
                    }],
                    'set-cookie': [{
                        'key': 'Set-Cookie',
                        'value': f'{self.cookie_name}=invalid; HttpOnly; Max-Age=-1; Path=/; Secure; SameSite=Lax'
                    }],
                },
                'status': '307',
                'statusDescription': 'Temporary Redirect'
                }


def session_key(session_id):
    return {'session_id': {'S': session_id}}
