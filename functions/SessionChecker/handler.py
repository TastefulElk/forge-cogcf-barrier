import boto3

import session_checker
import config

system = session_checker.System(
    ddb=boto3.client('dynamodb', region_name=config.SESSION_TABLE_REGION),
    session_table=config.SESSION_TABLE,
    cookie_name=config.COOKIE_NAME,
    login_url=config.LOGIN_URL
)

handler = system.handler
