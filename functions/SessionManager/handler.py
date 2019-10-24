import os

import boto3

import session_manager

system = session_manager.System(
    ddb=boto3.client('dynamodb'),
    session_table=os.environ.get('SESSION_TABLE'),
    cookie_name=os.environ.get('COOKIE_NAME'),
    user_pool_client_id=os.environ.get('USER_POOL_CLIENT_ID'),
    user_pool_domain=os.environ.get('USER_POOL_DOMAIN'),
    cloudfront_domain=os.environ.get('CLOUDFRONT_DOMAIN')
)

handler = system.handler
