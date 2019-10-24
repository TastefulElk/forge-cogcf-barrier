import boto3
import docker
import yaml
from pathlib import Path
import secrets

import forge_cogcf_barrier as fcb

TEST_SESSION_TABLE = 'SessionTable'
TEST_COOKIE_NAME = 'TestCookie'
TEST_USER = 'forge@test.com'


def session_table_spec():
    with open(f'{Path(__file__).parent.parent}/templates/SessionManager.yaml') as f:
        template = yaml.load(f, Loader=yaml.BaseLoader)
    table_spec = template['Resources']['SessionTable']['Properties']
    table_spec['TableName'] = TEST_SESSION_TABLE
    del table_spec['TimeToLiveSpecification']
    return table_spec


def try_create_session_table(*, ddb):
    try:
        table_spec = session_table_spec()
        try:
            ddb.create_table(**table_spec)
        except Exception as e:
            print(e)
            print(f"could not create table {table_spec}")
    except Exception as e:
        print(e)


def run_dynamodb_container():
    docker_client = docker.from_env()
    ddb_container = docker_client.containers.run('amazon/dynamodb-local', ports={'8000/tcp': None},
                                                 remove=True, detach=True)
    ddb_container.reload()
    ddb_container.dynamo_db_port = ddb_container.ports['8000/tcp'][0]['HostPort']
    return ddb_container


def ddb_test_client(*, ddb_container):
    return boto3.client('dynamodb',
                        endpoint_url=f'http://localhost:{ddb_container.dynamo_db_port}',
                        region_name='us-east-1',
                        aws_access_key_id='test',
                        aws_secret_access_key='test')


def deploy_barrier_test_resources_stack():
    stack = fcb.Stack(
        stack_name='BarrierTestResources',
        template_file=Path(Path(__file__).parent.parent, 'templates', 'BarrierTestResources.yaml'),
        config=fcb.Config({
            'Environment': {'AWSProfile': 'forge-test', 'Region': 'us-east-1'},
            'Packaging': {'S3Buckets': {'us-east-1': None}, 'S3Prefix': None},
            'CognitoUserPool': {'UserPoolId': None,
                                'UserPoolClientProperties': {
                                    'ReadAttributes': [],
                                    'WriteAttributes': [],
                                    'SupportedIdentityProviders': []},
                                'DomainName': None},
            'Cloudfront': {'DomainName': None},
            'CookieName': None,
            'StacksPrefix': None
        }),
        region='us-east-1',
        assembler=None,
    )
    try:
        user_pool_domain = stack.outputs()['UserPoolDomain']
    except:
        user_pool_domain = f't{secrets.token_hex(31)}'
    stack.parameters = {'Domain': user_pool_domain}
    stack.deploy()
    outputs = stack.outputs()
    return {'user_pool_id': outputs['UserPoolId'],
            'user_pool_client_id': outputs['UserPoolClientId'],
            'user_pool_domain': f'{outputs["UserPoolDomain"]}.auth.us-east-1.amazoncognito.com'}


def ensure_forge_test_user(test_resources):
    cog = boto3.Session(profile_name='forge-test').client('cognito-idp', region_name='us-east-1')
    user_pool_id = test_resources['user_pool_id']
    password = secrets.token_urlsafe(32) + '.'
    try:
        cog.admin_create_user(
            UserPoolId=user_pool_id,
            Username=TEST_USER
        )
    except:
        pass
    cog.admin_set_user_password(
        UserPoolId=user_pool_id,
        Username=TEST_USER,
        Password=password,
        Permanent=True
    )
    return password
