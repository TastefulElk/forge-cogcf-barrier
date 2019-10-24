import abc
import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

import boto3
import termcolor
import tabulate
import yaml

__version__ = '0.1.0'

FORGE_ASM_DIR = '.forge-asm'


class AssemblyHook(abc.ABC):
    @abc.abstractmethod
    def post_assembly(self, asm):
        pass


class Assembler:
    def __init__(self, function_path, hook: AssemblyHook = None):
        self.function_path = function_path
        self.hook = hook
        self.asm_path = Path(FORGE_ASM_DIR, function_path).absolute()
        self.requirement_path = Path(self.asm_path, 'requirements.txt')
        self.code_path = Path(self.asm_path, 'code')
        self.env = os.environ
        self.run('poetry', 'install', '-q', '--no-root')
        venv_bin = Path(self.run('poetry', 'env', 'info', '-p').stdout.decode('utf-8'), 'bin')
        env = os.environ.copy()
        env['PATH'] = f'{venv_bin}:{env["PATH"]}'
        self.env = env

    def cleanup(self):
        shutil.rmtree(self.asm_path, ignore_errors=True)
        self.asm_path.mkdir(parents=True, exist_ok=True)

    def assemble_funtion(self):
        termcolor.cprint(f'[Assemble the function {self.function_path}]', 'blue')
        self.cleanup()
        shutil.copytree(self.function_path, self.code_path, ignore=ignore_non_python)
        self.run('poetry', 'export', '-f', 'requirements.txt', '-o', self.requirement_path)
        self.run('pip', '-q', '-q', '-q', 'install', '-t', self.code_path, '-r', self.requirement_path)
        if self.hook:
            self.hook.post_assembly(self)

    def run(self, *args):
        return subprocess.run(args, cwd=self.function_path, env=self.env, check=True, stdout=subprocess.PIPE)


class Stack:
    def __init__(self, stack_name, template_file, config, assembler, region=None, **parameters):
        self.stack_name = stack_name
        self.config = config
        self.region = region if region else config.region
        self.assembler = assembler
        self.cf = boto3.Session(profile_name=config.profile).client('cloudformation', region_name=self.region)
        self.parameters = parameters
        self.template_file = template_file
        self.output_template = template_file
        self.s3_bucket = config.s3_buckets[self.region]

    def command_prefix(self):
        return ['aws', '--profile', self.config.profile, '--region', self.region, 'cloudformation']

    def package(self):
        termcolor.cprint(f'[ Packaging the stack {self.stack_name} ]', 'blue')
        self.output_template = Path(self.assembler.asm_path, Path(self.template_file).name)
        cmd = self.command_prefix()
        subprocess.run(cmd + ['package',
                              '--template-file', self.template_file,
                              '--s3-bucket', self.s3_bucket,
                              '--s3-prefix', self.config.s3_prefix,
                              '--output-template', self.output_template], check=True)

    @property
    def parameter_overrides(self):
        return [f'{key}={value}' for (key, value) in self.parameters.items()]

    def deploy(self):
        termcolor.cprint(f'[ Deploying the stack {self.stack_name} ]', 'blue')
        cmd = self.command_prefix()
        p = subprocess.run(cmd + ['deploy', '--stack-name', self.stack_name,
                                  '--template-file', self.output_template,
                                  '--capabilities=CAPABILITY_IAM', '--no-fail-on-empty-changeset',
                                  '--parameter-overrides']
                           + self.parameter_overrides, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def assemble_package_deploy(self):
        self.assembler.assemble_funtion()
        self.package()
        self.deploy()
        print('')

    def outputs(self):
        outputs = self.cf.describe_stacks(StackName=self.stack_name)['Stacks'][0]['Outputs']
        return {output['OutputKey']: output['OutputValue'] for output in outputs}


def is_python_code(src, name):
    path = Path(src, name)
    if path.is_file() and name.endswith('.py'):
        return True
    elif path.is_dir() and Path(path, '__init.py__').exists():
        return True
    else:
        return False


def ignore_non_python(src, names):
    return [name for name in names if not is_python_code(src, name)]


def escape_quote(string):
    return string.replace("'", r"\'")


class Config:
    def __init__(self, cfg):
        env = cfg['Environment']
        self.profile = env['AWSProfile']
        self.region = env['Region']
        packaging = cfg['Packaging']
        self.s3_buckets = packaging['S3Buckets']
        self.s3_prefix = packaging['S3Prefix']
        user_pool = cfg['CognitoUserPool']
        self.user_pool_id = user_pool['UserPoolId']
        user_pool_client = user_pool['UserPoolClientProperties']
        self.read_attributes = ','.join(user_pool_client['ReadAttributes'])
        self.write_attributes = ','.join(user_pool_client['WriteAttributes'])
        self.identity_providers = ','.join(user_pool_client['SupportedIdentityProviders'])
        self.user_pool_doamin_name = user_pool['DomainName']
        cloudfront = cfg['Cloudfront']
        self.cloudfront_domain_name = cloudfront['DomainName']
        self.cookie_name = cfg['CookieName']
        self.stacks_prefix = cfg['StacksPrefix']


def load_config(assembly_file):
    with open(assembly_file) as f:
        cfg = yaml.load(f, Loader=yaml.BaseLoader)
    return Config(cfg)


def session_manager_stack(config):
    asm = Assembler('functions/SessionManager')
    stack = Stack(stack_name=f'{config.stacks_prefix}SessionManager', template_file='templates/SessionManager.yaml',
                  config=config, assembler=asm,
                  UserPoolId=config.user_pool_id,
                  ReadAttributes=config.read_attributes,
                  WriteAttributes=config.write_attributes,
                  SupportedIdentityProviders=config.identity_providers,
                  UserPoolDomainName=config.user_pool_doamin_name,
                  CloudfrontDomainName=config.cloudfront_domain_name,
                  CookieName=config.cookie_name)
    return stack


def cognito_barrier_stack(config, session_manager_stack_outputs):
    session_table_read_policy_arn = session_manager_stack_outputs['SessionTableReadPolicyArn']
    session_table = session_manager_stack_outputs['SessionTable']
    session_table_region = session_manager_stack_outputs['SessionTableRegion']
    cookie_name = session_manager_stack_outputs['CookieName']
    login_url = session_manager_stack_outputs['LoginUrl']

    class ConfigAssemblyHook(AssemblyHook):
        def post_assembly(self, asm):
            with open(Path(asm.code_path, 'config.py'), 'w') as config_file:
                config_file.write(f'''\
SESSION_TABLE = '{escape_quote(session_table)}'
SESSION_TABLE_REGION = '{escape_quote(session_table_region)}'
COOKIE_NAME = '{escape_quote(cookie_name)}'
LOGIN_URL = '{escape_quote(login_url)}'
''')

    asm = Assembler('functions/SessionChecker', hook=ConfigAssemblyHook())
    stack = Stack(stack_name=f'{config.stacks_prefix}SessionChecker',
                  template_file='templates/SessionChecker.yaml',
                  region='us-east-1',
                  config=config, assembler=asm,
                  SessionTableReadPolicyArn=session_table_read_policy_arn)
    return stack


def deploy():
    args = parse_args()
    config = load_config(args.f)
    sms = session_manager_stack(config)
    sms.assemble_package_deploy()
    sms_outputs = sms.outputs()
    cbs = cognito_barrier_stack(config=config, session_manager_stack_outputs=sms_outputs)
    cbs.assemble_package_deploy()
    fancy_print(sms_outputs, cbs.outputs())


def info():
    info_raw(print_info)


def parse_args():
    parser = argparse.ArgumentParser(description='Assembly')
    parser.add_argument('-f', default="assembly.yaml", help='assembly file')
    return parser.parse_args()


def get_info(sms_outputs, cbs_outputs):
    return {
        'SessionManagerOriginHost': sms_outputs['ApiDomainName'],
        'SessionManagerOriginPath': sms_outputs['ApiPath'],
        'SessionCheckerFunctionArn': cbs_outputs['SessionCheckerFunctionVersionArn']
    }


def print_info(info):
    print(tabulate.tabulate([
        ['Session Manager Origin Host', info['SessionManagerOriginHost']],
        ['Session Manager Origin Path', info['SessionManagerOriginPath']],
        ['Session Checker Function Arn', info['SessionCheckerFunctionArn']]
    ], tablefmt="fancy_grid"))


def fancy_print(sms_outputs, cbs_outputs):
    print_info(get_info(sms_outputs, cbs_outputs))


def info_json():
    def print_json(info):
        print(json.dumps(info))

    info_raw(print_json)


def info_raw(fmt):
    config = load_config(parse_args().f)
    sms = session_manager_stack(config)
    sms_outputs = sms.outputs()
    cbs = cognito_barrier_stack(config=config, session_manager_stack_outputs=sms_outputs)
    cbs_outputs = cbs.outputs()
    fmt(get_info(sms_outputs, cbs_outputs))
