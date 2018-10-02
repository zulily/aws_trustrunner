#!/usr/bin/env python
"""
setup_lambda script
   Used to deploy zutrust to AWS Lambda, creating roles needed and
   pushing the script to AWS Lambda.

   Copyright 2018 zulily, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import os
from time import sleep

import boto3
from botocore.exceptions import ClientError

IAM_R = boto3.resource('iam')
IAM_C = boto3.client('iam')
LAMBDA_C = boto3.client('lambda')
EVENTS_C = boto3.client('events')

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

def setup_iam_role():
    """
    Setup the AWS IAM role
    """
    try:
        IAM_C.get_role(RoleName='aws_trustrunner')
    except ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchEntity':
            with open('{}/lambda_role_policy.json'.format(BASE_DIR), 'r') as policy_file:
                policy = policy_file.read()
                IAM_C.create_role(RoleName='aws_trustrunner',
                                  AssumeRolePolicyDocument=policy)
        else:
            raise err

    for pol in ['support_access', 'sns_access', 'cloudwatch_access', 's3_access']:
        with open('{}/{}.json'.format(BASE_DIR, pol), 'r') as policy_file:
            policy = policy_file.read()
            IAM_C.put_role_policy(RoleName='aws_trustrunner',
                                  PolicyName=pol,
                                  PolicyDocument=policy)
    try:
        IAM_C.get_instance_profile(InstanceProfileName='aws_trustrunner')
    except ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchEntity':
            IAM_C.create_instance_profile(InstanceProfileName='aws_trustrunner')
        else:
            raise err

    role_instance_profiles = IAM_C.list_instance_profiles_for_role(RoleName='aws_trustrunner')
    add_instance_profile = True
    for profile in role_instance_profiles['InstanceProfiles']:
        if profile['InstanceProfileName'] == 'aws_trustrunner':
            add_instance_profile = False
    if add_instance_profile:
        IAM_C.add_role_to_instance_profile(InstanceProfileName='aws_trustrunner',
                                           RoleName='aws_trustrunner')
    return IAM_R.Role('aws_trustrunner')

def configure_vpc():
    """
    Provide vpc/sg for lambda function
    """
    vpc_config = {}
    subnet_id = os.environ.get('SUBNET_ID')
    security_group_id = os.environ.get('SECURITY_GROUP_ID')
    if subnet_id:
        vpc_config['SubnetIds'] = [subnet_id]
    if security_group_id:
        vpc_config['SecurityGroupIds'] = [security_group_id]
    return vpc_config

def upload_lambda_function():
    """
    main function of deployment.
    Ensure IAM is setup. Upload zip. Create function.
    """
    vpc_config = configure_vpc()
    role = setup_iam_role()

    rule = EVENTS_C.put_rule(Name='TrustRunnerSchedule',
                             ScheduleExpression=os.environ.get('DISCOVERY_SCHEDULE'),
                             State='ENABLED',
                             Description='Start the trust runner')

    with open('{}/../aws_trustrunner.zip'.format(BASE_DIR), 'rb') as zip_file:
        zip_bytes = zip_file.read()
        fcn = {}
        try:
            LAMBDA_C.get_function(FunctionName='TrustRunner')
            fcn = LAMBDA_C.update_function_code(FunctionName='TrustRunner',
                                                ZipFile=zip_bytes,
                                                Publish=True)
        except ClientError as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                sleep(10)
                fcn = LAMBDA_C.create_function(FunctionName='TrustRunner',
                                               Code={'ZipFile': zip_bytes},
                                               Runtime='python2.7',
                                               Role=role.arn,
                                               Handler='zutrust.main',
                                               Timeout=300,
                                               Description="Trigger Trust Advisor Checks",
                                               MemorySize=128,
                                               VpcConfig=vpc_config)

            else:
                raise err

        try:
            LAMBDA_C.add_permission(FunctionName='TrustRunner',
                                    StatementId='TrustRunnerSchedule-Permission',
                                    Action='lambda:InvokeFunction',
                                    Principal='events.amazonaws.com',
                                    SourceArn=rule['RuleArn'])
        except ClientError as err:
            if err.response['Error']['Code'] != 'ResourceConflictException':
                # ignore conflicts if the rule exists
                raise err

        EVENTS_C.put_targets(Rule='TrustRunnerSchedule',
                             Targets=[{'Id': 'TrustRunner-schedule',
                                       'Arn': fcn['FunctionArn'],}])

upload_lambda_function()
