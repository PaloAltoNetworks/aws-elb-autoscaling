"""
/*****************************************************************************
 * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
 *                                                                           *
 * This Software is the property of Palo Alto Networks. The Software and all *
 * accompanying documentation are copyrighted.                               *
 *****************************************************************************/

Copyright 2016 Palo Alto Networks

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

import boto3
import logging
import json
import httplib
import xml.etree.ElementTree as et
import time
from urlparse import urlparse
from contextlib import closing
import ssl
import urllib2
import decimal
import uuid
import sys
import urllib
import hashlib
import base64
from boto3.dynamodb.conditions import Key, Attr

sys.path.append('lib/')
import pan.asglib as lib

s3 = boto3.client('s3')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
elb = boto3.client('elb')
asg = boto3.client('autoscaling')
cloudwatch = boto3.client('cloudwatch')
dynamodbstreams_client = boto3.client('dynamodbstreams')


logger = logging.getLogger()
logger.setLevel(logging.INFO)

valid_panfw_productcode_ids = {
    "6njl1pau431dv1qxipg63mvah": "VMLIC_BYOL",
    "ezf1psxb2kioq7658vhqcsd8l": "VM100_BND1",
    "aq69x88mwu3gsgzl9cnp2jrs" : "VM100_BND2",
    "6mydlutex4aol2trr2g7q65iv": "VM200_BND1",
    "1a8cei9n1136q07w76k0hsryu": "VM200_BND2",
    "6kxdw3bbmdeda3o6i1ggqt4km": "VM300_BND1",
    "806j2of0qy5osgjjixq9gqc6g": "VM300_BND2",
    "drl1fmzuqe2xzolduol1a44lk": "VM1000_BND1",
    "2yxza6dt6eedvvs80ohu1ae63": "VM1000_BND2",
    #AWS IC product codes
    "3bgub3avj7bew2l8odml3cxdx": "VMLIC_IC_BYOL",
    "atpzu21quydhsik27m2f0u8f" : "VM300_IC_BND1",
    "13w0cso64r7c4rralytfju3p6": "VM300_IC_BND2"
}


def random_string(string_length=10):
    """

    :param string_length:
    :return:
    """
    random = str(uuid.uuid4()) 
    random = random.replace("-","") 
    return random[0:string_length]

def send_response(event, context, responseStatus):
    """
    Method to send a response back to the CFT process.

    :param event:
    :param context:
    :param responseStatus:
    :return:
    """
    r=responseStatus.split(":")
    print(r)
    rs=str(r[0])
    reason=""
    if len(r) > 1:
        reason = str(r[1])
    else:
        reason = 'See the details in CloudWatch Log Stream.'
    print('send_response() to stack -- responseStatus: ' + str(rs) + ' Reason: ' + str(reason))
    response = {
                'Status': str(rs),
                'Reason': str(reason),
                'StackId': event['StackId'],
                'RequestId': event['RequestId'],
                'LogicalResourceId': event['LogicalResourceId'],
                'PhysicalResourceId': event['LogicalResourceId']
               }
    logger.info('RESPONSE: ' + json.dumps(response))
    parsed_url = urlparse(event['ResponseURL'])
    if (parsed_url.hostname == ''):
        logger.info('[ERROR]: Parsed URL is invalid...')
        return 'false'

    logger.info('[INFO]: Sending Response...')
    try:
        with closing(httplib.HTTPSConnection(parsed_url.hostname)) as connection:
            connection.request("PUT", parsed_url.path+"?"+parsed_url.query, json.dumps(response))
            response = connection.getresponse()
            if response.status != 200:
                logger.info('[ERROR]: Received non 200 response when sending response to cloudformation')
                logger.info('[RESPONSE]: ' + response.msg)
                return 'false'
            else:
                logger.info('[INFO]: Got good response')

    except:
        logger.info('[ERROR]: Got ERROR in sending response...')
        return 'false'
    finally:

        connection.close()
        return 'true'

def get_event_rule_name(stackname):
    """
    Method to create a unique name for the
    event rules.

    .. note:: The event name is constructed by appending
              a fixed string to the stack name.
    :param stackname:
    :return:
    """
    name = stackname + 'event-rule-init-lambda'
    return name[-63:len(name)]
    
def get_target_id_name(stackname):
    """

    :param stackname:
    :return:
    """
    name = stackname + 'target-id-init-lambda'
    return name[-63:len(name)]

def no_asgs(elbname):
    """

    :param elbname:
    :return:
    """
    asg_response=asg.describe_auto_scaling_groups()
    found = False
    for i in asg_response['AutoScalingGroups']:
        logger.info('ASG i[AutoScalingGroupName]: ' + i['AutoScalingGroupName'])
        for lbn in i['LoadBalancerNames']:
            if lbn == elbname:
                asg_name = i['AutoScalingGroupName']
                found = True
    return found

def read_s3_object(bucket, key):
    """
    Method to read data from and S3 bucket.

    .. note:: This method is used to read bootstrap
              information, in order to license and
              configure the firewall.

    :param bucket:
    :param key:
    :return:
    """
    # Get the object from the event and show its content type
    key = urllib.unquote_plus(key).decode('utf8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        contents=response['Body'].read()
        #print('Body: ' + str(contents))
        return str(contents)
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist.'.format(key, bucket))
        return None

def remove_sched_func(stackname, elbtg):
    """
    Remove the sched_evt function, in order to
    cleanup when the CFT stack is deleted.

    :param stackname:
    :return:
    """
    lambda_func_name= lib.get_sched_func_name(stackname, elbtg)

    event_rule_name= get_event_rule_name(stackname)
    target_id_name = get_target_id_name(stackname)
    try:
        events_client.remove_targets(Rule=event_rule_name,
                    Ids=[target_id_name])
    except Exception as e:
        logger.error("[Remove Targets]: {}".format(e))

    logger.info('Deleting event rule: ' +  event_rule_name)
    try:
        events_client.delete_rule(Name=event_rule_name)
    except Exception as e:
        logger.error("[Delete Rule]: {}".format(e))

    logger.info('Delete lambda function: ' + lambda_func_name)
    try:
        lambda_client.delete_function(FunctionName=lambda_func_name)
        return True
    except Exception as e:
        logger.error("[Delete Lambda Function]: {}".format(e))

    return False

def delete_resources(event):
    """
    Method to handle the delete of resources when the
    CFT stack is deleted.

    :param event:
    :return:
    """
    logger.info('Deleteing resources...')
    stackname = event['ResourceProperties']['StackName']
    region=event['ResourceProperties']['Region']

    r = event['ResourceProperties']
    logger.info('Dump all the parameters')
    logger.info(r)

    ScalingParameter = r['ScalingParameter']
    KeyPANWPanorama = r['KeyPANWPanorama']
    BootstrapS3Bucket = r['BootstrapS3Bucket']
    ELBTargetGroupName = r['ELBTargetGroupName']
    SubnetIDTrust = r['SubnetIDTrust']
    VPCSecurityGroup=r['VPCSecurityGroup']

    remove_sched_func(stackname, ELBTargetGroupName)

    tablename=lib.get_nlb_table_name(stackname, region)
    lib.delete_table(tablename)
    tablename=lib.get_firewall_table_name(stackname, region)
    lib.delete_table(tablename)

    lib.delete_asg_stacks(stackname, ELBTargetGroupName, VPCSecurityGroup, BootstrapS3Bucket, ScalingParameter, KeyPANWPanorama, SubnetIDTrust)
    return

def common_alarm_func_update(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc):
    """
    Method to create alarms to be monitored on instances in an ASG
    :param asg_name:
    :param metricname:
    :param namespace:
    :param arn_scalein:
    :param arn_scaleout:
    :param alarmname:
    :param desc:
    :return:
    """
    d1=desc+ " High"
    a1=alarmname + '-high'
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scaleout],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleUpThreshold), Statistic="Average", Namespace=namespace,
            ComparisonOperator="GreaterThanThreshold", Period=int(ScalingPeriod))
    except Exception as e:
        logger.error('Failed to Update High Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm High Update]: {}".format(e))
        return False

    a1=alarmname + '-low'
    d1=desc+ " Low"
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scalein],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleDownThreshold), Statistic="Average", Namespace=namespace,
            ComparisonOperator="LessThanThreshold", Period=int(ScalingPeriod))
    except Exception as e:
        logger.error('Failed to Update Low Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm Low Update]: {}".format(e))
        return False

    return True

def UpdateDataPlaneCPUUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    alarmname= asg_name + '-cw-cpu'
    return common_alarm_func_update(asg_name, "DataPlaneCPUUtilizationPct", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "DataPlane CPU Utilization (New)")

def UpdateActiveSessions(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    return common_alarm_func_update(asg_name, "panSessionActive", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Active Sessions (New)")

def UpdateSessionUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    return common_alarm_func_update(asg_name, "panSessionUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Session Utilization (New)")
    return

def UpdateSessionSslProxyUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating Session SSL Proxy Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-sspu'
    return common_alarm_func_update(asg_name, "panSessionSslProxyUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Session SSL Proxy Utilization (New)")
    return

def UpdateGPGatewayUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    return common_alarm_func_update(asg_name, "panGPGatewayUtilizationPct", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "GP Gateway Utilization (New)")
    return

def UpdateGPActiveTunnels(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpat'
    return common_alarm_func_update(asg_name, "panGPGWUtilizationActiveTunnels", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "GP Gateway Active Tunnels (New)")
    return

def UpdateDataPlaneBufferUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """

    :param stackname:
    :param asg_name:
    :param arn_scalein:
    :param arn_scaleout:
    :return:
    """
    logger.info('Creating DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    return common_alarm_func_update(asg_name, "DataPlanePacketBufferUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Data Plane Buffer Utilization (New)")
    return


cw_func_update_alarms = {  'DataPlaneCPUUtilizationPct': UpdateDataPlaneCPUUtilization,
                        'panSessionActive': UpdateActiveSessions,
                        'panSessionUtilization': UpdateSessionUtilization,
                        'panGPGatewayUtilizationPct': UpdateGPGatewayUtilization,
                        'panGPGWUtilizationActiveTunnels': UpdateGPActiveTunnels,
                        'panSessionSslProxyUtilization': UpdateSessionSslProxyUtilization,
                        'DataPlanePacketBufferUtilization': UpdateDataPlaneBufferUtilization}


def update_alarm(stackname, asg_name, event):
    """
    Method to update alarm parameters if they have been changed
    when the CFT stack was updated.

    :param stackname:
    :param asg_name:
    :param event:
    :return:
    """
    global ScaleUpThreshold
    global ScaleDownThreshold
    global ScalingParameter
    global ScalingPeriod

    r = event['ResourceProperties']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    ScalingParameter=r['ScalingParameter']
    ScalingPeriod=int(r['ScalingPeriod'])

    response=asg.describe_policies(AutoScalingGroupName=asg_name)
    arn_scalein=""
    arn_scaleout=""
    for p in response['ScalingPolicies']:
        if p['ScalingAdjustment'] < 0:
            arn_scalein=p['PolicyARN']
        elif p['ScalingAdjustment'] > 0:
            arn_scaleout=p['PolicyARN']

    if arn_scalein == "" or arn_scaleout == "":
        logger.error('Error in getting ScaleIn/ScaleOut Policy ARN')
        logger.error('Update: ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
        return False

    logger.info('Update: ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
    logger.info('Update: Adding Cloud Watch Alarm : ' + ScalingParameter + ' for ASG: ' + asg_name)
    if cw_func_update_alarms[ScalingParameter](stackname, asg_name, arn_scalein, arn_scaleout) == False:
        return False

    return True

def update_resources(event):
    """
    Method to handle any updates to the CFT templates.

    :param event: CFT input parameters
    :return: None
    """
    global asg_name
    global untrust
    global PanS3KeyTpl
    global LambdaS3Bucket 
    global KeyPANWPanorama
    global KeyPANWFirewall
    global ScalingParameter
    global Namespace
    global ilb_ip_address
    global ilb_name
    global elb_name
    global SubnetIDLambda
    global sgv
    global Arn

    stackname = event['ResourceProperties']['StackName']
    logger.info('Updating resources for stackname: ' + stackname)

    Arn=event['StackId']
    r = event['ResourceProperties']
    oldr = event['OldResourceProperties']
    logger.info('Dump all the new parameters')
    logger.info(r)
    logger.info('Dump all the OLD parameters')
    logger.info(oldr)

    LambdaExecutionRole = r['LambdaExecutionRole']
    LambdaS3Bucket=r['LambdaS3Bucket']
    PanS3KeyTpl=r['PanS3KeyTpl']
    KeyPANWFirewall=r['KeyPANWFirewall']
    KeyPANWPanorama=r['KeyPANWPanorama']
    KeyDeLicense=r['KeyDeLicense']
    elb_name=r['ELBName']
    ELBTargetGroupName=r['ELBTargetGroupName']
    sgv= r['VPCSecurityGroup']
    ScalingParameter = r['ScalingParameter']
    MaximumInstancesASG = r['MaximumInstancesASG']
    MinInstancesASG = r['MinInstancesASG']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    ScalingPeriod = r['ScalingPeriod']
    BootstrapS3Bucket = r['BootstrapS3Bucket']
    LambdaENIQueue = r['LambdaENIQueue']
    NetworkLoadBalancerQueue = r['NetworkLoadBalancerQueue']
    ASGNotifierRole=str(r['ASGNotifierRole'])
    LambdaENISNSTopic=str(r['LambdaENISNSTopic'])

    SubnetIDTrust = r['SubnetIDTrust']
    SubnetIDUntrust = r['SubnetIDUntrust']
    SubnetIDMgmt = r['SubnetIDMgmt']

    SubnetIDTrust=str(lib.fix_unicode(SubnetIDTrust))
    SubnetIDTrust=lib.fix_subnets(SubnetIDTrust)
    SubnetIDUntrust=str(lib.fix_unicode(SubnetIDUntrust))
    SubnetIDUntrust=lib.fix_subnets(SubnetIDUntrust)
    SubnetIDMgmt=str(lib.fix_unicode(SubnetIDMgmt))
    SubnetIDMgmt=lib.fix_subnets(SubnetIDMgmt)

    logger.info('Purging LambdaENIqueue: {}'.format(LambdaENIQueue))
    lib.purge_stack_queue(LambdaENIQueue)
    logger.info('Purging NLB queue: {}'.format(NetworkLoadBalancerQueue))
    lib.purge_stack_queue(NetworkLoadBalancerQueue)

    if remove_sched_func(stackname, ELBTargetGroupName) == False:
        logger.error('Failed to delete Sched Lambda Func (VIP Monitoring)')
        return 
    create_resources(event)

    if LambdaS3Bucket == "panw-aws-autoscale-v20":
        region=r['Region']
        LambdaS3Bucket=LambdaS3Bucket + "-" + region

    logger.info('-------------------------------------------------------------------------------')
    logger.info('Lambda Template S3 Bucket: ' + LambdaS3Bucket + ' S3Key is : ' + PanS3KeyTpl)
    logger.info('-------------------------------------------------------------------------------')

    lambda_func_name= r['FwInit']
    try:
        lambda_client.update_function_code(FunctionName=lambda_func_name, S3Bucket=LambdaS3Bucket, S3Key=PanS3KeyTpl)
        logger.info('Updated FwInit Lambda Function Code Successfully')
    except Exception as e:
        logger.error('Update Resource for FwInit Lambda Failed')
        logger.error("[Update Resource FwInit Lambda]: {}".format(e))
        return False

    lambda_func_name= r['InitLambda']
    try:
        lambda_client.update_function_code(FunctionName=lambda_func_name, S3Bucket=LambdaS3Bucket, S3Key=PanS3KeyTpl)
        logger.info('Updated Init Lambda Function Code Successfully')
    except Exception as e:
        logger.error('Update Resource for Init Lambda Failed')
        logger.error("[Update Resource Init Lambda]: {}".format(e))
        return False

    fw_azs = lib.getAzs(SubnetIDTrust)
    for i in fw_azs:
        search = lib.get_asg_name(stackname, ELBTargetGroupName, i)
        response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[search])
        if len(response['AutoScalingGroups']) == 0:
            logger.warning('ASG for az {} is not found'.format(i))
        if len(response['AutoScalingGroups']) > 1:
            logger.error('Multiple ASGs for az {} is found'.format(i))
        asg_response = response['AutoScalingGroups'][0]

        logger.info('Update Resource: ASG Name: ' + asg_response['AutoScalingGroupName'])
        asg_name = asg_response['AutoScalingGroupName']
        asg.update_auto_scaling_group(AutoScalingGroupName=asg_name,
                                      MinSize=int(MinInstancesASG), MaxSize=int(MaximumInstancesASG),
                                      DesiredCapacity=int(MinInstancesASG), DefaultCooldown=int(ScalingPeriod))
        update_alarm(stackname, asg_name, event)

        logger.info('Updating Life Cycle Hook for ASG: ' + asg_name)
        hookname = asg_name + '-life-cycle-launch'
        mgmt = lib.choose_subnet(SubnetIDMgmt, i)
        untrust = lib.choose_subnet(SubnetIDUntrust, i)
        trust = lib.choose_subnet(SubnetIDTrust, i)

        metadata = {
            'MGMT': mgmt, 'UNTRUST': untrust, 'TRUST': trust, 'KeyPANWFirewall': KeyPANWFirewall,
            'KeyPANWPanorama': KeyPANWPanorama, 'KeyDeLicense': KeyDeLicense,
            'LambdaENIQueue': LambdaENIQueue,'AvailZone': i
        }

        try:
            asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
                                   LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
                                   RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
                                   DefaultResult="ABANDON", HeartbeatTimeout=300,
                                   NotificationMetadata=json.dumps(metadata))
        except Exception as e:
            logger.error("[ASG LifeCycle Hook Launch. ROLLBACK]: {}".format(e))
            return False

        hookname = asg_name + '-life-cycle-terminate'
        try:
            asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
                                   LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
                                   RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
                                   DefaultResult="CONTINUE", HeartbeatTimeout=300,
                                   NotificationMetadata=json.dumps(metadata))
        except Exception as e:
            logger.error("[ASG LifeCycle Hook Terminate. ROLLBACK]: {}".format(e))

    logger.info('Done Updating Resources...')
    return

def validate_ami_id(event):
    """
       Validate that the AMI-ID provided is a valid
       PAN FW AMI.
       :param event: The CFT event params
       :return: bool
    """
    resource_props = event['ResourceProperties']
    ami_id = resource_props['ImageID']
    valid_ami = False
    valid_state = False

    try:
        image_info = ec2_client.describe_images(
                ImageIds=[ami_id]
        )
    except Exception as e:
        logger.info("Exception occured while retrieving AMI ID information: {}".format(e))
        return False

    logger.info('describe_images:response: {}'.format(image_info))

    ami_images = image_info['Images']
    for image in ami_images:
        product_codes = image['ProductCodes']
        for code in product_codes:
            product_code_id = code.get("ProductCodeId", None)
            if product_code_id in valid_panfw_productcode_ids.keys():
                valid_ami = True
                break

        if image['State'] == 'available':
            valid_state = True

    if valid_ami and valid_state:
        return True 

def create_resources(event):
    """
    This method is called from the lambda handler entry point.
    The following actions are performed:
        - validate the AMI-ID
        - deploys the ```sched_evt1``` lambda function.

    :param event:
    :return: None
    """
    stackname = event['ResourceProperties']['StackName']
    logger.info('Creating resources for stackname: ' + stackname)

    r = event['ResourceProperties']
    logger.info('Dump all the parameters')
    logger.info(r)
    debug = r['Debug']
    ScalingParameter = r['ScalingParameter']
    ScalingPeriod = r['ScalingPeriod']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    MinInstancesASG = r['MinInstancesASG']
    MaximumInstancesASG = r['MaximumInstancesASG']
    VpcId = r['VpcId']
    FWInstanceType = r['FWInstanceType']
    BootstrapS3Bucket = r['BootstrapS3Bucket']
    SubnetIDTrust = r['SubnetIDTrust']
    SubnetIDUntrust = r['SubnetIDUntrust']
    SubnetIDMgmt = r['SubnetIDMgmt']
    TrustSecurityGroup = r['TrustSecurityGroup']
    UntrustSecurityGroup = r['UntrustSecurityGroup']
    MgmtSecurityGroup = r['MgmtSecurityGroup']
    VPCSecurityGroup= r['VPCSecurityGroup']
    ELBName = r['ELBName']
    ELBTargetGroupName = r['ELBTargetGroupName']
    SSHLocation = r['SSHLocation']
    ImageID = r['ImageID']
    KeyName = r['KeyName']
    LambdaENISNSTopic = r['LambdaENISNSTopic']
    Region = r['Region']
    LambdaExecutionRole = r['LambdaExecutionRole']
    PanS3KeyTpl=r['PanS3KeyTpl']
    FirewallBootstrapRole = r['FirewallBootstrapRole']
    ASGNotifierRole= r['ASGNotifierRole']
    ASGNotifierRolePolicy= r['ASGNotifierRolePolicy']
    KeyPANWFirewall = r['KeyPANWFirewall']
    KeyPANWPanorama = r['KeyPANWPanorama']
    SubnetIDNATGW=r['SubnetIDNATGW']
    SubnetIDLambda=r['SubnetIDLambda']
    KeyDeLicense=r['KeyDeLicense']
    LambdaENIQueue = r['LambdaENIQueue']
    NetworkLoadBalancerQueue = r['NetworkLoadBalancerQueue']
    SubnetIDTrust=str(lib.fix_unicode(SubnetIDTrust))
    SubnetIDTrust=lib.fix_subnets(SubnetIDTrust)
    SubnetIDUntrust=str(lib.fix_unicode(SubnetIDUntrust))
    SubnetIDUntrust=lib.fix_subnets(SubnetIDUntrust)
    SubnetIDMgmt=str(lib.fix_unicode(SubnetIDMgmt))
    SubnetIDMgmt=lib.fix_subnets(SubnetIDMgmt)
    SubnetIDLambda=str(lib.fix_unicode(SubnetIDLambda))
    SubnetIDLambda=lib.fix_subnets(SubnetIDLambda)
    SubnetIDNATGW=str(lib.fix_unicode(SubnetIDNATGW))
    SubnetIDNATGW=lib.fix_subnets(SubnetIDNATGW)

    logger.info('Creating Sched Lambda funcion (VIP Monitoring) for stackname: ' + stackname)
    r = event['ResourceProperties']
    lambda_exec_role_name=r['LambdaExecutionRole']

    LambdaS3Bucket=r['LambdaS3Bucket']
    if LambdaS3Bucket == "panw-aws-autoscale-v20":
        LambdaS3Bucket=LambdaS3Bucket + "-" + Region

    logger.info('-------------------------------------------------------------------------------')
    logger.info('Lambda Template S3 Bucket: ' + LambdaS3Bucket + ' S3Key is : ' + PanS3KeyTpl)
    logger.info('-------------------------------------------------------------------------------')

    event_rule_name= get_event_rule_name(stackname)
    logger.info('Creating event rule: ' + event_rule_name)
    response = events_client.put_rule(
            Name=event_rule_name,
            ScheduleExpression='rate(1 minute)',
            State='ENABLED'
        )
    events_source_arn = response.get('RuleArn')
    logger.info('Getting IAM role')
    lambda_exec_role_arn = iam.get_role(RoleName=lambda_exec_role_name).get('Role').get('Arn')
    lambda_func_name = lib.get_sched_func_name(stackname, ELBTargetGroupName)
    logger.info('creating lambda function: ' + lambda_func_name)
    logger.info('SubnetIDLambda: {}'.format(SubnetIDLambda))
    subnetids = SubnetIDLambda.split(",")
    response = lambda_client.create_function(
            FunctionName=lambda_func_name,
            Runtime='python2.7',
            Role=lambda_exec_role_arn,
            Handler='sched_evt1.lambda_handler',
            Code={
                'S3Bucket': LambdaS3Bucket,
                'S3Key': PanS3KeyTpl
            },
            MemorySize=256,
            Timeout=120,
            VpcConfig={
                'SubnetIds': subnetids,
                'SecurityGroupIds': [
                   VPCSecurityGroup
                ]
            }
        )

    logger.info('Lambda function sched_evt created...')
    sched_evt_lambda_arn = response.get('FunctionArn')

    response = lambda_client.add_permission(
            FunctionName=sched_evt_lambda_arn,
            StatementId= lib.get_lambda_statement_id(stackname, ELBTargetGroupName),
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=events_source_arn
        )

    c=read_s3_object(BootstrapS3Bucket, "config/init-cfg.txt")
    dict = lib.get_values_from_init_cfg(c)
    logger.info('Init CFG bootstrap file Panorama settings: ')
    logger.info(dict)
    pip=dict['panorama-server']
    pdg=dict['dgname']
    ptpl=dict['tplname']
    Input = {'ScalingParameter': ScalingParameter, 'ScalingPeriod': ScalingPeriod,
		'StackName': stackname, 'VpcId': VpcId,
		'FWInstanceType': FWInstanceType, 'BootstrapS3Bucket': BootstrapS3Bucket,
		'SubnetIDTrust': SubnetIDTrust, 'SubnetIDUntrust': SubnetIDUntrust,
		'SubnetIDMgmt': SubnetIDMgmt, 'TrustSecurityGroup': TrustSecurityGroup,
		'UntrustSecurityGroup': UntrustSecurityGroup, 'MgmtSecurityGroup': MgmtSecurityGroup,
        'VPCSecurityGroup': VPCSecurityGroup,
		'MaximumInstancesASG': MaximumInstancesASG,
		'ELBName': ELBName, 'ELBTargetGroupName': ELBTargetGroupName, 'SSHLocation': SSHLocation,
		'ImageID': ImageID, 'ScaleUpThreshold': ScaleUpThreshold,
        'ScaleDownThreshold': ScaleDownThreshold, 'KeyName': KeyName,
		'LambdaENISNSTopic': LambdaENISNSTopic,
		'MinInstancesASG': MinInstancesASG, 'Region': Region,
		'FirewallBootstrapRole': FirewallBootstrapRole,
		'LambdaExecutionRole': LambdaExecutionRole,
		'ASGNotifierRole': ASGNotifierRole,
		'ASGNotifierRolePolicy': ASGNotifierRolePolicy,
		'LambdaS3Bucket': LambdaS3Bucket,
		'PanS3KeyTpl': PanS3KeyTpl,
        'KeyPANWFirewall': KeyPANWFirewall,
        'KeyPANWPanorama': KeyPANWPanorama,
        'SubnetIDNATGW': SubnetIDNATGW, 'SubnetIDLambda': SubnetIDLambda,
        'PIP': pip, 'PDG': pdg, 'PTPL': ptpl, 'Hostname': dict['hostname'],
        'KeyDeLicense': KeyDeLicense, 'LambdaENIQueue': LambdaENIQueue, 'NetworkLoadBalancerQueue':NetworkLoadBalancerQueue,
        'Debug':debug
		}

    stack_metadata= {
                'SGM': MgmtSecurityGroup, 'SGU': UntrustSecurityGroup, 'SGT': TrustSecurityGroup, 'SGV': VPCSecurityGroup,
                'IamLambda': LambdaExecutionRole, 'StackName': stackname, 'Region': Region, 'LambdaS3Bucket': LambdaS3Bucket,
                'PanS3KeyTpl': PanS3KeyTpl, 
                'ScalingParameter': ScalingParameter, 
                'SubnetIDNATGW': SubnetIDNATGW, 
                'PIP': pip, 'PDG': pdg, 'PTPL': ptpl, 'Hostname': dict['hostname'], 'Debug':debug
               }
    lib.set_queue_attributes(LambdaENIQueue, 345600)
    lib.set_queue_attributes(NetworkLoadBalancerQueue, 345600)
    logger.info("Send initial message onto the queue: {}".format(LambdaENIQueue))
    lib.send_message_to_queue(LambdaENIQueue, json.dumps(stack_metadata))

    logger.info('Event put targets')
    
    target_id_name = get_target_id_name(stackname)
    response= events_client.put_targets(
            Rule=event_rule_name,
            Targets=
                [{
                    'Id': target_id_name,
                    'Arn': sched_evt_lambda_arn,
                    'Input': json.dumps(Input)
                }]
        )

def get_sha(bucket, folder, lambda_sha):
    """
    Method to compute the SHA-256 encoding for the
    contents of the given file
    :param bucket:
    :param folder:
    :param lambda_sha:
    :return:
    """
    key=folder
    key = urllib.unquote_plus(key).decode('utf8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        contents=response['Body'].read()
        h=hashlib.sha256()
        h.update(contents)
        hex=h.digest()
        m=base64.b64encode(hex)
        logger.info('CodeSha256 for bucket: ' + bucket + ' file: ' + folder + ' is: ' + str(m))
        logger.info('CodeSha256 for InitLambda: ' + lambda_sha)
        if m != lambda_sha:
            logger.info('---------------------------------------------------------------------')
            logger.info('   WARNING: SHA256 does not match with published code')
            logger.info('---------------------------------------------------------------------')
        else:
            logger.info('---------------------------------------------------------------------')
            logger.info('Template Lambda Code SHA256 matched. Success')
            logger.info('---------------------------------------------------------------------')
    except Exception as e:
        logger.info(e)

def lambda_handler(event, context):
    """
        .. note:: This function is the entry point for the ```init``` Lambda function.
           This function performs the following actions:

           - invokes ```create | delete | update_resources()``` based on the action
                         required.
           - creates the ```sched_evt1``` lambda function
                        and configures the same.

           - validates that the PAN FW AMI-ID specified as input
                        is valid and supported.

        :param event: Encodes all the input variables to the lambda function, when
                      the function is invoked.
                      Essentially AWS Lambda uses this parameter to pass in event
                      data to the handler function.
        :type event: dict

        :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
        :type context: LambdaContext

        :return: None
    """
    global logger

    logger.info('got event{}'.format(event))

    try:
        r = event['ResourceProperties']

        lfunc=r['InitLambda']
        lresponse=lambda_client.get_function(FunctionName=lfunc)
        logger.info(json.dumps(lresponse))
        LambdaS3Bucket=r['LambdaS3Bucket']
        PanS3KeyTpl=r['PanS3KeyTpl']
        if LambdaS3Bucket != "panw-aws-autoscale-v20":
            logger.info('-------------------------------------------------------------------------------')
            logger.info('Customer is using their own lambada S3 bucket: ' + LambdaS3Bucket)
            logger.info('-------------------------------------------------------------------------------')

        stackname = r['StackName']
        region = r['Region']
        SubnetIDNATGW = r['SubnetIDNATGW']
        SubnetIDLambda = r['SubnetIDLambda']
        LambdaS3Bucket ="panw-aws-autoscale-v20-"+ region
        get_sha(LambdaS3Bucket, PanS3KeyTpl, lresponse['Configuration']['CodeSha256'])
    except Exception as e:
        logger.error("[CodeSha256]: {}".format(e))

    ami_id = event['ResourceProperties']['ImageID']
    status="SUCCESS"
    try:
        if event['RequestType'] == 'Delete':
            delete_resources(event)
            logger.info('[INFO]: Sending delete response to S3 URL for stack deletion to proceed')
        elif event['RequestType'] == 'Create':
            try:
                logger.info('Validate Ami-Id: {}'.format(ami_id))
                if not validate_ami_id(event):
                    # Check to ensure that the AMI-ID specified is valid.
                    send_response(event, context, "FAILURE: We do not support AMI-ID: {}".format(ami_id))
                    return
            except Exception as e:
                logger.error("Failed to determine validity of the AMI specified: {}".format(e))
                send_response(event, context, "FAILURE: validating AMI-ID {}. Unable to proceed".format(ami_id))
                return

            logger.info('Successfully validated that the Ami is a valid PAN FW AMI')

            try:
                SubnetIDLambda=str(lib.fix_unicode(SubnetIDLambda))
                SubnetIDLambda=lib.fix_subnets(SubnetIDLambda)
                SubnetIDNATGW=str(lib.fix_unicode(SubnetIDNATGW))
                SubnetIDNATGW=lib.fix_subnets(SubnetIDNATGW)
                llen=len(SubnetIDLambda.split(','))
                nlen=len(SubnetIDNATGW.split(','))
                print('Length of Lambda Subnets: ' + str(llen))
                print('Length of NATGW Subnets: ' + str(nlen))
                if llen == 0 or nlen == 0:
                    logger.error('[ERROR]: Either Lambda or NATGW Subnets were not passed...')
                    send_response(event, context, "FAILURE: Either Lambda or NATGW Subnets were not passed")
                    return

                if llen > 2 or nlen > 2:
                        logger.error('[ERROR]: Either Lambda or NATGW Subnets are more than 2 AZs')
                        send_response(event, context, "FAILURE: Either Lambda or NATGW Subnets are more than 2 AZs")
                        return
            except Exception as e:
                logger.error("[StackNameLenCheck]: {}".format(e))

            try:
                logger.info('Length of stackname is: ' + str(len(stackname)))
                if len(stackname) > 128:
                    logger.error('[ERROR]: We dont support Stack Name more than 128 characters long...')
                    send_response(event, context, "FAILURE: We dont support Stack Name more than 128 characters long")
                    return
            except Exception as e:
                logger.error("[StackNameLenCheck]: {}".format(e))

            logger.info('Create nlb table')
            lib.create_nlb_table(stackname, region)
            logger.info('Create firewall table')
            lib.create_firewall_table(stackname, region)
    
            create_resources(event)
            logger.info('[INFO]: Sending Create response to S3 URL for stack creation to proceed')
        elif event['RequestType'] == 'Update':
            update_resources(event)
            logger.info('[INFO]: Sending Update response to S3 URL for stack.')
    except Exception as e:
        logger.error('[ERROR]: Got ERROR in Init Lamnda handler...')
        logger.error("[Error in Init Lambda Handler]: {}".format(e))

    if (send_response(event, context, status)) == 'false':
        logger.info('[ERROR]: Got ERROR in sending response to S3 URL for custom resource...')
