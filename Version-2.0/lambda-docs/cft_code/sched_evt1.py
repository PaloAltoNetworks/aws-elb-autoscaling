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
from __future__ import print_function

import sys
import boto3
import botocore
import json
import logging
import time
import decimal
import uuid
import logging

sys.path.append('lib/')
import pan.asglib as lib

sys.path.append('dnslib/')
import pan_client as dns

# Enable creation of S3 bucket per-ASG
enable_s3=False
num_nlb_port=1280
start_nlb_port=81
num_fw_az=2

# Global Tunnables
dig=True
asg_tag_key="PANW-ASG"
asg_delay=30

####### GLobal Variables ############
stackname=""
region=""
ilb_tag=""
elb_name=""
sg_vpc=""
sg_mgmt=""
sg_untrust=""
sg_trust=""
keyname=""
iamprofilebs=""
s3master=""
subnetmgmt=""
subnetuntrust=""
subnettrust=""
imageID=""
ScalingPeriod=300
ScaleUpThreshold=50
ScaleDownThreshold=30
ScalingParameter=""
instanceType=""
MinInstancesASG=1
MaximumInstancesASG=3
LambdaExecutionRole=""
LambdaENISNSTopic=""
ASGNotifierRole=""
ASGNotifierRolePolicy=""
LambdaS3Bucket=""
PanS3KeyTpl=""
KeyPANWFirewall=""
KeyPANWPanorama=""
SubnetIDNATGW=""
SubnetIDLambda=""
LambdaENIQueue=""
PIP=""
PDG=""
PTPL=""
Hostname=""
error_line="--------ERROR------ERROR-----ERROR------ERROR-------"

######## BOTO3 Clients and Resources #############
s3 = boto3.client('s3')
asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
cloudwatch = boto3.client('cloudwatch')
elb = boto3.client('elb')
elbv2 = boto3.client('elbv2')

####### FUNCTIONS ############
def random_string(string_length=10):
    """

    :param string_length:
    :return:
    """
    random = str(uuid.uuid4()) 
    random = random.replace("-","") 
    return random[0:string_length]

def common_alarm_func_add(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc, Unit):
    """

    Method that supports a common interface to add cloud watch alarms along with the associated threshold
    metrics.

    :param asg_name: Name of the ASG that this alarm is associated with.
    :param metricname: Name of the metric.
    :param namespace: Name of the namespace.
    :param arn_scalein: ARN of the scale-in metric.
    :param arn_scaleout: ARN of the scale-out metric.
    :param alarmname: Name of the alarm that will be raised.
    :param desc: Description of the alarm
    :param Unit: The unit to be used.
    :return: bool
    """
    d1=desc+ " High"
    a1=alarmname + '-high'
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scaleout],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleUpThreshold), Statistic="Average", Namespace=namespace,
            ComparisonOperator="GreaterThanThreshold", Period=ScalingPeriod, Unit=Unit)
    except Exception as e:
        logger.error('Failed to add High Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm High Add]: {}".format(e))
        return False

    a1=alarmname + '-low'
    d1=desc+ " Low"
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scalein],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleDownThreshold), Statistic="Average", Namespace=namespace,
            ComparisonOperator="LessThanThreshold", Period=ScalingPeriod,
            Unit=Unit)
    except Exception as e:
        logger.error('Failed to add Low Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm Low Add]: {}".format(e))
        return False

    return True

def common_alarm_func_del(alarmname):
    """
    Common interface to delete alarms
    :param alarmname: Name of the alarm to delete.
    :return: None
    """
    a1=alarmname + '-high'
    cloudwatch.delete_alarms(AlarmNames=[a1])

    a1=alarmname + '-low'
    cloudwatch.delete_alarms(AlarmNames=[a1])
    return

## CloudWatch Alarms
def AddDataPlaneCPUUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneCPUUtilization Alarm. This alarm
    will trigger when the Data Plane CPU Utilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)
        
    alarmname= asg_name + '-cw-cpu'
    return common_alarm_func_add(asg_name, "DataPlaneCPUUtilizationPct", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "DataPlane CPU Utilization", 'Percent')

def DelDataPlaneCPUUtilization(asg_name):
    """
    Method to delete the DataPlaneCPUUtilization Alarm. This alarm
    will trigger when the Data Plane CPU Utilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-cpu'
    common_alarm_func_del(alarmname)
    return

def AddActiveSessions(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the ActiveSessions Alarm. This alarm
    will trigger when the Active Sessions exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    return common_alarm_func_add(asg_name, "panSessionActive", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Active Sessions", 'Count')

def DelActiveSessions(asg_name):
    """
    Method to delete the Active Sessions alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    common_alarm_func_del(alarmname)
    return

def AddSessionUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the SessionUtilization Alarm. This alarm
    will trigger when the SessionUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    return common_alarm_func_add(asg_name, "panSessionUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Session Utilization", 'Percent')

def DelSessionUtilization(asg_name):
    """
        Method to delete the Session Utilization alarm

        :param asg_name: Name of the ASG
        :return: None
    """
    logger.info('Deleting Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    common_alarm_func_del(alarmname)
    return

def AddGPGatewayUtilization(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the GPGatewayUtilization Alarm. This alarm
        will trigger when the GPGatewayUtilization exceeds the
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    """
    logger.info('Creating GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    return common_alarm_func_add(asg_name, "panGPGatewayUtilizationPct", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "GP Gateway Utilization", 'Percent')

def DelGPGatewayUtilization(asg_name):
    """
    Method to delete the GP Session Utilization alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    common_alarm_func_del(alarmname)
    return

def AddGPActiveTunnels(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the GPActiveTunnels Alarm. This alarm
        will trigger when the GP Active Tunnels  exceeds the
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool
    """
    logger.info('Creating GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpat'
    return common_alarm_func_add(asg_name, "panGPGWUtilizationActiveTunnels", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "GP Gateway Utilization", 'Count')

def DelGPActiveTunnels(asg_name):
    """
    Method to delete the GP GPActiveTunnels alarm
    
    :param asg_name: Name of the ASG
    :return: None
    """

    logger.info('Deleting GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpat'
    common_alarm_func_del(alarmname)
    return

def AddDataPlaneBufferUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneBufferUtilization Alarm. This alarm
    will trigger when the DataPlaneBufferUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    return common_alarm_func_add(asg_name, "DataPlanePacketBufferUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Data Plane Packet Buffer Utilization", 'Percent')

def DelDataPlaneBufferUtilization(asg_name):
    """
    Method to delete the DatePlaneBufferUtilization  alarm

    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting DP Packet Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    common_alarm_func_del(alarmname)
    return

def AddSessionSslProxyUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the SessionSslProxyUtilization Alarm. This alarm
    will trigger when the SessionSslProxyUtilization exceeds the
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating Session SSL Proxy  Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-sspu'
    return common_alarm_func_add(asg_name, "panGPGatewayUtilizationPct", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Session SSL Proxy Utilization", 'Percent')
    return

def DelSessionSslProxyUtilization(asg_name):
    """
    Method to delete the SessionSslProxyUtilization alarm
    
    :param asg_name: Name of the ASG
    :return: None
    """
    logger.info('Deleting Session SSL Proxy Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-sspu'
    common_alarm_func_del(alarmname)
    return

cw_func_add_alarms = {  'DataPlaneCPUUtilizationPct': AddDataPlaneCPUUtilization,
                        'panSessionActive': AddActiveSessions,
                        'panSessionUtilization': AddSessionUtilization,
                        'panGPGatewayUtilizationPct': AddGPGatewayUtilization,
                        'panGPGWUtilizationActiveTunnels': AddGPActiveTunnels,
                        'panSessionSslProxyUtilization': AddSessionSslProxyUtilization,
                        'DataPlanePacketBufferUtilization': AddDataPlaneBufferUtilization}

cw_func_del_alarms = {  'DataPlaneCPUUtilizationPct': DelDataPlaneCPUUtilization,
                        'panSessionActive': DelActiveSessions,
                        'panSessionUtilization': DelSessionUtilization,
                        'panGPGatewayUtilizationPct': DelGPGatewayUtilization,
                        'panGPGWUtilizationActiveTunnels': DelGPActiveTunnels,
                        'panSessionSslProxyUtilization': DelSessionSslProxyUtilization,
                        'DataPlanePacketBufferUtilization': DelDataPlaneBufferUtilization}

def create_asg_life_cycle(asg_name, AvailabilityZone):
    """
    Method to register ASG life cycle hook actions.


    When and ASG lifecycle hook is triggered the targets as registered
    by this method get triggered with the appropriate data fields.

    :param asg_name: Name of the ASG.
    :param AvailabilityZone: Name of the AZ
    :param ip_address: IP address of the instance
    :return: bool
    """
    logger.info('Creating Life Cycle Hook for ASG: ' + asg_name)
    hookname=asg_name + '-life-cycle-launch'
    mgmt=lib.choose_subnet(subnetmgmt, AvailabilityZone)
    untrust=lib.choose_subnet(subnetuntrust, AvailabilityZone)
    trust=lib.choose_subnet(subnettrust, AvailabilityZone)

    metadata= {
                'MGMT': mgmt, 'UNTRUST': untrust, 'TRUST': trust, 'KeyPANWFirewall': KeyPANWFirewall,
                'KeyPANWPanorama': KeyPANWPanorama, 'KeyDeLicense': KeyDeLicense,
                'LambdaENIQueue': LambdaENIQueue, 'AvailZone': AvailabilityZone
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
    
    hookname=asg_name + '-life-cycle-terminate'
    try:
        asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
            RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
            DefaultResult="CONTINUE", HeartbeatTimeout=300,
            NotificationMetadata=json.dumps(metadata))
    except Exception as e:
        logger.error("[ASG LifeCycle Hook Terminate. ROLLBACK]: {}".format(e))
        return False
    
    return True

def create_asg(AvailabilityZone):
    """
    Method to create an Auto Scale Group with the configuration
    provided.

    .. note:: This method performs the following critical functions

       - reads in configuration from an S3 bucket
       - creates a launch configuration
       - creates an ASG
       - associates the policies with the ASG
       - registers to ASG life-cycle hook events and provides handlers for these events.

    :param AvailabilityZone:
    :return:
    """
    lc_name= lib.get_lc_name(stackname, ELBTargetGroupName, AvailabilityZone)

    logger.info('Creating launch-config for a new ASG: ' + lc_name)
    userdata='vmseries-bootstrap-aws-s3bucket=' + s3master
    
    try:
        response=asg.create_launch_configuration(LaunchConfigurationName=lc_name, 
                ImageId=imageID, KeyName=keyname, SecurityGroups=[sg_untrust], InstanceType=instanceType,
                AssociatePublicIpAddress=False, EbsOptimized=True,
                IamInstanceProfile=iamprofilebs,
                BlockDeviceMappings=[
                        {'DeviceName': "/dev/xvda", 
                         'Ebs': 
                            {'DeleteOnTermination': True,
                             'VolumeType': 'gp2'
                            }
                        }
                ],
                UserData=userdata)
    except Exception as e:
         logger.error("[ASG LC error]: {}".format(e))
         return False
    #Get ELB ARN
    tgtGrp = elbv2.describe_target_groups(Names=[ELBTargetGroupName])
    if tgtGrp == None:
        tgtGrp_arn = None
        logger.info('ELB target group is not found!')
    else:
        tgtGrp_d = tgtGrp['TargetGroups']
        tgtGrp_arn = tgtGrp_d[0].get('TargetGroupArn')
    print("targetgroup arn: " + tgtGrp_arn)
    print( "ELBTargetGroupName: " +ELBTargetGroupName)
 
    asg_name = lib.get_asg_name(stackname, ELBTargetGroupName, AvailabilityZone)
    logger.info('Creating Auto-Scaling Group with name: ' + asg_name)
    tags={'ResourceId': asg_name, 'ResourceType': 'auto-scaling-group', 'Key': 'Name', 'Value': asg_name, 'PropagateAtLaunch':True}
    
    subnet=lib.choose_subnet(subnetuntrust, AvailabilityZone)
    try:
        response=asg.create_auto_scaling_group(AutoScalingGroupName=asg_name, LaunchConfigurationName=lc_name,
                MinSize=MinInstancesASG, MaxSize=MaximumInstancesASG, DesiredCapacity=MinInstancesASG,
                DefaultCooldown=ScalingPeriod, TargetGroupARNs=[tgtGrp_arn],
                VPCZoneIdentifier=subnet,
                Tags=[tags],
                HealthCheckGracePeriod=900)
    except Exception as e:
         logger.error("[ASG create error]: {}".format(e))
         return False
    
    if create_asg_life_cycle(asg_name, AvailabilityZone) == False:
        return False
    
    scalein=asg_name + '-scalein'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scalein, AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=-1, Cooldown=600)
        arn_scalein=response['PolicyARN']
    except Exception as e:
         logger.error("[ASG ScaleIn12 Policy]: {}".format(e))
         return False
         
    scaleout=asg_name + '-scaleout'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scaleout, AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=1, Cooldown=600)
        arn_scaleout=response['PolicyARN']
    except Exception as e:
         logger.info("[ASG ScaleOut123]: {}".format(e))
         return False
        
    logger.info('ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
    logger.info('Adding Cloud Watch Alarm : ' + ScalingParameter + ' for ASG: ' + asg_name)
    if cw_func_add_alarms[ScalingParameter](asg_name, arn_scalein, arn_scaleout) == False:
        return False
        
    return True

def getAz(ip, response_ilb):
    """
    Method to return the availability zone that a
    configured IP address belongs to.

    :param ip:
    :param response_ilb:
    :return:
    """
    for i in response_ilb['NetworkInterfaces']:
        logger.info('GetAz: Details about Internal Load Balancer')
        for k in i['PrivateIpAddresses']:
            logger.info('GetAz: IP Address of ILB is :' + k['PrivateIpAddress'])
            if k['PrivateIpAddress'] == ip:
                return i['AvailabilityZone']

    return None

def check_and_send_message_to_queue(queue_url, str_message):
    """
    Method to retrieve the IP addresses that are configured on an
    ILB.

    :param event:
    :param content:
    :param response_ilb:
    :return: str
    """
    msg_str, msg_sent_timestamp, receipt_handle = lib.get_from_sqs_queue(queue_url, 20, 5)

    if not msg_str:
        logger.warning('Unable to retrieve message during this cycle.')
        return 
    msg_data = json.loads(msg_str)
    
    msg_ts = float(msg_sent_timestamp) * 0.001
    logger.info('Message from queue: {}'.format(msg_data))
    current_time = time.time()

    logger.info('msg ts: {} current ts: {}'.format(msg_ts, current_time))

    if (current_time - msg_ts) > 259200:
        logger.info('Message in queue needs to be updated')
        lib.send_message_to_queue(queue_url, str_message)
        lib.delete_message_from_queue(queue_url, receipt_handle)  
    else:
        logger.info('Message in queue is still current.')

def firewall_asg_update(event, context):
    """
    Method to monitor the asg in the supported AZs.

    The actions performed by this function are:
        - if asg doesn't exist, create asg. 
        - Before create asg, it will remove the launch config if exists.
          Then create new launch config.
    :param event: Encodes all the input variables to the lambda function, when
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event
                  data to the handler function.
    :type event: dict

    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext

    :return: None
    """

    print("Firewall ASG update Time remaining (MS):", context.get_remaining_time_in_millis())
    for i in fw_azs:
        search = lib.get_asg_name(stackname, ELBTargetGroupName, i)
        asg_response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[search])
        #print(asg_response)
        if len(asg_response['AutoScalingGroups']) == 0:
            logger.warning('ASG for az {} is not found, creating ASG'.format(i))

            #Remove ASG LC if exists
            lc_name= lib.get_lc_name(stackname, ELBTargetGroupName, i)
            asg_response = asg.describe_launch_configurations(LaunchConfigurationNames=[lc_name])
            if len(asg_response['LaunchConfigurations']) != 0:
                logger.info('Deleting Lanuch-configuration for ASG: ' + search)
                try:
                    asg.delete_launch_configuration(LaunchConfigurationName=lc_name)
                except Exception as e:
                    logger.error('Could not remove ASG LC. Reason below')
                    logger.error("[ASG DELETE LC]: {}".format(e))

            if create_asg(i) == False:
                print(error_line)
                lib.remove_asg(stackname, ELBTargetGroupName, i, ScalingParameter, KeyPANWPanorama, False, False)
        
    print("Time remaining return firewall_asg_update (MS):", context.get_remaining_time_in_millis())

def network_load_balancer_update(event, context):
    """
    Method to monitor NLB sqs and update firewall nat rules

    The actions performed by this function are:
        - find all firewalls of COMMIT state in firewall table and apply
          nat rules of all NLB IPs in NLB table
        - read new msg from NLB sqs and update nlb table and firewall rules

    :param event: Encodes all the input variables to the lambda function, when
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event
                  data to the handler function.
    :type event: dict

    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext

    :return: None
    """
    print("NLB update Time remaining (MS):", context.get_remaining_time_in_millis())   
    logger.info('Running network load balancer update')
    fwcontext = lib.get_ssl_context()
    total_fw_az = len(fw_azs)


    #Search for COMMIT in firewall table
    try:
        response = lib.firewall_table_get_all_in_state(stackname, region, 'COMMIT')
        for fw in response['Items']:
            nlb_port_mask = []
            for i in range (0, (num_nlb_port)/64):
                nlb_port_mask.append(0)

            # Get firewall Availabilty Zone index
            fw_az_index = fw_azs.index(fw['AvailZone'])
            set_nat = True
            # Find all the nlb in commit state
            nlb_response=lib.nlb_table_get_all_in_state(stackname, region, 'COMMIT')
        
            for nlb in nlb_response['Items']:
                nlb_port = nlb['TCPPort']
                nlb_ip = nlb['NLBIp']
                rule_mask_index = int((nlb_port-start_nlb_port)/64)
                nlb_bit = int((nlb_port-start_nlb_port)%64)
                nlb_port_mask[rule_mask_index] |= 1<<nlb_bit
                fw_rule_mask = long(fw['NLBRuleMask'+str(rule_mask_index)], 0)
            
                # Skip if it's configured on firewall
                if fw_rule_mask & (1 << nlb_bit) != 0:
                    continue
                nlb_az_index = nlb['AZIndex']
                total_nlb_azs = nlb['TotalAZ']
                # Skip if NLB and firewall availabilty zone doesn't match
                if nlb_az_index%total_fw_az != fw_az_index:
                    continue

                if lib.config_firewall_add_nat_rule(fwcontext, fw['MgmtIP'], KeyPANWFirewall, fw['UntrustIP'], nlb_port, nlb_ip, True, trust_def_gw[fw_az_index], False) == False:
                    logger.error('Config firewall NAT rule failed for instance %s, IP %s, NLB-Port %d', fw['InstanceID'], fw['MgmtIP'], nlb_port)
                    set_nat = False
                    break
        
            if set_nat == True:
                # Find all the nlb deleted
                for rule_mask_index,item in enumerate(nlb_port_mask):
                    fw_rule_mask = long(fw['NLBRuleMask'+str(rule_mask_index)], 0)
                    if item & fw_rule_mask != fw_rule_mask:
                        #Found NLB entry has been deleted
                        for bit in range(0,64):
                            if (fw_rule_mask & 1<<bit) != 0 and (item & 1<<bit) == 0:
                                nlb_port = rule_mask_index*64+bit+start_nlb_port
                                if lib.config_firewall_delete_nat_rule(fwcontext, fw['MgmtIP'], KeyPANWFirewall, nlb_port, True, True) == False:
                                    logger.error('Delete firewall NAT rule failed for instance %s, IP %s, NLB-Port %d', fw['InstanceID'], fw['MgmtIP'], nlb_port)
                                    set_nat = False
                if lib.config_firewall_commit(fwcontext, fw['MgmtIP'], KeyPANWFirewall) == False:
                    logger.error('Commit firewall configuration failed for instance %s, IP %s', fw['InstanceID'], fw['MgmtIP'])
                else:
                    for mask in nlb_port_mask:
                        print('port mask committed in COMMIT: {}'.format(mask))
                    lib.firewall_table_update_rule_mask(stackname, region, fw['InstanceID'], nlb_port_mask)
                    lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'READY')
    except Exception as e:
        logger.exception("Exception occurred while processing firewalls in commit: {}".format(e))

    #Retrieve message from NLB queue
    pre_port = -1
    fw_update = False
    for read in xrange(0, 10):
        try:
            logger.info('Calling to retrieve message from NLB queue..: {}'.format(NetworkLoadBalancerQueue))
            message_data_str, ts, rh = lib.get_from_nlb_queue(NetworkLoadBalancerQueue, 10, 0)
            if not message_data_str:
                logger.info('No message to retrieve from NLB queue.')
                break 
            else:
                #Delete message from NLB queue
                lib.delete_message_from_queue(NetworkLoadBalancerQueue, rh)
                message_data = json.loads(message_data_str)
                logger.info("Data from sqs: {}".format(message_data_str))
                if 'MSG-TYPE' not in message_data or 'DNS-NAME' not in message_data:
                    logger.error("Found invalid message in NetworkLoadBalancerQueue: {}".format(message_data_str))
                    continue
                nlb_type = message_data['MSG-TYPE']
                dns_name = message_data['DNS-NAME']
                if nlb_type == 'ADD-NLB':
                    nlb_vpc = message_data['VPC-ID']
                    nlb_name = message_data['NLB-NAME']
                    dns_name = message_data['DNS-NAME']
                    nlb_azs = message_data['AVAIL-ZONES']
                    total_nlb_az = len(nlb_azs)
                    nlb_port = lib.nlb_table_get_next_avail_port(stackname, region)
                    for wait in xrange(0, 20):
                        if pre_port == nlb_port and pre_port != 0:
                            time.sleep(0.05)
                        else:
                            pre_port = nlb_port
                            break
                    if wait == 20:
                        logger.error("Get next available port returns the same port %d, skip adding nlb %s", nlb_port, nlb_name)
                        continue
                    else:
                        logger.info("Wait for syncing dynamodb sleep count %d", wait)
  
                    if nlb_port == 0:
                        logger.error("All ports number(%d-%d) has been used. Please deleting old network load balancer before adding more, skip adding nlb %s", 
                                    start_nlb_port, num_nlb_port+start_nlb_port-1, nlb_name)
                        continue
                    if total_nlb_az >= total_fw_az:
                        for index,item in enumerate(nlb_azs):
                            if 'NLB-IP' in item:
                                nlb_ip = item['NLB-IP']
                            else:
                                logger.error("NLB IP is missing in ADD-NLB msg, ignore this entry")
                                continue
                            nlb_subnet_id = item['SUBNET-ID']
                            nlb_zone_name = item['ZONE-NAME']
                            #Push NAT rules to all firewall in the same az  
                            if index  > total_fw_az:
                                continue
                            
                            response=lib.firewall_table_get_all_in_az_state(stackname, region, 'READY', fw_azs[index])
                            for fw in response['Items']:
                                fw_update = True
                                if lib.config_firewall_add_nat_rule(fwcontext, fw['MgmtIP'], KeyPANWFirewall, fw['UntrustIP'], nlb_port, nlb_ip, True, trust_def_gw[index], False) == False:
                                    logger.error('Config firewall NAT rule failed for instance %s, ip %s, NLB-port %d', fw['InstanceID'], fw['MgmtIP'], nlb_port)
                                    lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'COMMIT')
                            
                            logger.info("Add NLB entry IP %s, Port %d in COMMIT state", nlb_ip, nlb_port) 
                            lib.nlb_table_add_entry(stackname, region, nlb_ip, nlb_port, 'COMMIT', nlb_zone_name, nlb_subnet_id, total_nlb_az, index, dns_name, nlb_name)
                    else:
                        for index,item in enumerate(fw_azs):
                            response=lib.firewall_table_get_all_in_az_state(stackname, region, 'READY', item)
                            nlb_index = int(index%total_nlb_az)
                            az = nlb_azs[nlb_index]
                            nlb_ip = az['NLB-IP']
                            nlb_subnet_id = az['SUBNET-ID']
                            nlb_zone_name = az['ZONE-NAME']
                            
                            for fw in response['Items']:
                                fw_update = True
                                if lib.config_firewall_add_nat_rule(fwcontext, fw['MgmtIP'], KeyPANWFirewall, fw['UntrustIP'], nlb_port, nlb_ip, True, trust_def_gw[index], False) == False:
                                    logger.error('Config firewall NAT rule failed for instance %s, ip %s, NLB-port %d', fw['InstanceID'], fw['MgmtIP'], nlb_port)
                                    lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'COMMIT')
                            
                            if index < total_nlb_az:
                                    lib.nlb_table_add_entry(stackname, region, nlb_ip, nlb_port, 'COMMIT', nlb_zone_name, nlb_subnet_id, total_nlb_az, index, dns_name, nlb_name)
                elif nlb_type == 'DEL-NLB':
                    #Deleting all entries belong to same DNSName

                    print('Receive DEL-NLB msg from nlb queue')
                    response = lib.nlb_table_get_entry_by_dnsname(stackname, region, dns_name)
                    #Not found the NLB IP in the NLB table
                    if response['Count'] == 0:
                        logger.error("Receive NLB msg to delete non-existing NLB. DNS Name: %s", dns_name)
                        continue
                    for nlb in response['Items']:
                        nlb_port = nlb['TCPPort']
                        nlb_ip = nlb['NLBIp']
                        fw_response = lib.firewall_table_get_all_in_state(stackname, region, 'READY')
                        
                        for fw in fw_response['Items']:
                            fw_az_index=fw_azs.index(fw['AvailZone'])
                            nlb_az_index = fw_az_index%nlb['TotalAZ']
                            # if NLB az index doens't mach firewall az index, skip
                            if nlb['AZIndex'] != nlb_az_index:
                                continue 

                            fw_update = True
                            if lib.config_firewall_delete_nat_rule(fwcontext, fw['MgmtIP'], KeyPANWFirewall, nlb_port, True, False) == False:
                                logger.error('Delete firewall NAT rule failed for instance %s, IP %s, NLB-Port %d', fw['InstanceID'], fw['MgmtIP'], nlb_port)
                                lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'COMMIT')
                    
                    lib.nlb_table_delete_entry_by_dnsname(stackname, region, dns_name)
                        
                else:
                    logger.error('Receive invalid NLB message type for Network load balancer queue')

        except Exception as e:
            logger.exception("Exception occurred while retrieving data from NLB queue: {}".format(e))
   
    # Perform commit once for all firewalls in READY state
    if fw_update == True:
        try:
            nlb_port_mask = []
            for i in range (0, (num_nlb_port)/64):
                 nlb_port_mask.append(0)

            # Find all the nlb in commit state
            nlb_response=lib.nlb_table_get_all_in_state(stackname, region, 'COMMIT')
            print('nlb_response count: {}'.format(nlb_response['Count']))

            for nlb in nlb_response['Items']:
                nlb_port = nlb['TCPPort']
                nlb_ip = nlb['NLBIp']
                rule_mask_index = int((nlb_port-start_nlb_port)/64)
                nlb_bit = int((nlb_port-start_nlb_port)%64)
                nlb_port_mask[rule_mask_index] |= 1<<nlb_bit

            response=lib.firewall_table_get_all_in_state(stackname, region, 'READY')
            for fw in response['Items']:
                if lib.config_firewall_commit(fwcontext, fw['MgmtIP'], KeyPANWFirewall) == False:
                    logger.error('Commit firewall configuration failed for instance %s, IP %s', fw['InstanceID'], fw['MgmtIP'])
                    lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'COMMIT')
                else:
                    for mask in nlb_port_mask:
                        print('port mask commited in READY: {}'.format(mask))

                    lib.firewall_table_update_rule_mask(stackname, region, fw['InstanceID'], nlb_port_mask)
        except Exception as e:
            logger.exception("Exception occurred while updating firewall rules: {}".format(e))

 
    print("Time remaining return network_load_balancer_update (MS):", context.get_remaining_time_in_millis())


def firewall_init_config(event, context):
    """
    Method to monitor the firewall of INIT state in firewall table and set state
    to COMMIT if firewall auto commit completes

    :param event: Encodes all the input variables to the lambda function, when
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event
                  data to the handler function.
    :type event: dict

    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext

    :return: None
    """
    print("firewall_init_config Time remaining (MS):", context.get_remaining_time_in_millis())   
    
    #Get all firewall instance in INIT state
    response=lib.firewall_table_get_all_in_state(stackname, region, 'INIT')
    for fw in response['Items']:
        try:
            logger.info("Fireawall in init state: {}".format(fw))
            # Need this to by pass invalid certificate issue.
            fwcontext = lib.get_ssl_context()
    
            if lib.is_firewall_ready(fwcontext, fw['MgmtIP'],KeyPANWFirewall) == False:
                logger.info('Firewall is not in ready state yet')
                lib.is_firewall_auto_commit_done(fwcontext, fw['MgmtIP'],KeyPANWFirewall)
            else:
                # Configure firewall and push NAT rules
                if lib.config_firewall_init_setting(fwcontext, fw['MgmtIP'], KeyPANWFirewall,fw['AsgName'], fw['UntrustIP']) == False:
                    logger.error('Config firewall init setting failed')
                else:
                    lib.firewall_table_update_state(stackname, region, fw['InstanceID'], 'COMMIT')
        except Exception as e:
            logger.exception("Exception occurred while checking if firewall is ready: {}".format(e))

    print("Time remaining return firewall_init_config (MS):", context.get_remaining_time_in_millis())
        
def lambda_handler(event, context):
    """
    .. note:: This function is the entry point for the ```sched_event1``` Lambda function.

    This function performs the following actions:
    firewall_asg_update(event, context)
    firewall_init_config(event, context)
    network_load_balancer_update(event, context)

        | invokes ```check_and_send_message_to_queue()```
        |  desc: Checks the messages on the queue to ensure its up to date
        |        and for any changes as the case maybe.

        | invokes ```firewall_asg_update()```
        |  desc: monitor firewall asg and create asg if not exist

        | invokes ```firewall_init_config()```
        |  desc: monitor firewall in INIT state and move it to COMMIT if 
        |        firewall auto commit is done

        | invokes ```network_load_balancer_update()```
        |  desc: update firewall nat rules based on info in firewall table
        |        nlb table

    :param event: Encodes all the input variables to the lambda function, when
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event
                  data to the handler function.
    :type event: dict

    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext

    :return: None
    """
    global stackname
    global ilb_tag
    global elb_name
    global ELBTargetGroupName 
    global region
    global sg_mgmt
    global sg_untrust
    global sg_trust
    global sg_vpc
    global keyname
    global iamprofilebs
    global s3master
    global subnetmgmt
    global subnetuntrust
    global subnettrust
    global imageID
    global ScalingPeriod
    global ScaleUpThreshold
    global ScaleDownThreshold
    global ScalingParameter
    global instanceType
    global gcontext
    global MinInstancesASG
    global MaximumInstancesASG
    global LambdaExecutionRole
    global LambdaENISNSTopic
    global ASGNotifierRolePolicy
    global ASGNotifierRole
    global LambdaS3Bucket
    global PanS3KeyTpl
    global KeyPANWFirewall
    global KeyPANWPanorama
    global SubnetIDNATGW
    global SubnetIDLambda
    global PIP
    global PDG
    global PTPL
    global Hostname
    global logger
    global KeyDeLicense
    global LambdaENIQueue
    global NetworkLoadBalancerQueue 
    global fw_azs
    global trust_def_gw 

    gcontext = context
    #print("First operation remaining (MS):", context.get_remaining_time_in_millis())
    #print('Parameters {}...'.format(event))
    
    stackname=event['StackName']
    elb_name=event['ELBName']
    ELBTargetGroupName=event['ELBTargetGroupName']
    sg_mgmt=event['MgmtSecurityGroup']
    sg_trust=event['TrustSecurityGroup']
    sg_untrust=event['UntrustSecurityGroup']
    sg_vpc=event['VPCSecurityGroup']
    keyname=event['KeyName']
    s3master=event['BootstrapS3Bucket']
    subnetmgmt=event['SubnetIDMgmt']
    subnettrust=event['SubnetIDTrust']
    subnetuntrust=event['SubnetIDUntrust']
    imageID=event['ImageID']
    instanceType=event['FWInstanceType']
    region=event['Region']
    iamprofilebs=str(event['FirewallBootstrapRole'])
    LambdaENISNSTopic=str(event['LambdaENISNSTopic'])
    LambdaExecutionRole=str(event['LambdaExecutionRole'])
    ASGNotifierRole=str(event['ASGNotifierRole'])
    ASGNotifierRolePolicy=str(event['ASGNotifierRolePolicy'])
    LambdaS3Bucket=event['LambdaS3Bucket']
    PanS3KeyTpl=event['PanS3KeyTpl']
    KeyPANWFirewall=event['KeyPANWFirewall']
    KeyPANWPanorama=event['KeyPANWPanorama']
    SubnetIDNATGW=event['SubnetIDNATGW']
    SubnetIDLambda=event['SubnetIDLambda']
    PIP=event['PIP']
    PDG=event['PDG']
    PTPL=event['PTPL']
    Hostname=event['Hostname']
    KeyDeLicense=event['KeyDeLicense']
    LambdaENIQueue=event['LambdaENIQueue']
    NetworkLoadBalancerQueue=event['NetworkLoadBalancerQueue']

    logger = logging.getLogger()

    debug = event['Debug']
    if debug == 'Yes':
        logger.setLevel(logging.INFO)

    logger.info('got event{}'.format(event))

    subnetuntrust=str(lib.fix_unicode(subnetuntrust))
    subnetuntrust=lib.fix_subnets(subnetuntrust)
    
    subnetmgmt=str(lib.fix_unicode(subnetmgmt))
    subnetmgmt=lib.fix_subnets(subnetmgmt)
    
    subnettrust=str(lib.fix_unicode(subnettrust))
    subnettrust=lib.fix_subnets(subnettrust)

    SubnetIDNATGW=str(lib.fix_unicode(SubnetIDNATGW))
    SubnetIDNATGW=lib.fix_subnets(SubnetIDNATGW)

    SubnetIDLambda=str(lib.fix_unicode(SubnetIDLambda))
    SubnetIDLambda=lib.fix_subnets(SubnetIDLambda)
    
    logger.info('StackName:' +  event['StackName'])
    logger.info('ELB Name: ' + elb_name)
    logger.info('Mgmt Security Group ID : ' + sg_mgmt)
    logger.info('KeyName is :' + keyname)
    logger.info('S3 Master Bucket :' + s3master)
    logger.info('iamprofilebs: ' + iamprofilebs)
    logger.info('Subnet Mgmt List: ' + subnetmgmt)
    logger.info('Subnet Untrust List: ' + subnetuntrust)
    logger.info('Subnet Trust List: ' + subnettrust)
    if PIP != "":
        logger.info('Panorama IP is: ' + PIP)

    ScalingPeriod = int(event['ScalingPeriod'])
    ScaleUpThreshold = float(event['ScaleUpThreshold'])
    ScaleDownThreshold = float(event['ScaleDownThreshold'])
    ScalingParameter = event['ScalingParameter']
    MinInstancesASG = int(event['MinInstancesASG'])
    MaximumInstancesASG = int(event['MaximumInstancesASG']) 

    stack_metadata= {
                'SGM': sg_mgmt, 'SGU': sg_untrust, 'SGT': sg_trust, 'SGV': sg_vpc,
                'IamLambda': LambdaExecutionRole, 'StackName': stackname, 'LambdaS3Bucket': LambdaS3Bucket,
                'PanS3KeyTpl': PanS3KeyTpl, 
                'ScalingParameter': ScalingParameter, 
                'SubnetIDNATGW': SubnetIDNATGW, 
                'PIP': PIP, 'PDG': PDG, 'PTPL': PTPL, 'Hostname': Hostname, "Debug":debug
               }

    check_and_send_message_to_queue(LambdaENIQueue, json.dumps(stack_metadata))

    logger.info('First Time remaining (MS):' + str(context.get_remaining_time_in_millis()))

    try:
        fw_azs = lib.getAzs(subnettrust)
        trust_def_gw = []
        for i in fw_azs:
            trust_subnet_id=lib.choose_subnet(subnettrust, i)
            subnet=ec2.Subnet(trust_subnet_id)
            subnet_str,gw=lib.get_subnet_and_gw(subnet.cidr_block)
            trust_def_gw.append(gw)
            #logger.info("Trust subnet default gw[{}]: {}".format(i, trust_def_gw[i]))
    except Exception as e:
        logger.exception("Get az and trust default gw error]: {}".format(e))

    firewall_asg_update(event, context)
    firewall_init_config(event, context)
    network_load_balancer_update(event, context)
    
    logger.info('DONE: Last Operations: Time remaining (MS):' + str(context.get_remaining_time_in_millis()))
