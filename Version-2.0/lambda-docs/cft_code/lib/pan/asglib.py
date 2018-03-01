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

import boto3
import botocore
import json
import logging
import time
import socket
import struct
import decimal
import uuid
import logging
import urllib2
import urllib
import ssl
import xml.etree.ElementTree as et
from httplib import HTTPSConnection
#import ssl
#from boto3.dynamodb.conditions import Key, Attr


logger = logging.getLogger()

# Enable creation of S3 bucket per-ASG
enable_s3=False
num_nlb_port=1280
start_nlb_port=81

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
sqs = boto3.client('sqs')
sns = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')


def purge_stack_queue(queue_url):
    """
    Delete all the messages in the queue

    :param queue_url: URL of the queue
    :return: None
    """
    sqs.purge_queue(QueueUrl=queue_url)

def set_queue_attributes(queue_url, retention_period):
    """
    Set the queue attributes

    :param queue_url: URL of the queue
    :param retention_period: Duration of time that the message
                             will be retained for.
    :return: None
    """
    try:         
        sqs.set_queue_attributes(QueueUrl=queue_url,
                                 Attributes={
                                    'MessageRetentionPeriod': str(retention_period)
                                }
        )
        
    except Exception as e:
        logger.exception('Unable to set queue attributes')
        

def get_from_sqs_queue(queue_url, visiblity_timeout=10, waittimes_seconds=5):
    """
     Retrieve data from a queue

     :param queue_url: URL of the queue
     :param visiblity_timeout: The duration during which the message will not
                               be available to other consumers
     :param waittimes_seconds: Wait timeout
     :return: None
    """
    stack_msg = None
    stack_attrs = None

    for retry in range(0, 10):
        time.sleep(5) 
        try:
            logger.info('Retrieve data from queue: {}'.format(queue_url))
            response = sqs.receive_message(QueueUrl=queue_url, 
                                       MaxNumberOfMessages=10, 
                                       AttributeNames=['All'],
                                       MessageAttributeNames=['All'], 
                                       VisibilityTimeout=visiblity_timeout,
                                       WaitTimeSeconds=waittimes_seconds)

            logger.info('Retrieved response: {}'.format(response))

            for message in response.get('Messages', []):
                if message:
                    msg_attr = message.get('MessageAttributes', None)
                    handle = message.get('ReceiptHandle', None)
                    if msg_attr and 'panw-fw-stack-params' in msg_attr.keys():
                        stack_msg = message.get('Body', None)
                        logger.info('Stack message: {}'.format(stack_msg))
                    attrs = message.get('Attributes')
                    senttimestamp = attrs.get('SentTimestamp', None)
                    logger.info('msg details:: msg: {} ts: {} rh: {}'.format(stack_msg, senttimestamp, handle))
                    return (stack_msg, senttimestamp, handle) 
        except Exception as e:
            logger.exception('Exception occurred retrieving message from queue: {}'.format(e))

    
    return None, None, None

def send_message_to_queue(queue_url, str_message):
    """
    Send a message on the specified queue.

    :param queue_url: The URL of the queue
    :param str_message: Message to send to the queue
    :return:  None
    """
    logger.info("Sending message to queue: {}".format(str_message))
    ret_dict = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=str_message,
        MessageAttributes={
            'panw-fw-stack-params': {
                'StringValue': '1000',
                'DataType' : 'String'
            }
        }
    )
    logger.info("Response data from sending message to queue: {}".format(ret_dict))

def delete_message_from_queue(queue_url, receipt_handle):
    """
    Delete a message from the SQS queue.

    :param queue_url: The URL of the queue
    :param receipt_handle: The receipt handle of the message
    :return: None
    """
    logger.info('Attempting to delete the message from the queue')

    try:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
    except Exception as e:
        logger.exception('Exception occurred while attemption to delete message from the queue.')

def get_from_nlb_queue(queue_url, visiblity_timeout=10, waittimes_seconds=0):
    """
    Retrieve a message from nlb queue

    :param queue_url:
    :param visiblity_timeout:
    :param waittimes_seconds:
    :return: msg or None
    """
    nlb_msg = None
    nlb_attrs = None
        
    try:
        logger.info('Retrieve data from queue: {}'.format(queue_url))
        response = sqs.receive_message(QueueUrl=queue_url,
                                       MaxNumberOfMessages=1,
                                       AttributeNames=['All'],
                                       MessageAttributeNames=['All'],
                                       VisibilityTimeout=visiblity_timeout,
                                       WaitTimeSeconds=waittimes_seconds)
    
        logger.info('Retrieved response: {}'.format(response))
        
        for message in response.get('Messages', []):
            if message:
                msg_attr = message.get('MessageAttributes', None)
                handle = message.get('ReceiptHandle', None)
                if msg_attr and 'panw-fw-nlb-msg' in msg_attr.keys():
                    nlb_msg = message.get('Body', None)
                    logger.info('NLB message: {}'.format(nlb_msg))
                attrs = message.get('Attributes')
                senttimestamp = attrs.get('SentTimestamp', None)
                logger.info('NLB queue msg details:: msg: {} ts: {} rh: {}'.format(nlb_msg, senttimestamp, handle))
                return (nlb_msg, senttimestamp, handle)
    except Exception as e:
        logger.exception('Exception occurred retrieving message from NLB queue: {}'.format(e))

    return None, None, None

def send_message_to_nlb_queue(queue_url, str_message):
    """
    Send a message on the Network Load Balancer queue.

    :param queue_url: The URL of the queue
    :param str_message: Message to send to the queue
    :return:  None
    """


    logger.info("Sending message to NLB queue: {}".format(str_message))
    ret_dict = sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=str_message,
        MessageAttributes={
            'panw-fw-nlb-msg': {
                'StringValue': '1000',
                'DataType' : 'String'
            }
        }
    )
    logger.info("Response data from sending message to NLB queue: {}".format(ret_dict))

def substring_after(s, delim):
    """

    :param s:
    :param delim:
    :return:
    """
    return s.partition(delim)[2]

def fix_unicode(data):
    """
        Method to convert opaque data from unicode to utf-8
        :param data: Opaque data
        :return: utf-8 encoded data
    """
    if isinstance(data, unicode):
        return data.encode('utf-8')
    elif isinstance(data, dict):
        data = dict((fix_unicode(k), fix_unicode(data[k])) for k in data)
    elif isinstance(data, list):
        for i in xrange(0, len(data)):
            data[i] = fix_unicode(data[i])

    return data

def fix_subnets(data1):
    """

    :param data1:
    :return:
    """
    data=str(data1)
    data=data.replace("'", "")
    data=data.replace("[", "")
    data=data.replace("]", "")
    return data
  
def ip2int(addr):
    """

    :param addr:
    :return:
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    """

    :param addr:
    :return:
    """
    return socket.inet_ntoa(struct.pack("!I", addr))
 
def get_subnet_and_gw(ip_cidr):
    """
    Extract subnet and gateway from subnet cidr in AWS

    :param ip_cidr:
    :return:
    """
    addr_mask = ip_cidr.split('/')
    addr = addr_mask[0]
    try:
        mask = addr_mask[1]
    except IndexError:
        mask = '32'

    # convert to int
    addr = ip2int(addr)
    mask = int(mask)

    subnet = addr & ((0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF)
    if mask == 32:
        gw = addr
    else:
        gw = subnet | 1

    return (int2ip(subnet), int2ip(gw))

def retrieve_fw_ip(instance_id):
    """
    Retrieve the IP of the Instance

    :param instance_id: The id of the instance
    :type instance_id: str
    """

    eni_response=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [instance_id]},
                    {'Name': "attachment.device-index", 'Values': ["1"]}])

    logger.info("Describe network interfaces response: {}".format(eni_response))

    eniId=""
    for eni in eni_response['NetworkInterfaces']:
        eniId=eni['NetworkInterfaceId']

    if eniId == "":
        logger.error('Mgmt ENI ID not found for instance: ' + instance_id)
        return False
    

    logger.info('Eni ID (eth1) for instance : ' + instance_id + ' is: ' + eniId)
    try:
        response=ec2_client.describe_network_interfaces(NetworkInterfaceIds=[eniId])
    except Exception as e:
        logger.error("[Describe network interfaces failed while retrieving fw ip]: {}".format(e))
        return False

    ip="NO_IP"
    try:
        for i in response['NetworkInterfaces']:
            logger.info(i['PrivateIpAddresses'])
            ip=i['PrivateIpAddress']
    except Exception as e:
        logger.error("[FW IP Address in retrieve fw ip]: {}".format(e))
        ip="NO_PrivateIP_ADDR"

    if ip.find("NO_") >= 0:
        logger.error('We failed to get either EIP or Private IP for instance: ' + str(instance_id) + ' IP: ' + ip)
        logger.error('We will not proceed further with this Instance: ' + str(instance_id))
        return False
    else:
        logger.info('The IP address of the fw device is: {}'.format(ip))
        return ip
 
def get_asg_name(stackname, elbtg, az):
    """
    Construct asg name

    :param stackname:
    :param :elbtg
    :param az:
    :return: asg name
    """
    name = stackname[:10] + '-' + elbtg + '_ASG_' + az
    return name[-63:len(name)]

def get_sched_func_name(stackname, elbtg):
    """

    :param stackname:
    :param elbtg:
    :return:
    """
    name= stackname[:10] + '-'+ elbtg + '-lambda-sched-event'
    return name[-63:len(name)]

def get_lambda_statement_id(stackname, elbtg):
    """

    :param stackname:
    :param elbtg:
    :return:
    """
    statementId = stackname[:10] + '-' + elbtg + '-lambda_add_perm'
    return statementId[-63:len(statementId)]

def get_lc_name(stackname, elbtg, az):
    """

    :param stackname:
    :param elbtg:
    :param az:
    :return:
    """
    name = stackname[:10] + '-' + elbtg + '_ASG_LC_' + az
    return name[-63:len(name)]

def get_cw_name_space(stackname, asg_name):
    """

    :param stackname:
    :param asg_name:
    :return:
    """
    name = asg_name
    return name[-63:len(name)]

def get_s3_bucket_name(stackname, ilbtag):
    """
    
    :param stackname:
    :param ilbtag:
    :return:
    """
    logger.info('Stackname: ' + stackname)
    name = stackname + '-bstrap-'
    name=name.lower()
    return name[-63:len(name)]

def get_nlb_table_name(stackname, region):
    """
    
    :param stackname:
    :param region:
    :return:
    """
    name=stackname+"-nlb-"+region
    return name

def get_firewall_table_name(stackname, region):
    """
 
    :param stackname:
    :param region:
    :return:
    """
    name=stackname+"-firewall-"+region
    return name

#DUMMY FUNC -- NOT USED
def get_s3_bucket_name1(stackname, ilbtag, ip_address):
    if enable_s3 == False:
        return "enable_s3_is_false"

    first=stackname.split('-')
    try:
        response=elbv2.describe_load_balancers(Names=[ilbtag])
    except Exception as e:
         logger.info("[S3 Delete Bucket]: {}".format(e))
         return "s3-bucket-not-found"

    ilb=first[0] + str(ip_address.replace(".", "-"))
    logger.info('ILB: ' + ilb)
    cnt=0
    for i in response['LoadBalancers']:
        logger.info('DNSName: ' + i['DNSName'])
        dnsname=i['DNSName']
        list=dnsname.split('.')
        ilb=ilb + list[0]
        cnt = cnt + 1
 
    logger.info('ILB: ' + ilb)
    name=""
    if cnt == 0:
       logger.critical('Problem with S3 bucketnaming: Didnt find ILB' + ilb)
       name = stackname + '-bstrap-' + str(ip_address.replace(".", "-"))
    elif cnt > 1:
       logger.crictical('Problem with S3 bucketnaming: ' + ilb)
       name = stackname + '-bstrap-' + str(ip_address.replace(".", "-"))
    else:
       name=ilb

    name=name.lower()
    return name[-63:len(name)]

def get_lambda_cloud_watch_func_name(stackname, asg_name, instanceId):
    """
    Generate the name of the cloud watch metrics as a function
    of the ASG name and the instance id.
    :param stackname:
    :param asg_name:
    :param instanceId:
    :return: str
    """
    name = asg_name + '-cwm-' + str(instanceId)
    return name[-63:len(name)]

def get_event_rule_name(stackname, instanceId):
    """
    Generate the name of the event rule.

    :param stackname:
    :param instanceId:
    :return: str
    """
    name = stackname + '-cw-event-rule-' + str(instanceId)
    return name[-63:len(name)]

def get_statement_id(stackname, instanceId):
    """

    :param stackname:
    :param instanceId:
    :return:
    """
    name = stackname + '-cw-statementid-' + str(instanceId)
    return name[-63:len(name)]

def get_target_id_name(stackname, instanceId):
    """

    :param stackname:
    :param instanceId:
    :return:
    """
    name = stackname + '-lmda-target-id' + str(instanceId)
    return name[-63:len(name)]

def choose_subnet(subnet, AvailabilityZone):
    """
    Method to identify the subnet id based upon the
    availability zone.

    :param subnet:
    :param AvailabilityZone:
    :return:
    """
    logger.info('Choose Subnets: ')
    logger.info(subnet)
    list_subnets=subnet.split(",")
    response=ec2_client.describe_subnets(SubnetIds=list_subnets)
    ret_subnets=""
    for i in response['Subnets']:
        if i['AvailabilityZone'] == AvailabilityZone:
            if ret_subnets == "":
                ret_subnets=i['SubnetId']
            else:
                ret_subnets= ret_subnets + "," + i['SubnetId']

    logger.info('Return Subnets for AZ: ' + AvailabilityZone + ' Subnets: ' + ret_subnets)
    return ret_subnets

def getASGTag(rid, key):
    """
    Set tags on a specified auto scale group.
   
    .. note:: This method is important from the perspective
              that it allows the lambda function code to
              distinguish ```PAN-FW``` deployed ASG's from
              other ASG's that might already exist in the
              customer VPC.
   
    :param rid: The name of the ASG
    :param key: The tag to retrieve
    :return: None or str
    """
    logger.info('Getting all the tags for rid: ' + rid)
    try:
        response=asg.describe_tags(Filters=[{'Name': 'auto-scaling-group', 'Values': [rid]}])
    except Exception as e:
         logger.info("[Failed to describe tag]: {}".format(e))
         return None

    logger.info(response)
    for i in response['Tags']:
        if i['Key'] == key:
            return i['Value']

    return None

def setASGTag(rid, key, value):
    """
    Set ```PAN-FW``` specific tags on an ASG.

    .. note:: This method is important from the perspective
              that it allows the lambda function code to
              distinguish ```PAN-FW``` deployed ASG's from
              other ASG's that might already exist in the
              customer VPC.

    :param rid: Name of the ASG
    :param key: Tag
    :param value: Tag Value
    :return: None
    """
    try:
        asg.create_or_update_tags(Tags=[{'ResourceId': rid, 'ResourceType': "auto-scaling-group", 'Key': key, 'Value': value, 'PropagateAtLaunch': False}])
    except Exception as e:
         logger.info("[Failed to Set Tag]: {}".format(e))
    return

def runCommand(gcontext, cmd, gwMgmtIp, api_key):
    """

    Method to run generic API commands against a PAN Firewall.

    .. note:: This is a generic method to interact with PAN
              firewalls to execute api calls.

    :param gcontext: SSL Context
    :param cmd: Command to execute
    :param gwMgmtIp: Management IP of the PAN FW
    :param api_key: API key of the Firewall
    :return: None or str
    """
    try:
        response = urllib2.urlopen(cmd, context=gcontext, timeout=5).read()
        logger.info("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
        logger.error("[RunCommand Response Fail]: {}".format(e))
        return None

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.error("[ERROR]: didn't get a valid response from Firewall command: " + cmd)
        return None

    if resp_header.attrib['status'] == 'error':
        logger.error("[ERROR]: Got an error for the command: " + cmd)
        return None

    if resp_header.attrib['status'] == 'success':
        return response

    return None

def runShutdownCommand(gcontext, cmd, gwMgmtIp, api_key):
    """
    Method to shutdown a device.

    :param gcontext:
    :param cmd:
    :param gwMgmtIp:
    :param api_key:
    :return: bool 
    """
    try:
        response = urllib2.urlopen(cmd, context=gcontext, timeout=5).read()
        logger.info("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
        logger.warning("[RunCommand Response Fail]: firewall could be shutting down {}".format(e))
        return True

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.error("[ERROR]: didn't get a valid response from Firewall command: " + cmd)
        return False

    if resp_header.attrib['status'] == 'error':
        logger.error("[ERROR]: Got an error for the command: " + cmd)
        return False

    if resp_header.attrib['status'] == 'success':
        return True

    return False
def send_command(conn, req_url):
    """
    An alternative interface to interact with the PAN FW's

    :param conn:
    :param req_url:
    :return: dict
    """
    conn.request("POST", req_url)
    resp = conn.getresponse()
    msg = resp.read()
    
    if resp.status == 200 :
        logger.info('[200 OK] CMD: ' +  req_url + '    MSG in send_command(): ' + msg)
        root = et.fromstring(msg)
        if root.attrib['status'] == 'success':
            logger.info('Success response status. Data: {} Type: {}'.format(str(root), type(root)))
            return {'result': True, 'data': root}
        elif root.attrib['status'] == 'error':
            logger.info('Command succeeded but the status is error.')
            conn.close()
            logger.info('Error response status. Data: {} Type: {}'.format(str(root), type(root)))
            return {'result': False, 'data': root}
        else:
            conn.close()
            logger.error('Failure received in send_command for URL: ' + str(req_url))
            return {'result': False, 'data': msg}
    else:
        logger.error('Status is not 200 in send_command for URL: ' + str(req_url))
        logger.info('CMD: ' +  req_url + '    MSG in send_command(): ' + msg)
        conn.close()
        return {'result': False, 'data': None}

def remove_device(stackname, remove, PanoramaIP, api_key, dev_group, tp_group, serial_no, gwMgmtIp):
    """
    Method to remove a device from Panorama.

    :param stackname:
    :param remove:
    :param PanoramaIP:
    :param api_key:
    :param dev_group:
    :param tp_group:
    :param serial_no:
    :param gwMgmtIp:
    :return: None or str
    """
    conn = HTTPSConnection(PanoramaIP, 443, timeout=10, context=ssl._create_unverified_context())

    if dev_group != "":
        cmd_show_device_group = "/api/?type=op&cmd=<show><devicegroups><name>%s</name></devicegroups></show>&key=%s"%(dev_group, api_key)
        response = send_command(conn, cmd_show_device_group)
        if response['result'] == False:
            conn.close()
            logger.error('Panorama: Fail to execute Panorama API show dg for device: ' + gwMgmtIp)
            return None

        logger.info('show dg: ' + str(response))
        #data = response['data'].findall('./result/devices/*')
        data = response['data'].findall('./result/devicegroups/entry/devices/*')

        for entry in data:
            ip_tag = entry.find('ip-address')
            if ip_tag is None:
                print('ip_tag: ' + str(ip_tag))
                pass
            else:
                ip_addr = ip_tag.text
                if ip_addr == gwMgmtIp:
                    serial_no = entry.attrib.get('name')
                    logger.info('entry: ' + str(entry.tag) + ' ' + str(entry.text) + ' ' + str(entry.attrib))
                    logger.info('serial_no in show dg: ' + str(serial_no))

        if serial_no == "":
            logger.error('Panorama: Fail to find serial number for device: ' + gwMgmtIp)
        elif remove == True:
            logger.info('show dg: serial number is: (' + str(serial_no) + ')')
            cmd_delete_from_devgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/devices/entry[@name='%s']&key=%s"%(dev_group, serial_no, api_key)
            response = send_command(conn, cmd_delete_from_devgroup)
            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API delete dg for device: ' + gwMgmtIp)
                return None

    if tp_group != "":
        if serial_no == "":
            cmd_show_template = "/api/?type=op&cmd=<show><templates><name>%s</name></templates></show>&key=%s"%(tp_group, api_key)
            response = send_command(conn, cmd_show_template)
            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API show template for device: ' + gwMgmtIp)
                return None

            logger.info('show tpl: response: ' + str(response))
            #data = response['data'].findall('./result/devices/*')
            data = response['data'].findall('./result/templates/entry/devices/*')

            for entry in data:
                ip_tag = entry.find('ip-address')
                if ip_tag is None:
                    print('ip_tag: ' + str(ip_tag))
                    pass
                else:
                    ip_addr = ip_tag.text
                    if ip_addr == gwMgmtIp:
                        serial_no = entry.attrib.get('name')
                        logger.info('entry: ' + str(entry.tag) + ' ' + str(entry.text) + ' ' + str(entry.attrib))
                        logger.info('serial_no in show tpl: ' + str(serial_no))

            if serial_no == "":
                logger.error('Panorama: Fail to serial number in show template for device: ' + gwMgmtIp)


        if serial_no != "" and remove == True:
            cmd_delete_from_tpgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/devices/entry[@name='%s']&key=%s"%(tp_group, serial_no, api_key)
            #send and make sure it is successful
            response = send_command(conn, cmd_delete_from_tpgroup)

            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API delete template for device: ' + gwMgmtIp)
                return None

    if serial_no == "":
        cmd_show_all_devices = "/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=%s"%(api_key)
        response = send_command(conn, cmd_show_all_devices)
        if response['result'] == False:
            conn.close()
            logger.error('Panorama: Fail to execute Panorama API show devices for device: ' + gwMgmtIp)
            return None

        logger.info('show all devices: response: ' + str(response))
        data = response['data'].findall('./result/devices/*')

        for entry in data:
            ip_tag = entry.find('ip-address')
            if ip_tag is None:
                pass
            else:
                ip_addr = ip_tag.text
                if ip_addr == gwMgmtIp:
                    serial_no = entry.attrib.get('name')

        if serial_no == "":
            logger.error('Panorama: No registered device found with IP address: ' + gwMgmtIp)
            conn.close()
            return "Done"

    if remove == False:
        conn.close()
        return serial_no

    cmd_delete_device = "/api/?type=config&action=delete&xpath=/config/mgt-config/devices/entry[@name='%s']&key=%s"%(serial_no, api_key)
    response = send_command(conn, cmd_delete_device)
    if response['result'] == False:
        conn.close()
        logger.error('Panorama: Fail to execute Panorama API delete device for device: ' + gwMgmtIp)
        return None

    logger.info('delete unmanaged device: response: ' + str(response))
    cmd_commit = "/api/?type=commit&cmd=<commit></commit>&key="+api_key
    response = send_command(conn, cmd_commit)

    if response['result'] == False:
        conn.close()
        logger.error('Panorama: Fail to execute Panorama API commit for device: ' + gwMgmtIp)
        return None

    job_id=""
    data = response['data'].findall('./result/*')
    for entry in data:
        if entry.tag == 'job':
            job_id = entry.text

    if job_id == "":
        conn.close()
        return None

    logger.info('Commit is being done')
    cmd_commit_success  = "/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
    response = send_command(conn, cmd_commit_success)

    if response['result'] == False:
        conn.close()
        logger.error('Panorama: Fail to execute Panorama API show jobs for device: ' + gwMgmtIp)
        return None

    conn.close()
    return "Done"

def get_ssl_context():  
    """
    Create default ssl context
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options = ssl.PROTOCOL_TLSv1_2
    return ctx

def execute_api_request(gwMgmtIp, port, cmd):
    """
    Execute API requests against the FW.
    :param gwMgmtIp:
    :param port:
    :param cmd:
    :return:
    """
    conn = None
    conn = HTTPSConnection(gwMgmtIp, port, timeout=10, context=ssl._create_unverified_context())
    response = None
    ex_occurred = False
    try:
        response = send_command(conn, cmd)
    except Exception as e:
        logger.exception('Executing API Request. Cmd: {} {}'.format(cmd, e))
        ex_occurred = True

    if ex_occurred:
        ctx = get_ssl_context()
        logger.warning('Exception occurred in the first attempt. Attempting again with default ssl context')
        response = None
        ctx = get_ssl_context()
        conn = HTTPSConnection(gwMgmtIp, 443, timeout=10, context=ctx)
        response = send_command(conn, cmd)

    conn.close()
    return response

def get_device_serial_no(gcontext, instanceId, gwMgmtIp, fwApiKey):
    """
    Retrieve the serial number from the FW.

    :param gcontext: ssl context
    :param instanceId: instance Id 
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: The serial number of the FW
    :rtype: str
    """

    serial_no = None
    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return None

    logger.info('Retrieve the serial number from FW {} with IP: {}'.format(instanceId, gwMgmtIp))
    fw_cmd="https://"+gwMgmtIp+"/api/?type=op&key="+fwApiKey+"&cmd=<show><system><info/></system></show>"
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            pan_print('CFG_FW_GET_SERIAL_NO: Failed to run command: ' + fw_cmd)
            return None
    except Exception as e:
        pan_print("[CFG_FW_GET_SERIAL_NO]: {}".format(e))
        return None

    resp = et.fromstring(response) 
    serial_info = resp.findall(".//serial")
    for info in serial_info:
        serial_no = info.text

    if not serial_no:
        logger.error("Unable to retrieve the serial number from device: {} with IP: {}".format(instanceId, gwMgmtIp))

    return serial_no


def deactivate_fw_license(gcontext, instanceId, gwMgmtIp, fwApiKey):
    """
    Call the FW to deactivate the license from the licensing
    server

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: Api call status
    :rtype: bool 
    """

    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return False

    logger.info('Deactivate and the license for FW: {} with IP: {}'.format(instanceId, gwMgmtIp))
   
    fw_cmd = "https://{}/api/?type=op&key={}&cmd=<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>".format(gwMgmtIp, fwApiKey)
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            pan_print('CFG_FW_DELICENSE: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
        pan_print("[CFG_FW_DELICENSE]: {}".format(e))
        return False

    return True
  
def shutdown_fw_device(gcontext, instanceId, gwMgmtIp, fwApiKey):
    """
    Shutdown the firewall device

    :param gcontext: ssl context
    :param instanceId: instance Id
    :param gwMgmtIP: The IP address of the FW
    :param fwApiKey: Api key of the FW

    :return: Api call status
    :rtype: bool
    """
    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return False

    logger.info('Shutdown the firewall device : {} with IP: {}'.format(instanceId, gwMgmtIp))
   
    fw_cmd = "https://{}/api/?type=op&key={}&cmd=<request><shutdown><system></system></shutdown></request>".format(gwMgmtIp, fwApiKey)

    try:
        response = runShutdownCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response == False:
            pan_print('CFG_FW_SHUTDOWN: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
        pan_print("[CFG_FW_SHUTDOWN]: {}".format(e))
        return False

    return True

def set_deactivate_api_key(gcontext, instanceId, gwMgmtIp, fwApiKey, deactivateApiKey):
    """
    Setup the deactivate api key to allow the FW deactivate sequence
    :param instanceId:
    :param gwMgmtIp:
    :param fwApiKey:
    :param deactivateApiKey:
    :return: bool
    """

    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not interact with the device')
        return False

    logger.info('Setup the deactivate API Key on the FW for device {} with IP: {}'.format(instanceId, gwMgmtIp))

    fw_cmd = "https://{}/api/?type=op&key={}&cmd=<request><license><api-key><set><key>{}</key></set></api-key></license></request>".format(gwMgmtIp, fwApiKey, deactivateApiKey)
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, fwApiKey)
        if response is None:
            pan_print('CFG_FW_SET_DELIC_KEY: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
        pan_print("[CFG_FW_SET_DELIC_KEY]: {}".format(e))
        return False

    return True

def remove_fw_from_panorama(instanceId, KeyPANWPanorama, gwMgmtIp, PanoramaIP, PanoramaDG, PanoramaTPL):
    """

    :param instanceId:
    :param KeyPANWPanorama:
    :param gwMgmtIp:
    :param PanoramaIP:
    :param PanoramaDG:
    :param PanoramaTPL:
    :return:
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    logger.info('Panorama: Removing PANW Firewall IP : ' + str(instanceId) + ' from Panorama IP: ' + str(PanoramaIP))

    if gwMgmtIp is None:
        logger.error('Firewall IP could not be found. Can not remove it from Panorama')
        return False

    print('Panorama: Firewall IP address to remove from Panorama is: ' + gwMgmtIp)

    conn = HTTPSConnection(PanoramaIP, 443, timeout=10, context=ssl._create_unverified_context())

    serial_no = ""
    dev_group = PanoramaDG
    tp_group = PanoramaTPL
    api_key = KeyPANWPanorama
    connected="yes"

    if dev_group != "":
        cmd_show_device_group = "/api/?type=op&cmd=<show><devicegroups><name>%s</name></devicegroups></show>&key=%s"%(dev_group, api_key)
        response = send_command(conn, cmd_show_device_group)
        if response['result'] == False:
            conn.close()
            logger.error('Panorama: Fail to execute Panorama API show dg for device: ' + gwMgmtIp)
            return False
        
        logger.info('show dg: ' + str(response))
        #data = response['data'].findall('./result/devices/*')
        data = response['data'].findall('./result/devicegroups/entry/devices/*')

        for entry in data:
            ip_tag = entry.find('ip-address')
            if ip_tag is None:
                logger.info('ip_tag: ' + str(ip_tag))
                pass
            else:
                ip_addr = ip_tag.text
                if ip_addr == gwMgmtIp:
                    serial_no = entry.attrib.get('name')
                    logger.info('entry: ' + str(entry.tag) + ' ' + str(entry.text) + ' ' + str(entry.attrib))
                    logger.info('serial_no in show dg: ' + str(serial_no))
                    state= entry.find('connected')
                    if state is not None:
                        connected=state.text
                        logger.info('show dg device state tag value: ' + str(connected))
                        if str(connected) == "yes":
                            logger.error('Device is still in connected state in show dg: ' + gwMgmtIp)
                            conn.close()
                            return False

        if serial_no == "":
            logger.error('Panorama: Fail to find serial number for device: ' + gwMgmtIp)
        else:
            logger.info('show dg: serial number is: (' + str(serial_no) + ')')
            cmd_delete_from_devgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/devices/entry[@name='%s']&key=%s"%(dev_group, serial_no, api_key)
            response = send_command(conn, cmd_delete_from_devgroup)
            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API delete dg for device: ' + gwMgmtIp)
                return False

    if tp_group != "":
        if serial_no == "":
            cmd_show_template = "/api/?type=op&cmd=<show><templates><name>%s</name></templates></show>&key=%s"%(tp_group, api_key)
            response = send_command(conn, cmd_show_template)
            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API show template for device: ' + gwMgmtIp)
                return False

            logger.info('show tpl: response: ' + str(response))
            #data = response['data'].findall('./result/devices/*')
            data = response['data'].findall('./result/templates/entry/devices/*')

            for entry in data:
                ip_tag = entry.find('ip-address')
                if ip_tag is None:
                    logger.info('ip_tag: ' + str(ip_tag))
                    pass
                else:
                    ip_addr = ip_tag.text
                    if ip_addr == gwMgmtIp:
                        serial_no = entry.attrib.get('name')
                        logger.info('entry: ' + str(entry.tag) + ' ' + str(entry.text) + ' ' + str(entry.attrib))
                        logger.info('serial_no in show tpl: ' + str(serial_no))
                        state= entry.find('connected')
                        if state is not None:
                            connected=state.text
                            logger.info('show tpl device state tag value: ' + str(connected))
                            if str(connected) == "yes":
                                logger.error('Device is still in connected state in show tpl: ' + gwMgmtIp)
                                conn.close()
                                return False

            if serial_no == "":
                logger.error('Panorama: Fail to get serial number in show template for device: ' + gwMgmtIp)


        if serial_no != "":
            #Get panorama version
            sw_ver = ""
            cmd_show_system_info = "/api/?type=op&cmd=<show><system><info/></system></show>&key=%s"%(api_key)
            response = send_command(conn, cmd_show_system_info)
            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API show system info')
                return False
            logger.info('show system info: response: ' + str(response))

            sw_info = response['data'].findall(".//sw-version")
            for info in sw_info:
                sw_ver = info.text

            if sw_ver == "":
                logger.error('Panorama: Fail to get software version in show system info')
                cmd_delete_from_tpgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/devices/entry[@name='%s']&key=%s" % (tp_group, serial_no, api_key)
            else:
                logger.info('Panorama software version: ' + sw_ver)
                try:
                    if float(sw_ver[:3]) >= float(8.1):
                        cmd_delete_from_tpgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='%s']/devices/entry[@name='%s']&key=%s"%(tp_group, serial_no, api_key)
                    else:
                        cmd_delete_from_tpgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/devices/entry[@name='%s']&key=%s"%(tp_group, serial_no, api_key)
                except Exception as e:
                    logger.error('Panorama: get invalid software version: ' + sw_ver)
                    cmd_delete_from_tpgroup = "/api/?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']/devices/entry[@name='%s']&key=%s" % (tp_group, serial_no, api_key)

            #send and make sure it is successful
            response = send_command(conn, cmd_delete_from_tpgroup)

            if response['result'] == False:
                conn.close()
                logger.error('Panorama: Fail to execute Panorama API delete template for device: ' + gwMgmtIp)
                return False

    if serial_no == "":
        cmd_show_all_devices = "/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=%s"%(api_key)
        response = send_command(conn, cmd_show_all_devices)
        if response['result'] == False:
            conn.close() 
            logger.error('Panorama: Fail to execute Panorama API show devices for device: ' + gwMgmtIp)
            return False

        logger.info('show all devices: response: ' + str(response))
        data = response['data'].findall('./result/devices/*')
                    
        for entry in data:
            ip_tag = entry.find('ip-address')
            if ip_tag is None:
                pass
            else:
                ip_addr = ip_tag.text
                if ip_addr == gwMgmtIp:
                    serial_no = entry.attrib.get('name')
                    state= entry.find('connected')
                    if state is not None:
                        connected=state.text
                        logger.info('show dg device state tag value: ' + str(connected))
                        if str(connected) == "yes":
                            logger.error('Device is still in connected state in show dg: ' + gwMgmtIp)
                            conn.close()
                            return False

        if serial_no == "":
            logger.error('Panorama: No registered device found with IP address: ' + gwMgmtIp)
            conn.close()
            return True
            
    cmd_delete_device = "/api/?type=config&action=delete&xpath=/config/mgt-config/devices/entry[@name='%s']&key=%s"%(serial_no, api_key)
    response = send_command(conn, cmd_delete_device)
    if response['result'] == False:
        conn.close()
        logger.error('Panorama: Fail to execute Panorama API delete device for device: ' + gwMgmtIp)
        return False
            
    logger.info('delete unmanaged device: response: ' + str(response))
    cmd_commit = "/api/?type=commit&cmd=<commit></commit>&key="+api_key
    response = send_command(conn, cmd_commit)
                     
    if response['result'] == False:
        conn.close() 
        logger.error('Panorama: Fail to execute Panorama API commit for device: ' + gwMgmtIp)
        return False
            
    job_id=""
    data = response['data'].findall('./result/*')
    for entry in data:
        if entry.tag == 'job':
            job_id = entry.text
        
    if job_id is None:
        conn.close()
        logger.error('Job id could not be found')
        return False

    logger.info('Commit is being done')
    cmd_commit_success  = "/api/?type=op&cmd=<show><jobs><id>"+job_id+"</id></jobs></show>&key="+api_key
    response = send_command(conn, cmd_commit_success)

    if response['result'] == False:
        conn.close()
        logger.error('Panorama: Fail to execute Panorama API show jobs for device: ' + gwMgmtIp)
        return False

    conn.close()

    return True

def get_panorama_version(gcontext, gwMgmtIp, apiKey):
    """
    Retrieve the software version of Panorama.

    :param gcontext: ssl context
    :param gwMgmtIP: The IP address of the FW
    :param apiKey: Api key of the Panorama

    :return: The software version of the Panorama
    :rtype: str 
    """

    sw_ver = None
    if gwMgmtIp is None:
        logger.error('Panorama IP could not be found. Can not interact with the Panorama')
        return None

    logger.info('Retrieve the software version from Panorama with IP: {}'.format(gwMgmtIp))
    pano_cmd="https://"+gwMgmtIp+"/api/?type=op&key="+apiKey+"&cmd=<show><system><info/></system></show>"
    try:
        response = runCommand(gcontext, pano_cmd, gwMgmtIp, apiKey)
        if response is None:
            pan_print('CFG_PANO_GET_SW_VER: Failed to run command: ' + pano_cmd)
            return False
    except Exception as e:
        pan_print("[CFG_PANO_GET_SW_VER]: {}".format(e))
        return False

    resp = et.fromstring(response)
    sw_info = resp.findall(".//sw-version")
    for info in sw_info:
        sw_ver = info.text

    if not sw_ver:
        logger.error("Unable to retrieve the software version from panorama: {} with IP: {}".format(gwMgmtIp))

    return sw_ver


def release_eip(stackname, instanceId):
    """

    :param stackname:
    :param instanceId:
    :return:
    """
    logger.info('Releasing Elastic IPs...')
    try:
        response=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [str(instanceId)]}])
        logger.info(response)
        for i in response['NetworkInterfaces']:
            eniId=i['NetworkInterfaceId']
            try:
                ass=i['PrivateIpAddresses']
                strass=str(ass)
                if strass.find("AssociationId") <= 0:
                    continue

                Attachment=i['Attachment']
                aId=i['PrivateIpAddresses'][0]['Association']['AllocationId']
                logger.info('EIP Attachment ID: ' + aId + ' DeviceIndex: ' +  str(Attachment['DeviceIndex']))
                gwMgmtIp=i['PrivateIpAddresses'][0]['Association']['PublicIp']
                ec2_client.disassociate_address(PublicIp=gwMgmtIp)
                ec2_client.release_address(AllocationId=aId)
            except Exception as e:
                logger.info("[Release EIP Loop each ENI]: {}".format(e))

    except Exception as e:
         logger.error("[Release EIP]: {}".format(e))

    return

def random_string(string_length=10):
    """

    :param string_length:
    :return:
    """
    random = str(uuid.uuid4())
    random = random.replace("-","")
    return random[0:string_length]

def common_alarm_func_del(alarmname):
    """

    :param alarmname:
    :return:
    """
    a1=alarmname + '-high'
    cloudwatch.delete_alarms(AlarmNames=[a1])

    a1=alarmname + '-low'
    cloudwatch.delete_alarms(AlarmNames=[a1])
    return

def remove_s3_bucket(s3_bucket_name):
    """

    :param s3_bucket_name:
    :return:
    """
    logger.info('Removing keys from S3 bootstrap bucket: ' + s3_bucket_name)

    try:
        response=s3.list_objects_v2(Bucket=s3_bucket_name)
        for i in response['Contents']:
            logger.info('Deleting object/key: ' + i['Key'])
            s3.delete_object(Bucket=s3_bucket_name, Key=i['Key'])

        logger.info('Delete S3 bootstrap bucket: ' + s3_bucket_name)
        s3.delete_bucket(Bucket=s3_bucket_name)
    except Exception as e:
         logger.info("[S3 Delete Bucket]: {}".format(e))

    return

def remove_asg_life_cycle(asg_name):
    """

    :param asg_name:
    :return:
    """
    logger.info('Removing Life Cycle Hooks for ASG: ' + asg_name)
    hookname=asg_name + '-life-cycle-launch'
    try:
        asg.delete_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name)
    except Exception as e:
        logger.info("[ASG life-cycle Hook Launch]: {}".format(e))
    hookname=asg_name + '-life-cycle-terminate'
    try:
        asg.delete_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name)
    except Exception as e:
        logger.info("[ASG life-cycle Hook Terminate]: {}".format(e))
    return

def remove_asg_vms(stackname, asg_grp_name, KeyPANWPanorama, delete_stack):
    """

    :param stackname:
    :param :asg_grp_name:
    :param :KeyPANWPanorama:
    :param :delete_stack:
    :return:
    """
    response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_grp_name])
   
    # Initiate removal of all EC2 instances associated to ASG
    found = False
    for i in response['AutoScalingGroups']:
        for ec2i in i['Instances']:
            found = True
            logger.info('Terminating instance: ' + ec2i['InstanceId'] + ' HealthStatus: ' + ec2i['HealthStatus'])
            logger.info(ec2i)

            release_eip(stackname, ec2i['InstanceId'])

            try:
                ec2_client.terminate_instances(InstanceIds=[ec2i['InstanceId']])
            except Exception as e:
                logger.warning("[Terminate Instance in ASG]: {}".format(e))
    
    return found

def common_alarm_func_del(alarmname):
    """

    :param alarmname:
    :return:
    """
    a1=alarmname + '-high'
    logger.info('Removing Alarm Name: ' + alarmname + ' High: ' + a1)
    try:
       cloudwatch.delete_alarms(AlarmNames=[a1])
    except Exception as e:
       a1=alarmname + '-low'

    a1=alarmname + '-low'
    try:
        cloudwatch.delete_alarms(AlarmNames=[a1])
    except Exception as e:
       return

    return

def remove_alarm(asg_name):
    """

    :param asg_name:
    :return:
    """
    alarmname= asg_name + '-cw-cpu'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-as'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-su'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-gpu'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-gpat'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-dpb'
    common_alarm_func_del(alarmname)

    alarmname= asg_name + '-cw-sspu'
    common_alarm_func_del(alarmname)

    return

def scalein_asg(stackname, elbtg, az):
    asg_grp_name=get_asg_name(stackname, elbtg, az)
    try:
        logger.info('Disable metrics collection and Set Min and Desired Capacity to 0 for ASG: ' + asg_grp_name)
        asg.disable_metrics_collection(AutoScalingGroupName=asg_grp_name)
        asg.update_auto_scaling_group(AutoScalingGroupName=asg_grp_name, MinSize=0, DesiredCapacity=0, DefaultCooldown=0)
    except Exception as e:
         logger.info('Could not disable_metrics_collection and Set Min/Desired Capacity to 0 for ASG. Reason below')
         logger.info("[RESPONSE]: {}".format(e))
         return False

    return True


def remove_asg(stackname, elbtg, az, ScalingParameter, KeyPANWPanorama, force, delete_stack):
    """

    :param stackname:
    :param elbtg:
    :param az:
    :param ScalingParameter:
    :param KeyPANWPanorama:
    :param force:
    :param delete_stack:
    :return:
    """
    asg_grp_name=get_asg_name(stackname, elbtg, az)

    logger.info('Remove ASG: ' + asg_grp_name)

    try:
        logger.info('Disable metrics collection and Set Min and Desired Capacity to 0 for ASG: ' + asg_grp_name)
        asg.disable_metrics_collection(AutoScalingGroupName=asg_grp_name)
        scaleout=asg_grp_name + '-scaleout'
        asg.update_auto_scaling_group(AutoScalingGroupName=asg_grp_name, MinSize=0, DesiredCapacity=0)
        #asg.put_scheduled_update_group_action(AutoScalingGroupName=asg_grp_name, ScheduledActionName=scaleout, MinSize=0, DesiredCapacity=0)
    except Exception as e:
         logger.info('Could not disable_metrics_collection and Set Min/Desired Capacity to 0 for ASG. Reason below')
         logger.info("[RESPONSE]: {}".format(e))
         if force == False:
             remove_alarm(asg_grp_name)
             return False

    remove_alarm(asg_grp_name)

    policyname=asg_grp_name + '-scalein'
    logger.info('Deleting ScalePolicyIn :' + policyname)
    try:
        asg.delete_policy(AutoScalingGroupName=asg_grp_name, PolicyName=policyname)
    except Exception as e:
         logger.info("[ScaleIn Policy]: {}".format(e))

    policyname=asg_grp_name + '-scaleout'

    logger.info('Deleting ScalePolicyOut :' + policyname)
    try:
        asg.delete_policy(AutoScalingGroupName=asg_grp_name, PolicyName=policyname)
    except Exception as e:
         logger.info("[ScaleOut Policy]: {}".format(e))

    if remove_asg_vms(stackname, asg_grp_name, KeyPANWPanorama, delete_stack) == True:
        if force == False:
            return False

    response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_grp_name])
    lc_name=""
    try:
        for i in response['AutoScalingGroups']:
            logger.info('i of response[AutoScalingGroups]:')
            logger.info(i)
            lc_name=i['LaunchConfigurationName']
    except Exception as e:
         logger.info("[LC config Name]: {}".format(e))

    if lc_name == "":
        logger.critical('LC for ASG not found: ' + asg_grp_name)
        if force == False:
            return False

    remove_asg_life_cycle(asg_grp_name)

    logger.info('Deleting ASG : ' + asg_grp_name)
    try:
        if force == True:
            asg.delete_auto_scaling_group(AutoScalingGroupName=asg_grp_name, ForceDelete=True)
        else:
            asg.delete_auto_scaling_group(AutoScalingGroupName=asg_grp_name)
    except Exception as e:
         logger.info('Could not remove ASG. Reason below')
         logger.info("[ASG DELETE]: {}".format(e))
         if force == False:
             return False

    logger.info('Deleting Lanuch-configuration for ASG: ' + asg_grp_name)
    try:
        asg.delete_launch_configuration(LaunchConfigurationName=lc_name)
    except Exception as e:
         logger.info('Could not remove ASG. Reason below')
         logger.info("[ASG DELETE LC]: {}".format(e))
         if force == False:
             return False

    return True

def read_s3_object(bucket, key):
    """

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

def get_values_from_init_cfg(contents):
    """
    Retrieve the keys from the init-cfg file
    :param contents:
    :return: dict
    """
    d = {'panorama-server': "", 'tplname': "", 'dgname': "", 'hostname': ""}
    if contents is None:
        return d

    contents=contents.replace('\n', '::')
    list=contents.split("::")
    for i in list:
        if i == "":
            continue

        s=i.split("=")
        if s[0] != "" and s[0] == "panorama-server" and s[1] != "":
            d['panorama-server']=s[1]
        elif s[0] != "" and s[0] == "tplname" and s[1] != "":
            d['tplname']=s[1]
        elif s[0] != "" and s[0] == "dgname" and s[1] != "":
            d['dgname']=s[1]
        elif s[0] != "" and s[0] == "hostname" and s[1] != "":
            d['hostname']=s[1]

    return d


def panorama_remove_serial_and_ip(stackname, r, pdict):
    """

    :param stackname:
    :param r:
    :param pdict:
    :return:
    """
    if pdict is None:
        return

    BootstrapS3Bucket=r['BootstrapS3Bucket']
    c=read_s3_object(BootstrapS3Bucket, "config/init-cfg.txt")
    dict = get_values_from_init_cfg(c)
    logger.info('Panorama: Init CFG bootstrap file Panorama settings is as follows: ')
    logger.info(dict)

    PanoramaIP=dict['panorama-server']
    PanoramaDG=dict['dgname']
    PanoramaTPL=dict['tplname']

    KeyPANWPanorama=r['KeyPANWPanorama']

    if PanoramaIP == "":
        return None

    cnt=len(pdict)
    for i in pdict:
        print(i)

    return

def panorama_save_serial_and_ip(stackname, r):
    """

    :param stackname:
    :param r:
    :return:
    """
    pdict = []

    BootstrapS3Bucket=r['BootstrapS3Bucket']
    c=read_s3_object(BootstrapS3Bucket, "config/init-cfg.txt")
    dict = get_values_from_init_cfg(c)
    logger.info('Panorama: Init CFG bootstrap file Panorama settings is as follows: ')
    logger.info(dict)

    PanoramaIP=dict['panorama-server']
    PanoramaDG=dict['dgname']
    PanoramaTPL=dict['tplname']

    KeyPANWPanorama=r['KeyPANWPanorama']
    elb_name=r['ELBName']

    if PanoramaIP == "":
        return None

    response = elb.describe_instance_health(LoadBalancerName=elb_name)
    for i in response['InstanceStates']:
        instanceId=i['InstanceId']
        iresponse=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [str(instanceId)]}])
        gwMgmtIp=""
        for ir in iresponse['NetworkInterfaces']:
            eniId=ir['NetworkInterfaceId']
            Attachment=ir['Attachment']
            aId=Attachment['AttachmentId']
            if Attachment['DeviceIndex'] == 1:
                gwMgmtIp=ir['PrivateIpAddress']
                break

        if gwMgmtIp is not None:
            serial_no=remove_device(stackname, False, PanoramaIP, KeyPANWPanorama, PanoramaDG, PanoramaTPL, "", gwMgmtIp)
            if serial_no is not None and serial_no != "Done":
                d = {'IP': gwMgmtIp, 'SerialNo': serial_no}
                pdict.append(d)

    print('Items for Panorama are as follows:')
    print(pdict)
    return pdict


def panorama_delete_stack(bsS3Bucket, asg_name, keyPanoramam):
    """

    :param bsS3Bucket:
    :param asg_name:
    :param keyPanoramam:
    :return:
    """
    c=read_s3_object(bsS3Bucket, "config/init-cfg.txt")
    dict = get_values_from_init_cfg(c)
    logger.info('Panorama: Init CFG bootstrap file Panorama settings is as follows: ')
    logger.info(dict)

    PanoramaIP=dict['panorama-server']
    PanoramaDG=dict['dgname']
    PanoramaTPL=dict['tplname']

    if PanoramaIP == "":
        return

    response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
   
    # Initiate removal of all EC2 instances associated to ASG
    found = False
    for i in response['AutoScalingGroups']:
        for ec2i in i['Instances']:
            instanceId=ec2i['InstanceId']
            iresponse=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [str(instanceId)]}])
            gwMgmtIp=""
            for i in iresponse['NetworkInterfaces']:
                eniId=i['NetworkInterfaceId']
                Attachment=i['Attachment']
                aId=Attachment['AttachmentId']
                if Attachment['DeviceIndex'] == 1:
                    gwMgmtIp=i['PrivateIpAddress']
                    break

                if gwMgmtIp == "":
                    logger.error('Firewall IP could not be found. Can not remove it from Panorama')
                    return

            logger.info('Panorama: Removing instance: ' + ec2i['InstanceId'] + ' from Panorama Device. HealthStatus: ' + ec2i['HealthStatus'])
            remove_fw_from_panorama(instanceId, keyPanoramam, gwMgmtIp, PanoramaIP, PanoramaDG, PanoramaTPL)

    return

def delete_asg_stack(stackname, elbtg, bsS3Bucket, ScalingParameter, keyPanoramam, force, subnet_ids):
    """

    :param stackname:
    :param elbtg:
    :param bsS3Bucket:
    :param ScalingParameter:
    :param KeyPANWPanorama:
    :param force:
    :param subnet_ids:
    :return:
    """
    found = False

    azs = getAzs(subnet_ids)
    for i in azs:
        search = get_asg_name(stackname, elbtg, i)
        asg_response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[search])
        print(asg_response)
        if len(asg_response['AutoScalingGroups']) != 0:
            found = True
            logger.info('Delete asg for az: ' + i)
            asg_name = get_asg_name(stackname, elbtg, i)
            try:
                panorama_delete_stack(bsS3Bucket, asg_name, keyPanoramam)
            except Exception as e:
                logger.warning("[Delete Device from Panorama]: {}".format(e))
            remove_asg(stackname, elbtg, i, ScalingParameter, keyPanoramam, force, True)

    return found

#
# Lambda ENIs when deployed in NAT Gateway mode don't go away (because of VPCconfig)
#
def delete_eni_lambda(vpc_sg):
    """

    :param vpc_sg:
    :return:
    """
    print('Look for ENIs in Lambda VPC SG: ' + vpc_sg)
    response=ec2_client.describe_network_interfaces(Filters=[{'Name': "group-id", 'Values': [str(vpc_sg)]}])
    print(response)
    good=True
    for i in response['NetworkInterfaces']:
        eniId=i['NetworkInterfaceId']
        if i['Status'] == "available":
            try:
                ec2_client.delete_network_interface(NetworkInterfaceId=eniId)
            except Exception as e:
                logger.warning("[Lambda delete Eni]: {}".format(e))
                good=False
            continue

        Attachment=i['Attachment']
        aId=Attachment['AttachmentId']
        print('Detaching Eni ID: ' + eniId + ' Desc: ' + i['Description'] + ' IP: ' + i['PrivateIpAddress'] + ' AZ: ' + i['AvailabilityZone'])
        print('Detaching Attachment ID: ' + aId + ' DeviceIndex: ' +  str(Attachment['DeviceIndex']))
        if Attachment['DeviceIndex'] != 0:
            try:
                ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eniId,
                           Attachment={ 'AttachmentId': aId, 'DeleteOnTermination': True})
                ec2_client.detach_network_interface(AttachmentId=aId, Force=True)
                ec2_client.delete_network_interface(NetworkInterfaceId=eniId)
            except Exception as e:
                good=False
                logger.warning("[Lambda detach Eni]: {}".format(e))
                try:
                    ec2_client.delete_network_interface(NetworkInterfaceId=eniId)
                except Exception as e:
                    logger.warning("[Lambda delete Eni in modify/delete]: {}".format(e))

    return good


def delete_asg_stacks(stackname, elbtg, vpc_sg, bsS3Bucket, ScalingParameter, KeyPANWPanorama, subnet_ids):
    """

    :param stackname:
    :param elbtg:
    :param vpc_sg:
    :param bsS3Bucket:
    :param ScalingParameter:
    :param KeyPANWPanorama:
    :param subnet_ids:
    :return:
    """
    force=False
    for i in range(1,90):
        logger.info('Attemping to Delete ASGs Iternation: ' + str(i))
        if i >= 2:
            force=True
            try:
                print('Delete ENI for Lambda with VPC SG if any...')
                delete_eni_lambda(vpc_sg)
            except Exception as e:
                 logger.warning("[delete ENI lambda]: {}".format(e))

        if delete_asg_stack(stackname, elbtg, bsS3Bucket, ScalingParameter, KeyPANWPanorama, force, subnet_ids) == False:
            logger.info('DONE with deleting ASGs')
            break
        time.sleep(1)

    try:
        delete_eni_lambda(vpc_sg)
        for iter in range(1,30):
            print('Delete ENI for Lambda with VPC SG if any: Iteration: ' + str(iter))
            if delete_eni_lambda(vpc_sg) == True:
                break
            time.sleep(1)
    except Exception as e:
        logger.error("[Delete eni lambda]: {}".format(e))
        logger.error("You may have some left-over resource which you will have to delete manually")

    return

def getAccountId(rid):
    """

    :param rid:
    :return:
    """
    try:
        list=rid.split(":")
        return list[4]
    except Exception as e:
        return None

def getRegion(rid):
    """

    :param rid:
    :return:
    """
    try:
        list=rid.split(":")
        return list[3]
    except Exception as e:
        return None

def getSqs(stackname, region, account):
    """

    :param stackname:
    :param region:
    :param account:
    :return:
    """
    try:
        queue_url="https://"+region+".queue.amazonaws.com/"+account+"/"+stackname
        #print('getSqs Queue is: ' + queue_url)
        response=sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
        print(response)
        str=""
        for m in response['Messages']:
            body=m['Body']
            if str == "":
                str=body
            else:
                str=str+":"+body

        print(str)
        return str
    except Exception as e:
         return None
    return None

def getSqsMessages(stackname, account):
    """

    :param stackname:
    :param account:
    :return:
    """
    region=getRegion(account)
    if region is None:
        return None

    id=getAccountId(account)
    msg=getSqs(stackname, region, id)
    return msg

def getDebugLevelFromMsg(msg):
    """

    :param msg:
    :return:
    """
    #print('Message is 1: ' + msg)
    list=msg.split(":")
    for i in list:
        ilist=i.split("=")
        name=ilist[0]
        value=ilist[1]
        if name == "logger":
            return value

def setDebugLevelFromMsg(logger, lvl):
    """

    :param logger:
    :param lvl:
    :return:
    """
    #print('Setting lvl to: ' + lvl)
    if lvl is None:
        logger.setLevel(logging.WARNING)
    elif lvl == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif lvl == "INFO":
        logger.setLevel(logging.INFO)
    elif lvl == "WARNING":
        logger.setLevel(logging.WARNING)
    elif lvl == "ERROR":
        logger.setLevel(logging.ERROR)
    elif lvl == "CRITICAL":
        logger.setLevel(logging.CRITICAL)

def getDebugLevel(stackname, region, account):
    """

    :param stackname:
    :param region:
    :param account:
    :return:
    """
    try:
        queue_url="https://"+region+".queue.amazonaws.com/"+account+"/"+stackname
        #print('Queue Name is : ' + queue_url)
        response=sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
        #print(response)
        for m in response['Messages']:
            body=m['Body']
            list=body.split(":")
            for i in list:
                ilist=i.split("=")
                name=ilist[0]
                value=ilist[1]
                if name == "logger":
                    return value
    except Exception as e:
         return None

def setLoggerLevel(logger, stackname, account):
    """

    :param logger:
    :param stackname:
    :param account:
    :return:
    """
    region=getRegion(account)
    if region is None:
        return None

    id=getAccountId(account)
    lvl=getDebugLevel(stackname, region, id)

    if lvl is None:
        logger.setLevel(logging.WARNING)
    elif lvl == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif lvl == "INFO":
        logger.setLevel(logging.INFO)
    elif lvl == "WARNING":
        logger.setLevel(logging.WARNING)
    elif lvl == "ERROR":
        logger.setLevel(logging.ERROR)
    elif lvl == "CRITICAL":
        logger.setLevel(logging.CRITICAL)

def getScalingValue(msg, ScalingParameter):
    """

    :param msg:
    :param ScalingParameter:
    :return:
    """
    print('getScalingValue()...')
    print(msg)
    try:
        list=msg.split(":")
        for i in list:
           ilist=i.split("=")
           name=ilist[0]
           value=ilist[1]
           print('Name: ' + name + ' Value: ' + value)
           if name == "ActiveSessions" and ScalingParameter == "ActiveSessions":
               return float(value)
           elif name == "DataPlaneCPUUtilization" and ScalingParameter == "DataPlaneCPUUtilization":
               return float(value)
           elif name == "SessionUtilization" and ScalingParameter == "SessionUtilization":
               return float(value)
           elif name == "GPGatewayUtilization" and ScalingParameter == "GPGatewayUtilization":
               return float(value)
           elif name == "DataPlaneBufferUtilization" and ScalingParameter == "DataPlaneBufferUtilization":
               return float(value)
    except Exception as e:
         return None

    return None

def getUntrustIP(instanceid, untrust):
    """

    :param instanceid:
    :param untrust:
    :return:
    """
    logger.info('Getting IP address of Untrust Interface for instance: ' + instanceid)
    ip=""
    found=False
    response=ec2_client.describe_instances(InstanceIds=[instanceid])
    logger.info(response)
    for r in response['Reservations']:
        for i in r['Instances']:
            for s in i['NetworkInterfaces']:
                 if s['SubnetId'] == untrust:
                     found=True
                     ip=s['PrivateIpAddress']
                     break

        if found == True:
            break

    if found == True:
        return ip

    return None

def getAzs(subnet_ids):
    """
    
    :param subnet_ids:
    :return:
    """
    fw_azs = []
    subnetids=subnet_ids.split(',')
    for i in subnetids:
        subnet=ec2.Subnet(i)
        fw_azs.append(subnet.availability_zone)
    return fw_azs

def delete_table(tablename):
    """
    
    :param tablename:
    :return:
    """
    dynamodb = boto3.client('dynamodb')

    try:
        dynamodb.delete_table(TableName=tablename)
        return True
    except Exception as e:
        logger.error("[Delete DynamoDB Table]: {}".format(e))
        return False

def create_firewall_table(stack_name, region):
    """

    :param stack_name:
    :param region:
    :return:
    """

    table_name=get_firewall_table_name(stack_name, region)

    try:
        response = dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'InstanceID',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'InstanceState',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AvailZone',
                    'AttributeType': 'S'
                },
            ],
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'InstanceID',
                    'KeyType': 'HASH'
                },
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'StateIndex',
                    'KeySchema': [
                        {
                            'AttributeName': 'InstanceState',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'AvailZone',
                            'KeyType': 'RANGE'
                        },
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL',
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10
                    }
                },
            ],
            StreamSpecification={
                'StreamEnabled': True,
                'StreamViewType': 'NEW_AND_OLD_IMAGES'
            },
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        #logger.info("Table status: %s", response['TableDescription']['TableStatus'])
        return True

    except Exception as e:
        logger.error("[Create DynamoDB Table]: {}".format(e))
        return False

def create_nlb_table(stack_name, region):
    """

    :param stack_name:
    :param region:
    :return:
    """
    table_name=get_nlb_table_name(stack_name, region)

    try:
        response = dynamodb.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'NLBIp',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'TCPPort',
                    'AttributeType': 'N'
                },
                {
                    'AttributeName': 'NLBState',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'Sort',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'DNSName',
                    'AttributeType': 'S'
                },

            ],
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'NLBIp',
                    'KeyType': 'HASH'
                },
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'SortIndex',
                    'KeySchema': [
                        {
                            'AttributeName': 'Sort',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'TCPPort',
                            'KeyType': 'RANGE'
                        },
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL',
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10
                    }
                },
                {
                    'IndexName': 'StateIndex',
                    'KeySchema': [
                        {
                            'AttributeName': 'NLBState',
                            'KeyType': 'HASH'
                        },
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL',
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10
                    }
                },
                {   
                    'IndexName': 'DNSNameIndex',
                    'KeySchema': [
                        {   
                            'AttributeName': 'DNSName',
                            'KeyType': 'HASH'
                        },
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL',
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10
                    }
                },

            ],
            StreamSpecification={
                'StreamEnabled': True,
                'StreamViewType': 'NEW_AND_OLD_IMAGES'
            },
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        #logger.info("Table status: %s", response['TableDescription']['TableStatus'])
        return True

    except Exception as e:
        logger.exception("[Create DynamoDB Table]: {}".format(e))
        return False

def nlb_table_add_entry(stack_name, region, nlb_ip, port, nlb_state, nlb_zone_name, nlb_subnet_id, total_avail_zones, avail_zone_index, dns_name, nlb_name):
    """

    :param stack_name:
    :param region:
    :param nlb_ip:
    :param port:
    :param nlb_state:
    :param nlb_zone_name:
    :param nlb_subnet_id:
    :param total_avail_zones:
    :param avail_zone_index:
    :param dns_name:
    :param nlb_name:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.put_item(
            Item={
                    'NLBIp': nlb_ip,
                    'TCPPort':int(port),
                    'NLBState': nlb_state,
                    'Sort':'OK',
                    'SubnetId': nlb_subnet_id,
                    'AZName': nlb_zone_name,
                    'TotalAZ': total_avail_zones,
                    'AZIndex': avail_zone_index,
                    'DNSName': dns_name,
                    'NLBName': nlb_name
            }
        )
        return True
    except Exception as e:
        logger.exception("[NLB Table add entry error]: {}".format(e))
        return False

def nlb_table_delete_entry(stack_name, region, nlb_ip):
    """

    :param stack_name:
    :param region:
    :param nlb_ip:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.delete_item(
            Key={
                    'NLBIp': nlb_ip,
            }
        )
        return True
    except Exception as e:
        logger.exception("[NLB Table delete entry error]: {}".format(e))
        return False

def nlb_table_delete_entry_by_dnsname(stack_name, region, dns_name):
    """

    :param stack_name:
    :param region:
    :param dns_name:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='DNSNameIndex',
            KeyConditionExpression=Key('DNSName').eq(dns_name),
            ScanIndexForward=False)
        if response['Count'] != 0:
            for i in response['Items']:
                del_resp = table.delete_item(
                    Key={
                        'NLBIp': i['NLBIp'],
                    }
                )
        return True
    except Exception as e:
        logger.exception("[NLB Table add entry by DNS name error]: {}".format(e))
        return False

def nlb_table_get_entry_by_dnsname(stack_name, region, dns_name):
    """

    :param stack_name:
    :param region:
    :param dns_name:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='DNSNameIndex',
            KeyConditionExpression=Key('DNSName').eq(dns_name),
            ScanIndexForward=False)
        return response
    except Exception as e:
        logger.exception("[NLB Table get entry by DNS name error]: {}".format(e))
        return None

def nlb_table_update_state(stack_name, region, nlb_ip, nlb_state):
    """

    :param stack_name:
    :param region:
    :param nlb_ip:
    :param nlb_state:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.update_item(
            Key={'NLBIp': nlb_ip},
            UpdateExpression="SET NLBState = :s",
            ExpressionAttributeValues={ ':s': nlb_state, }
        )
        return True
    except Exception as e:
        logger.exception("[NLB Table update state error]: {}".format(e))
        return False


def nlb_table_get_from_db(stack_name, region, nlb_ip):
    """

    :param stack_name:
    :param region:
    :param nlb_ip:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.query(
            KeyConditionExpression=Key('NLBIp').eq(nlb_ip)
        )
        return response
    except Exception as e:
        logger.exception("[NLB Table get from db error]: {}".format(e))
        return None

def nlb_table_get_next_avail_port(stack_name, region):
    """

    :param stack_name:
    :param region:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='SortIndex',
            KeyConditionExpression=Key('Sort').eq('OK'),
            ScanIndexForward=False)
        if response['Count'] == 0:
            return start_nlb_port
        if response['Items'][0]['TCPPort'] < num_nlb_port+start_nlb_port-1:
            return response['Items'][0]['TCPPort']+1
        else:
            response=table.query(IndexName='SortIndex',
                KeyConditionExpression=Key('Sort').eq('OK'))
            for i in range(start_nlb_port, num_nlb_port+start_nlb_port-1):
                for k in response['Items']:
                    if i == k['TCPPort']:
                        break
                    if i < k['TCPPort']:
                        return i
    except Exception as e:
        logger.exception("[NLB Table get next avail port error]: {}".format(e))

    return 0

def nlb_table_get_all_in_state(stack_name, region, state):
    """

    :param stack_name:
    :param region:
    :param state:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='StateIndex',
            KeyConditionExpression=Key('NLBState').eq(state),
            ScanIndexForward=False)
        return response
    except Exception as e:
        logger.exception("[NLB Table get all in state error]: {}".format(e))
        return None

def firewall_table_add_instance(stack_name, region, avail_zone, instance_id, state, term_state, asg_name, ip, pip, untrust_ip):
    """

    :param stack_name:
    :param region:
    :param avail_zone:
    :param instance_id:
    :param state:
    :param term_state:
    :param asg_name:
    :param ip:
    :param pip:
    :param untrust_ip:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.put_item(
            Item={
                    'InstanceID': instance_id,
                    'InstanceState': state,
                    'AsgName': asg_name,
                    'AvailZone': avail_zone,
                    'MgmtIP': ip,
                    'MgmtPrivIP': pip,
                    'UntrustIP': untrust_ip,
                    'ListNLBPorts': 'None',
                    'NLBRuleMask0': hex(0),
                    'NLBRuleMask1': hex(0),
                    'NLBRuleMask2': hex(0),
                    'NLBRuleMask3': hex(0),
                    'NLBRuleMask4': hex(0),
                    'NLBRuleMask5': hex(0),
                    'NLBRuleMask6': hex(0),
                    'NLBRuleMask7': hex(0),
                    'NLBRuleMask8': hex(0),
                    'NLBRuleMask9': hex(0),
                    'NLBRuleMask10': hex(0),
                    'NLBRuleMask11': hex(0),
                    'NLBRuleMask12': hex(0),
                    'NLBRuleMask13': hex(0),
                    'NLBRuleMask14': hex(0),
                    'NLBRuleMask15': hex(0),
                    'NLBRuleMask16': hex(0),
                    'NLBRuleMask17': hex(0),
                    'NLBRuleMask18': hex(0),
                    'NLBRuleMask19': hex(0)
            }
        )
        return True
    except Exception as e:
        logger.exception("[FW Table add instance error]: {}".format(e))
        return False


def firewall_table_update_state(stack_name, region, instance_id, state):
    """

    :param stack_name:
    :param region:
    :param instance_id:
    :param state:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.update_item(
            Key={'InstanceID': instance_id},
            UpdateExpression="SET InstanceState = :s",
            ExpressionAttributeValues={ ':s': state, }
        )
        return True
    except Exception as e:
        logger.exception("[FW Table update state error]: {}".format(e))
        return False

def firewall_table_update_rule_mask(stack_name, region, instance_id, rule_mask):
    """

    :param stack_name:
    :param region:
    :param instance_id:
    :param rule_mask:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        ports=''
        for index in range(len(rule_mask)):
            for bit in range(64):
                if (rule_mask[index] & 1<<bit) != 0:
                    ports += str(64*index+bit+start_nlb_port)+','
        if not ports:
            ports = 'None'
        else:
            ports = ports[:-1]
        response = table.update_item(
            Key={'InstanceID': instance_id},
            UpdateExpression='SET NLBRuleMask0=:0, NLBRuleMask1=:1, NLBRuleMask2=:2, NLBRuleMask3=:3, NLBRuleMask4=:4, NLBRuleMask5=:5, NLBRuleMask6=:6,'+
                                'NLBRuleMask7=:7, NLBRuleMask8=:8, NLBRuleMask9=:9, NLBRuleMask10=:10,NLBRuleMask11=:11,NLBRuleMask12=:12, NLBRuleMask13=:13,'+
                                'NLBRuleMask14=:14, NLBRuleMask15=:15,NLBRuleMask16=:16,NLBRuleMask17=:17,NLBRuleMask18=:18,NLBRuleMask19=:19,ListNLBPorts=:20',
            ExpressionAttributeValues={ ':0': hex(rule_mask[0]), ':1': hex(rule_mask[1]), ':2': hex(rule_mask[2]), ':3': hex(rule_mask[3]), ':4': hex(rule_mask[4]),
                                ':5': hex(rule_mask[5]), ':6': hex(rule_mask[6]), ':7': hex(rule_mask[7]), ':8': hex(rule_mask[8]), ':9': hex(rule_mask[9]),
                                ':10': hex(rule_mask[10]), ':11': hex(rule_mask[11]), ':12': hex(rule_mask[12]), ':13': hex(rule_mask[13]), ':14': hex(rule_mask[14]),
                                ':15': hex(rule_mask[15]), ':16': hex(rule_mask[16]), ':17': hex(rule_mask[17]), ':18': hex(rule_mask[18]), ':19': hex(rule_mask[19]),
                                ':20': ports
            }
        )
        return True
    except Exception as e:
        logger.exception("[FW Table update rule mask error]: {}".format(e))
        return False


def firewall_table_get_from_db(stack_name, region, instance_id):
    """

    :param stack_name:
    :param region:
    :param instance_id:
    :return:
    """
    try:
        table_name=get_nlb_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.query(
            KeyConditionExpression=Key('InstanceID').eq(instance_id)
        )
        return response
    except Exception as e:
        logger.exception("[FW Table get from db error]: {}".format(e))
        return None

def firewall_table_delete_instance1(stack_name, region, instance_id):
    """

    :param stack_name:
    :param region:
    :param instance_id:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.query(
            KeyConditionExpression=Key('InstanceID').eq(instance_id)
        )
        if response['Count'] != 0:
            state = response['Items'][0]['InstanceState']
            response = table.delete_item(
                Key={
                        'InstanceID': instance_id,
                        'InstanceState': state
                }
            )
        return True
    except Exception as e:
        logger.exception("[FW Table detele instance error]: {}".format(e))
        return False

def firewall_table_delete_instance(stack_name, region, instance_id):
    """

    :param stack_name:
    :param region:
    :param instance_id:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response = table.delete_item(
            Key={
                    'InstanceID': instance_id,
            }
        )
        return True
    except Exception as e:
        logger.exception("[FW Table delete instance error]: {}".format(e))
        return False

def firewall_table_get_all_in_az_state(stack_name, region, state, avail_zone):
    """

    :param stack_name:
    :param region:
    :param state:
    :param avail_zone:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='StateIndex',
            KeyConditionExpression=Key('InstanceState').eq(state) & Key('AvailZone').eq(avail_zone),
            ScanIndexForward=False)
        return response
    except Exception as e:
        logger.exception("[FW Table get all in az state error]: {}".format(e))
        return None

def firewall_table_get_all_in_state(stack_name, region, state):
    """
        
    :param stack_name:
    :param region:
    :param state:
    :return:
    """
    try:
        table_name=get_firewall_table_name(stack_name, region)
        table=dynamodb.Table(table_name)
        response=table.query(IndexName='StateIndex',
            KeyConditionExpression=Key('InstanceState').eq(state),
            ScanIndexForward=False)
        return response
    except Exception as e:
        logger.exception("[FW Table get all in state error]: {}".format(e))
        return None

remote=0

def pan_print(s):
    """
        
    :param s:
    :return:
    """
    if remote > 0:
        logger.info(s)
        return
    print(s)
    return

def getChassisReady(response):
    """

    :param response:
    :return:
    """
    s1=response.replace('\n',"")
    s1=s1.replace(" ","")
    if s1.find("<![CDATA[no]]") > 0:
        return False
    if s1.find("<![CDATA[yes]]>") > 0:
        return True
    return False

def getJobStatus(response):
    """

    :param response:
    :return:
    """
    s1=response.replace("/","")
    index=s1.find("<status>")
    list=s1.split("<status>")
    return list[1]

def getJobResult(response):
    """

    :param response:
    :return:
    """
    s1=response.replace("/","")
    index=s1.find("<result>")
    list=s1.split("<result>")
    return list[2]

def getJobTfin(response):
    """

    :param response:
    :return:
    """
    s1=response.replace("/","")
    index=s1.find("<tfin>")
    list=s1.split("<tfin>")
    return list[1]

def getJobProgress(response):
    """

    :param response:
    :return:
    """
    s1=response.replace("/","")
    index=s1.find("<progress>")
    list=s1.split("<progress>")
    return list[1]

def is_firewall_ready(gcontext, gwMgmtIp, api_key):
    """

    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :return:
    """
    pan_print('Checking whether Chassis is ready or not')
    cmd="<show><chassis-ready/></show>"
    fw_cmd= "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Failed to run command: ' + fw_cmd)
            return False
        status=getChassisReady(response)
        if status == True:
            pan_print('Chassis is in ready state')
            return True
        else:
            pan_print('Chassis is not ready yet')

        pan_print("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[AutoCommit RESPONSE]: {}".format(e))

    return False

def is_firewall_auto_commit_done(gcontext, gwMgmtIp, api_key):
    """
    
    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :return:
    """
    pan_print('Checking whether AutoCommit is done or not')
    cmd="<show><jobs><id>1</id></jobs></show>"
    fw_cmd= "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Failed to run command: ' + fw_cmd)
            return False
        status=getJobStatus(response)
        if status == "FIN":
            pan_print('AutoCommit is Done')
            pan_print('AutoCommit job status is : ' + getJobStatus(response))
            pan_print('AutoCommit job result is : ' + getJobResult(response))
            pan_print('AutoCommit job tfin is : ' + getJobTfin(response))
            pan_print('AutoCommit job Progress is : ' + getJobProgress(response))
            return True
        else:
            pan_print('AutoCommit is not done or over or failed')
            pan_print('AutoCommit job status is : ' + getJobStatus(response))
            pan_print('AutoCommit job result is : ' + getJobResult(response))
            pan_print('AutoCommit job tfin is : ' + getJobTfin(response))
            pan_print('AutoCommit job Progress is : ' + getJobProgress(response))

        pan_print("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[AutoCommit RESPONSE]: {}".format(e))

    return False

def config_firewall_init_setting(gcontext, gwMgmtIp, api_key, asg_name, untrust_ip):
    """
    
    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :param asg_name:
    :return:
    """
    pan_print('Set firewall cloudwatch asg name')
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/deviceconfig/setting/aws-cloudwatch&element=<name>"+asg_name+"</name>"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_CW_NAME: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_CW_NAME RESPONSE]: {}".format(e))
         return False

    pan_print('Set firewall untrust address object')

    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/address&element=<entry%20name='AWS-NAT-UNTRUST'><description>UNTRUST-IP-address</description><ip-netmask>"+untrust_ip+"</ip-netmask></entry>"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_UNTRUST_ADDR_OBJ: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_UNTRUST_ADDR_OBJ RESPONSE]: {}".format(e))
         return False

    fw_cmd="https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_CW_COMMIT: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[Commit RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_CW_COMMIT RESPONSE]: {}".format(e))
         return False

    return True

def config_firewall_add_nat_rule(gcontext, gwMgmtIp, api_key, untrust_ip, nlb_port, nlb_ip, static_route, default_gw, commit):
    """

    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :param untrust_ip:
    :param nlb_port:
    :param nlb_ip:
    :param static_route:
    :param default_gw:
    :param commit:
    :return:
    """
    pan_print('Add firewall NAT rule port: {} ip: {}'.format(nlb_port, nlb_ip))
    # Add service tcp/port for NAT
    service_name="'"+'tcp'+str(nlb_port)+"'"
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/service&element=<entry%20name="+service_name+"><protocol><tcp><source-port>1-65535</source-port><port>"+str(nlb_port)+"</port></tcp></protocol></entry>"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_ADD_SERVICE: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_SERVICE RESPONSE]: {}".format(e))
         return False

    # Add NAT rule
    nat_rule_name="'"+'port'+str(nlb_port)+"'"
    service_name='tcp'+str(nlb_port)
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/rulebase/nat/rules&element=<entry%20name="+nat_rule_name+"><to><member>Untrust</member></to><destination-translation><translated-port>80</translated-port><translated-address>"+nlb_ip+"</translated-address></destination-translation><from><member>Untrust</member></from><source><member>any</member></source><destination><member>"+untrust_ip+"</member></destination><service>"+service_name+"</service><to-interface>ethernet1/1</to-interface><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface></interface-address></dynamic-ip-and-port></source-translation></entry>"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_ADD_NAT: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_ADD_NAT RESPONSE]: {}".format(e))
         return False

    if static_route:
        fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/network/virtual-router/entry[@name='default']/routing-table/ip/static-route&element=<entry%20name="+nat_rule_name+"><nexthop><ip-address>"+default_gw+"</ip-address></nexthop><interface>ethernet1/2</interface><destination>"+nlb_ip+"/32</destination></entry>"
        try:
            response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
            if response is None:
                pan_print('CFG_FW_ADD_ROUTE: Failed to run command: ' + fw_cmd)
                return False
        except Exception as e:
             #logger.error("[NAT Address RESPONSE]: {}".format(e))
             pan_print("[CFG_FW_ADD_ROUTE RESPONSE]: {}".format(e))
             return False

    if commit:
        fw_cmd="https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
        try:
            response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
            if response is None:
                pan_print('CFG_FW_NAT_COMMIT: Failed to run command: ' + fw_cmd)
                return False
        except Exception as e:
            #logger.error("[Commit RESPONSE]: {}".format(e))
            pan_print("[CFG_FW_NAT_COMMIT RESPONSE]: {}".format(e))
            return False

    return True

def config_firewall_delete_nat_rule(gcontext, gwMgmtIp, api_key,  nlb_port, static_route, commit):
    """

    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :param nlb_port:
    :param static_route:
    :param commit:
    :return:
    """
    pan_print('Delete firewall NAT rule port: {}'.format(nlb_port))
    nat_rule_name="'"+'port'+str(nlb_port)+"'"
    # Delete route
    if static_route:
        fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=delete&key="+api_key+"&xpath=/config/devices/entry/network/virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name="+nat_rule_name+"]"
        try:
            response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
            if response is None:
                pan_print('CFG_FW_DEL_ROUTE: Failed to run command: ' + fw_cmd)
                return False
        except Exception as e:
             #logger.error("[NAT Address RESPONSE]: {}".format(e))
             pan_print("[CFG_FW_DEL_ROUTE RESPONSE]: {}".format(e))
             return False

    # Delete NAT rule
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=delete&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/rulebase/nat/rules/entry[@name="+nat_rule_name+"]"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_DEL_NAT: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_DEL_NAT RESPONSE]: {}".format(e))
         return False

    # Delete service tcp/port for NAT
    service_name="'"+'tcp'+str(nlb_port)+"'"
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=delete&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/service/entry[@name="+service_name+"]"

    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_DEL_SERVICE: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[CFG_DEL_SERVICE RESPONSE]: {}".format(e))
         return False

    if commit:
        fw_cmd="https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
        try:
            response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
            if response is None:
                pan_print('CFG_FW_NAT_COMMIT: Failed to run command: ' + fw_cmd)
                return False
        except Exception as e:
            #logger.error("[Commit RESPONSE]: {}".format(e))
            pan_print("[CFG_FW_NAT_COMMIT RESPONSE]: {}".format(e))
            return False

    return True

def config_firewall_commit(gcontext, gwMgmtIp, api_key):
    """

    :param gcontext:
    :param gwMgmtIp:
    :param api_key:
    :return:
    """
    pan_print('Commit configuration on firewall: {}'.format(gwMgmtIp))

    fw_cmd="https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('CFG_FW_CW_COMMIT: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[Commit RESPONSE]: {}".format(e))
         pan_print("[CFG_FW_CW_COMMIT RESPONSE]: {}".format(e))
         return False

    return True

