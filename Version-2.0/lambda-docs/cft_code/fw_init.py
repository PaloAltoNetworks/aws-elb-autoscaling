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
import uuid
import sys
import ssl

sys.path.append('lib/')
import pan.asglib as lib

mgmt=""
untrust=""
trust=""
sgm=""
sgu=""
sgt=""
sgv=""
PanS3KeyTpl=""
PanS3BucketTpl=""
KeyPANWFirewall=""
KeyPANWPanorama=""
ScalingParameter=""
Namespace=""
asg_name=""
SubnetIDNATGW=""
#SubnetIDLambda=""
#elb_name=""
Arn=""

asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
cloudwatch = boto3.client('cloudwatch')

valid_panfw_productcode_byol = {
    "6njl1pau431dv1qxipg63mvah": "VMLIC_BYOL",
    #AWS IC product codes
    "3bgub3avj7bew2l8odml3cxdx": "VMLIC_IC_BYOL",
}


def get_lambda_cloud_watch_func_name(stackname, instanceId):
    name = asg_name + '-cwm-' + str(instanceId)
    return name[-63:len(name)]
    
def get_event_rule_name(stackname, instanceId):
    name = stackname + '-cw-event-rule-' + str(instanceId)
    return name[-63:len(name)]
    
def get_statement_id(stackname, instanceId):
    name = stackname + '-cw-statementid-' + str(instanceId)
    return name[-63:len(name)]
    
def get_target_id_name(stackname, instanceId):
    name = stackname + '-lmda-target-id' + str(instanceId)
    return name[-63:len(name)]
    
def random_string(string_length=10):
    random = str(uuid.uuid4()) 
    random = random.replace("-","") 
    return random[0:string_length]

def remove_eni_in_subnet(subnet):
    response=ec2_client.describe_network_interfaces(Filters=[{'Name': "subnet-id", 'Values': [str(subnet)]}])
    for i in response['NetworkInterfaces']:
        if i['Status'] == "available":
            logger.info('Removing Network Interfaces in Available state for subnetid : ' + subnet)
            eniId=i['NetworkInterfaceId']
            logger.info('Removing Eni ID: ' + eniId + ' Desc: ' + i['Description'] + ' IP: ' + i['PrivateIpAddress'] + ' AZ: ' + i['AvailabilityZone'])
            try:
                ec2_client.delete_network_interface(NetworkInterfaceId=eniId)
            except Exception as e:
                logger.warning("[delete Eni for subnet]: {}".format(e))
        
    return

def remove_eni(message):
    instanceId = message['EC2InstanceId']
    logger.info('Removing Network Interfaces for instanceId: ' + instanceId)
    
    # Detach all the ENIs first
    response=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [str(instanceId)]}])
    cnt = 0
    eni_ids=[]
    for i in response['NetworkInterfaces']:
        eniId=i['NetworkInterfaceId']
        Attachment=i['Attachment']
        aId=Attachment['AttachmentId']
        logger.info('Detaching Eni ID: ' + eniId + ' Desc: ' + i['Description'] + ' IP: ' + i['PrivateIpAddress'] + ' AZ: ' + i['AvailabilityZone'])
        logger.info('Detaching Attachment ID: ' + aId + ' DeviceIndex: ' +  str(Attachment['DeviceIndex']))
        if Attachment['DeviceIndex'] != 0:
            try:
                ec2_client.detach_network_interface(AttachmentId=aId)
                cnt = cnt + 1
                eni_ids.append(str(eniId))
            except Exception as e:
                logger.warning("[detach Eni]: {}".format(e))
                try:
                    ec2_client.delete_network_interface(NetworkInterfaceId=eniId)
                except Exception as e:
                    logger.warning("[delete Eni]: {}".format(e))

    if cnt == 0:
        logger.warning('No more ENIs for delete. Strange though')
        return
    
    logger.info('Delete ENIs PANW InstanceID: ' + str(instanceId) + ' ENI cnt: ' + str(cnt))
    logger.info('Delete ENIs: ' + str(eni_ids))

    # Now delete ENIs if they are in 'available' state
    fcnt = 0
    for timeout in range(0,25):
        if fcnt == cnt:
            logger.info('Finally Done with deleting all ENIs')
            return
        
        response=ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=eni_ids,
                Filters=[{'Name': 'status', 'Values': ['available']}])
        
        for i in response['NetworkInterfaces']:
            id=i['NetworkInterfaceId']
            fcnt = fcnt + 1
            try:
                ec2_client.delete_network_interface(NetworkInterfaceId=id)
            except Exception as e:
                logger.error("[delete Eni after detach]: {}".format(e))
                
        time.sleep(5)
        
    response=ec2_client.describe_network_interfaces(NetworkInterfaceIds=eni_ids)
    for i in response['NetworkInterfaces']:
        logger.error('Timed out waiting for detach ENI. Final cnt: ' + str(fcnt) + ' vs ' + str(cnt))
        logger.error(i)

    logger.error('Return from remove_eni due to detach issue')                
    return

def count_eni(msg, instanceId):
    response=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [str(instanceId)]}])
    #logger.info(response)
    cnt = 0
    for i in response['NetworkInterfaces']:
        cnt =  cnt + 1
    logger.info(msg + ' PANW InstanceID: ' + str(instanceId) + ' ENI cnt: ' + str(cnt))
    return cnt

def associateAddress(AllocId, nifId):
    logger.info('EIP Associate AllocId: ' + str(AllocId) + ' ENI Id: ' + str(nifId))
    try:
        ec2_client.associate_address(AllocationId=AllocId, NetworkInterfaceId=nifId)
    except Exception as e:
        logger.error("[associateAddress failed]: {}".format(e))
        return False
    else:
        logger.info("Associated EIP")
        return True

def getUnassociatedAddress(eip_list):
    fail = {'PublicIp': 'None', 'Domain': 'vpc', 'AllocationId': 'None'}
    logger.info("Trying to find and eip that is not associated")
    logger.info(eip_list)
    for eip_iter in eip_list['Addresses']:
        #is the public ip address associated with an instance id, if so don't use it
        logger.info('eip_iter is as follows:')
        logger.info(eip_iter)
        if "InstanceId" not in eip_iter:
            if "AllocationId" not in eip_iter:
                address = eip_iter['PublicIp']
                if address:
                    return  eip_iter
    return None

def get_eip(mgmt_eniId, mgmt_instanceId):
    fail = {'PublicIp': 'None', 'Domain': 'vpc', 'AllocationId': 'None'}
    dict = ec2_client.describe_addresses()
    logger.info(dict)

    found=False
    for i in dict['Addresses']:
        found=True
        break

    if found == False:
        try:
            response = ec2_client.allocate_address(Domain='vpc')
            return response
        except Exception as e:
            logger.error("[alloate_eip_address failed]: {}".format(e))
            return None

    response = getUnassociatedAddress(dict)
    if response is None:
        try:
            response = ec2_client.allocate_address(Domain='vpc')
            return response
        except Exception as e:
            logger.error("[alloate_eip_address failed]: {}".format(e))
            return None
    return response

def handle_instance_termination(fwApiKey, instanceId, delicenseKey, fwMgmtIp):
    """
    Execute the sequence to deactivate the Firewall in the case of BYOL.

    @param fwAPiKey: Api key to interact with the firewall
    @type ```str```
    @param instance_id The id of the instance
    @type ```str```
    @type ```str```
    @param delicenseKey
    @type ```str```

    @return Status of the firewall license deactivation workflow
    @rtype bool
    """


    fwcontext = lib.get_ssl_context()

    serial_no = lib.get_device_serial_no(fwcontext, instanceId, fwMgmtIp, fwApiKey)
    if not serial_no:
        logger.error('Unable to retrieve the serial no for device with IP: {}'.format(fwMgmtIp))
        return False

    logger.info('The serial number retrieved from device with IP: {} is {}'.format(fwMgmtIp, serial_no))

    try:
        instance_info = ec2_client.describe_instance_attribute(
            Attribute='productCodes',
            InstanceId=instanceId,
        )
    except Exception as e:
        logger.info("Exception occured while retrieving instance ID information: {}".format(e))

    logger.info('describe_instance_attribute:response: {}'.format(instance_info))
    valid_byol = False
    for code in instance_info['ProductCodes']:
        product_code_id = code.get("ProductCodeId", None)
        if product_code_id in valid_panfw_productcode_byol.keys():
            valid_byol = True
            break

    if valid_byol:
        if delicenseKey:
            try:
                for retry in range (1, 10):
                    logger.info('Set the deactivation API key, retry {} time'.format(retry))
                    ret = lib.set_deactivate_api_key(fwcontext, instanceId, fwMgmtIp, fwApiKey, delicenseKey)
                    if not ret:
                        logger.error('Failed to set the deactivation API key for device: {} with IP: {}'.format(instanceId, fwMgmtIp))

                    logger.info('Identified the fw license as BYOL. The fw will be de-licensed now.')
                    ret = lib.deactivate_fw_license(fwcontext, instanceId, fwMgmtIp, fwApiKey)
                    if not ret:
                        logger.error('Failed to deactivate the license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                    else:
                        logger.info('Successfully deactivated license for device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                        break
            except Exception as e:
                logger.exception("Exception occurred during deactivate license for device: {} with IP: {}. Error:  {}".format(instanceId, fwMgmtIp, e))
        else:
            logger.warning('Key to de-activate the FW was not specified. Cannot de-activate license without a valid key.')

        try:
            time.sleep(30)
            logger.info('Attempting to shutdown the fw device: {} with IP: {}'.format(instanceId, fwMgmtIp))
            ret = lib.shutdown_fw_device(fwcontext, instanceId, fwMgmtIp, fwApiKey)
            if not ret:
                logger.error('Error encountered while shutting down the firewall device: {} with IP: {}'.format(instanceId, fwMgmtIp))
                return False
            logger.info("Firewall device: {} with IP: {} successfully shutdown.".format(instanceId, fwMgmtIp))
        except Exception as e:
            logger.exception('Exeption shutting down firewall device: {} with IP:{} Error: {}'.format(instanceId, fwMgmtIp, e))
    else:
        logger.info("This firewall device does not have a BYOL license.")
    
    logger.info('Termination sequence completed.')    
    return True

def get_stack_params(queue_url):

    for retry in xrange(0, 5):
        time.sleep(5)
        try:
            logger.info('Calling to retrieve message from the queue..: {}'.format(queue_url))
            message_data_str, ts, rh = lib.get_from_sqs_queue(queue_url, 10, 5)
            if not message_data_str:
                logger.error('Unable to retrieve message from the queue. Operation will be retried')
                continue
            else:
                message_data = json.loads(message_data_str)
                logger.info("Data from sqs: {}".format(message_data_str))
                return message_data
        except Exception as e:
            logger.exception("Exception occurred while retrieving data from sqs: {}".format(e))
    return None


def lambda_handler(event, context):
    global asg_name
    global PanS3KeyTpl
    global PanS3BucketTpl
    global mgmt
    global untrust
    global trust
    global sgm
    global sgu
    global sgt
    global sgv
    global KeyPANWPanorama
    global KeyPANWFirewall
    global ScalingParameter
    global Namespace
    global SubnetIDNATGW
    global logger
    global Arn

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info('Message in the SNS is:')
    logger.info(message)

    #logger.info('got event{}'.format(event))
    
    strevent=str(event)
    
    if strevent.find("autoscaling:TEST_NOTIFICATION") >= 0:
        logger.info('Testing Notification SNS Message ')
        logger.info('ASG name is: ' + message['AutoScalingGroupName'])
        return 
    
    
    asg_name=message['AutoScalingGroupName']
    instanceId = message['EC2InstanceId']
    logger.info('instanceId: ' + instanceId)
    metadata = json.loads(message['NotificationMetadata'])
    #logger.error('Metadata is: ')
    #logger.error(metadata)

    mgmt=metadata['MGMT']
    untrust=metadata['UNTRUST']
    trust=metadata['TRUST']
    
    KeyPANWFirewall=metadata['KeyPANWFirewall']
    KeyPANWPanorama=metadata['KeyPANWPanorama']

    KeyDeLicense=metadata['KeyDeLicense']
    LambdaENIQueue=metadata['LambdaENIQueue']
    avail_zone=metadata['AvailZone']

    Arn=event['Records'][0]['EventSubscriptionArn']

    logger.info('LifecycleHookName1: ' + message['LifecycleHookName'])

    logger.info('Retrieve metadata from the queue..: {}'.format(LambdaENIQueue))
    message_data = get_stack_params(LambdaENIQueue)
    if not message_data:
        logger.warning('Unable to successfully complete asg life cycle event.: {}'.format(message))
        done('true', context, message);
        return

    debug=message_data['Debug']

    if debug == 'Yes':
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    sgm = message_data['SGM']
    sgu = message_data['SGU']
    sgt = message_data['SGT']
    sgv = message_data['SGV']
    stackname = message_data['StackName']
    region = message_data['Region']
    IamLambda = message_data['IamLambda']
    PanS3BucketTpl = message_data['LambdaS3Bucket']
    PanS3KeyTpl = message_data['PanS3KeyTpl']
    ScalingParameter = message_data['ScalingParameter']
    SubnetIDNATGW = message_data['SubnetIDNATGW']
    PIP = message_data['PIP']
    PDG = message_data['PDG']
    PTPL = message_data['PTPL']
    Hostname = message_data['Hostname']
    cnt = count_eni("INIT", instanceId)


    if strevent.find("autoscaling:EC2_INSTANCE_LAUNCHING") >= 0:
        logger.info('PANW EC2 Firewall Instance is launching')
        
    if strevent.find("autoscaling:EC2_INSTANCE_TERMINATING") >= 0:
        logger.info('PANW EC2 Firewall Instance is terminating')
        #remove_eni(message)
        #Remove instance from firewall db
        logger.info('Remove instance %s from firewall table', str(instanceId))
        lib.firewall_table_delete_instance(stackname, region, instanceId)

        fwMgmtIp = lib.retrieve_fw_ip(instanceId)

        if not fwMgmtIp:
            logger.error('Retrieve firewall mgmt IP failed. Unable to deactivate firewall license')
            if PIP != "":
                logger.error("Unable to deregister firewall from Panorama")
            return

        try: 
            handle_instance_termination(KeyPANWFirewall, instanceId, KeyDeLicense, fwMgmtIp)
        except Exception as e:
            logger.exception('Handling instance termination: {}'.format(e))

        logger.info('Handle the cleanup of the ENI')
        count_eni("REMOVE", instanceId)

        if PIP != "":
            logger.info('Panorama: Firewall IP will be removed by fw_init Lambda: ' + str(instanceId) + ' from Panorama IP: ' + str(PIP))
            time.sleep(60)

            try:
                lib.remove_fw_from_panorama(instanceId, KeyPANWPanorama, fwMgmtIp, PIP, PDG, PTPL)
            except Exception as e:
                logger.error("[Deregister firewall from Panorama failed in fw_init]: {}".format(e))

        done('true', context, message);
        return

    logger.info('Mgmt Subnet: ' + mgmt + ' Security-Group: ' + sgm)
    logger.info('Untrust Subnet: ' + untrust + ' Security-Group: ' + sgu)
    logger.info('Trust Subnet: ' + trust + ' Security-Group: ' + sgt)
    
    #CreateEni for mgmt interface
    nif = ""
    err = createEni(mgmt, sgm, 1)
    if err == 'false':
        logger.info("Error: Eni creation failed\n")
        abandon(context, message)
        return

    #Wait for the ENI to be 'available'
    mgmt_eniId=eniId
    err = waitEniReady(eniId)
    if err == 'false':
        logger.info("ERROR: Failure waiting for ENI to be ready");
        abandon(context, message)
        return

    #Attach the network interface to the instance
    mgmt_instanceId = instanceId
    mgmt_eniId=eniId
    err = attachEni(instanceId, eniId, 1)
    if err == 'false':
        logger.info("ERROR: Failure attaching ENI to instance for eth1");
        removeEni(eniId)
        abandon(context, message)
        return
    else:
        logger.info("INFO: Success! Attached ENI to instance for eth1");

    #CreateEni for Trust Subnet
    nif = ""
    err = createEni(trust, sgt, 2)
    if err == 'false':
        logger.info("Error: Eni creation failed\n")

    logger.info(nif)
    #Wait for the ENI to be 'available'
    err = waitEniReady(eniId)
    if err == 'false':
        logger.info("ERROR: Failure waiting for ENI to be ready");
        abandon(context, message)
        return

    #Attach the network interface to the instance
    err = attachEni(instanceId, eniId, 2)
    if err == 'false':
        logger.info("ERROR: Failure attaching ENI to instance for eth2");
        removeEni(eniId)
        abandon(context, message)
        return
    else:
        logger.info("INFO: Success! Attached ENI to instance for eth2");

    count_eni("ADD", instanceId)

    # Get mgmt IP
    try:
        response=ec2_client.describe_network_interfaces(NetworkInterfaceIds=[mgmt_eniId])
    except Exception as e:
        logger.error("[Describe NI failed in Create CW]: {}".format(e))

    ip="NO_IP"
    pip="NO_IP"
    try:
        for i in response['NetworkInterfaces']:
            ip=i['PrivateIpAddress']
            pip=i['PrivateIpAddress']
    except Exception as e:
        logger.error("[FW IP Address in Create CW]: {}".format(e))
        ip="NO_PrivateIP_ADDR"

    if ip.find("NO_") >= 0:
        logger.error('We failed to get either EIP or Private IP for instance: ' + str(instanceId) + ' IP: ' + ip)
        logger.error('We will not proceed further with this Instance: ' + str(instanceId))

    # Add instance to firewall table
    untrust_ip=lib.getUntrustIP(instanceId, untrust) 
    logger.info("Add instance %s to firewall table", str(instanceId))
    lib.firewall_table_add_instance(stackname, region, avail_zone, instanceId, 'INIT', 'INIT', asg_name, ip, pip, untrust_ip)
  
    done('true', context, message);
    return

def abandon(context, asg_message):
    result = "ABANDON";

    #call autoscaling
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName = asg_message['AutoScalingGroupName'],
            LifecycleHookName = asg_message['LifecycleHookName'],
            LifecycleActionToken = asg_message['LifecycleActionToken'],
            LifecycleActionResult = result)
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))

def done(success, context, asg_message):
    result = "CONTINUE";

    #call autoscaling
    try:
        asg.complete_lifecycle_action(
            AutoScalingGroupName = asg_message['AutoScalingGroupName'],
            LifecycleHookName = asg_message['LifecycleHookName'],
            LifecycleActionToken = asg_message['LifecycleActionToken'],
            LifecycleActionResult = result)
    except Exception as e:
        logger.error("[complete_lifecycle_action]: {}".format(e))
        return False

    return True
        
#Create a network interface, pass the Interface ID to callback
def createEni(subnetId, securityGroups, index):
    global nif
    global eniId
    
    desc=asg_name + '-eth' + str(index)
    logger.info('Creating ENI for Subnet: ' + subnetId)
    logger.info('Creating ENI for SG: ' + securityGroups)
    try:
        nif = ec2.create_network_interface(SubnetId=subnetId, Groups=[securityGroups], Description=desc)
    except botocore.exceptions.ClientError as error:
        logger.info("ERROR: ENI creation failed.\n");
        logger.info(error)
        return 'false'
    else:
        logger.info("INFO: ENI Created.\n");
        try:
            nif.modify_attribute(SourceDestCheck={'Value': False})
            nif.reload()
            response = nif.describe_attribute(Attribute='description')
            eniId = response['NetworkInterfaceId']
            logger.info('Eni-id for newly created ENI is: ' + str(eniId))
        except Exception as e:
            logger.error("[createEni modify attr, reload failed]: {}".format(e))
            logger.error('Deleting previously created ENI');
            logger.error(nif)
            logger.error('Nif id is: ' + str(nif.id))
            removeEni(nif.id)
            return 'false'
            
        return 'true'

def removeEni(eniId1):
    try:
        ec2_client.delete_network_interface(NetworkInterfaceId=eniId1)
    except Exception as e:
        logger.error("[removeEni]: {}".format(e))
        
    return

def waitEniReady(eniId):
    try:
        waiter = ec2_client.get_waiter('network_interface_available')
        waiter.wait(NetworkInterfaceIds=[eniId], Filters= [{'Name' : 'status', 'Values': ['available']}])
    except botocore.exceptions.ClientError:
        logger.info("ERROR: ENI failed to reach desired state\n")
        return 'false'
    else:
       return 'true'


def attachEni(ec2Id, eniId, index):
    try:
        response=ec2_client.attach_network_interface(NetworkInterfaceId=eniId, InstanceId=ec2Id,DeviceIndex=index)
        aid=response['AttachmentId']
        ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eniId,
                Attachment={ 'AttachmentId': aid, 'DeleteOnTermination': True})
    except Exception as e:
        logger.error("[attach/modify Eni]: {}".format(e))
        return 'false'

    else:
        logger.info('INFO: ENI attached EC2 instance for index: ' + str(index))
        return 'true'
