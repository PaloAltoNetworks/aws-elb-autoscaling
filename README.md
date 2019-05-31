# Caution: These repositories contain default password information and should be used for Proof of Concept purposes only. If you wish to use this template in a production environment it is your responsibility to change the default passwords.  

# Auto Scaling VM-Series firewalls in AWS to protect Internet facing applications.

This repository provides AWS CloudFormation Templates (CFT) and related Lambda functions to enable auto scaling of VM-Series next generation firewalls in AWS. They use AWS elastic load balancing (ELB) services such as classic ELB, ALB and NLB to provide elastic, on-demand, scale out of security to match increased demand for the applications protected by VM-Series. It uses a common design pattern of a load balancer sandwich to protect Internet-facing applications. VM-Series provides visibility and protection of the inbound traffic. This allows network and security administrators to use the same automation tools and Panorama to centrally manage their security in the cloud, as their on-premises environments. Review the support policy section of each folder to understand how to get help. 

To protect outbound traffic flows, hybrid architectures that connect AWS to on-premises, and east-west flows between VPCs, refer to the Transit VPC options listed http://live.paloaltonetworks.com/cloudtemplate

## History
### Version 1.0 - Mar 2017
### Version 2.0 - Jan 2018
### Version 2.0.1 - Nov 2018, bug fixes
### Version 2.1-CS - Jan 2019, Deprecated and removed
### Version 2.1 - May 2019 Fully GA
* Support for separating the frontend firewall VPC from the backend application VPC using AWS PrivateLink or VPC peering
* Support for specific combinations of external and internal load balancing

