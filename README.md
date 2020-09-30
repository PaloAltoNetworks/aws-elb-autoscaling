# Auto Scaling VM-Series firewalls in AWS to protect Internet facing applications.

This repository provides AWS CloudFormation Templates (CFT) and related Lambda functions to enable auto scaling of VM-Series next generation firewalls in AWS. They use AWS elastic load balancing (ELB) services such as classic ELB, ALB and NLB to provide elastic, on-demand, scale out of security to match increased demand for the applications protected by VM-Series. It uses a common design pattern of a load balancer sandwich to protect Internet-facing applications. VM-Series provides visibility and protection of the inbound traffic. This allows network and security administrators to use the same automation tools and Panorama to centrally manage their security in the cloud, as their on-premises environments. Review the support policy section of each folder to understand how to get help. 

To protect outbound traffic flows, hybrid architectures that connect AWS to on-premises, and east-west flows between VPCs, refer to the Transit VPC options listed http://live.paloaltonetworks.com/cloudtemplate

## History
### Version 1.1 - Mar 2017 Deprecated
### Version 1.2 - June 2019 Bug Fixes
### Version 2.0 - Jan 2018 Initial Release
### Version 2.0.1 - Nov 2018, Bug Fixes
### Version 2.1-CS - Jan 2019, Deprecated and removed
### Version 2.1 - May 2019 Fully GA
* Support for separating the frontend firewall VPC from the backend application VPC using AWS PrivateLink or VPC peering
* Support for specific combinations of external and internal load balancing

# Proceed with Caution: 
These repositories contain default password information and should be used for Proof of Concept purposes only. If you wish to use this template in a production environment it is your responsibility to change the default passwords. 

# Copyright 2020  Palo Alto Networks
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
