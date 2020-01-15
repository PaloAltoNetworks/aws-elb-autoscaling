# Auto Scaling VM-Series firewalls on AWS

Version 2.1 Firewall Template GA release

# Overview
This release enables a clear separation of the firewall VPC's from the application VPC's. This separation allows security teams to offer firewall-as-a-service to their internal teams such as line of business, application developers and DevOps who build, ship and run applications (called "application teams" here). This enables separate billing and management of each. In addition, security and application teams can put specific restrictions such as tight security groups, no IGW etc on the application VPC's for a stronger security posture, and leave all security of inbound traffic to the security team. Enforcement of these policy-based capabilities on the application VPC's can be easily done through services such as [RedLock](https://www.paloaltonetworks.com/redlock), while VM-Series provides the network security protections and visibility. Also, as the number of protected application VPC's grow, security teams can use the auto scaling stack of firewalls for elastic, on-demand, security. Each application (via its related internal load balancer) are mapped to a load balancing rule in the external load balancer.

This architecture uses a load balancer sandwich for protecting Internet facing applications, for other use cases click [here]( https://github.com/PaloAltoNetworks/aws-elb-autoscaling)

# Topology

**Single-VPC**  
![alt text](/Version-2.1/cft_elb21_SingleVPC.png?raw=true "Topology for the Auto Scaling VM-Series Firewalls in a SingleVPC on AWS Version 2.1")  

**Multi-VPC**  
![alt text](/Version-2.1/cft_elb21_MultiVPC.png?raw=true "Topology for the Auto Scaling VM-Series Firewalls in MultiVPC on AWS Version 2.1")

# Features
* Support for separating the frontend firewall VPC from the backend application VPC using AWS PrivateLink or VPC peering.
* Support for specific combinations of external and internal load balancing using ALB and NLB. The early release version (Community-Supported) allows new deployment of ALB as external load balancer, and NLB as the internal load balancer. Both oc which must be deployed into new VPC's. This version may be used as a reference by advanced customers who build their own, custom, implementation of auto scaling VM-Series.
* The firewall VPC's and application VPC's can be part of same AWS account or different accounts, i.e. cross-account.

# Documentation
* Refer to the [deployment guide]
(https://docs.paloaltonetworks.com/vm-series/9-0/vm-series-deployment/set-up-the-vm-series-firewall-on-aws/auto-scale-vm-series-firewalls-with-the-amazon-elb/vm-series-auto-scale-template-for-aws-version-v21.html) before starting.
* [Reference architectures](https://www.paloaltonetworks.com/resources/reference-architectures) for protecting outbound and east-west flows are also available.
* How-to videos, datasheet and templates can be found at [live.paloaltonetworks.com/aws](http://live.paloaltonetworks.com/aws).

# Support Policy
**The Firewall Template is a GA Release & Officially Supported** 
The autoscaling firewall template is released under the official support policy of Palo Alto Networks through the support options that you've purchased, for example Premium Support, support teams, or ASC (Authorized Support Centers) partners and Premium Partner Support options. The support scope is restricted to troubleshooting for the stated/intended use cases and product versions specified in the project documentation and does not cover customization of the scripts or templates. 

**The Application Template is a sample and Community-Supported aka NOT TAC SUPPORTED**
This CFT is released under an as-is, best effort, support policy. These scripts should be seen as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.

NOTE: Python Software Foundation (PSF) has announced that Python 2.7 which is used in the AWS Lambda functions used in this auto scaling solution will reach [end of life](https://www.python.org/dev/peps/pep-0373/) in January 2020. This change does not impact the auto scaling solution since AWS has announced [continued support](https://aws.amazon.com/blogs/compute/continued-support-for-python-2-7-on-aws-lambda/) for Python 2.7 on AWS Lambda till December 2020. Palo Alto Networks will evaluate how to continue supporting auto scaling on AWS beyond December 2020 and provide an update on our plans at a future date.