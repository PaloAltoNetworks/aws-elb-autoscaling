# Auto Scaling VM-Series firewalls in AWS
Version 2.1 - Community support release
Availability: Mid-January

Note: The initial release of version 2.1 of the Auto Scaling VM-Series firewalls in AWS is provided as a community supported, i.e. best effort, release. You can consider this as an open beta to introduce new features and collect feedback for improving the generally available release that will be officially supported.

# Overview
This release enables a clear separation of the firewall VPC's from the application VPC's. This separation allows security teams to offer firewall-as-a-service to their internal teams such as line of business, application developers and DevOps who build, ship and run applications (called "application teams" here). This enables separate billing and management of each. In addition, security and application teams can put specific restrictions such as tight security groups, no IGW etc on the application VPC's for a stronger security posture, and leave all security of inbound traffic to the security team. Enforcement of these policy-based capabilities on the application VPC's can be easily done through services such as [RedLock](https://www.paloaltonetworks.com/redlock), while VM-Series provides the network security protections and visibility. Also, as the number of protected application VPC's grow, security teams can use the auto scaling stack of firewalls for elastic, on-demand, security. Each application (via its related internal load balancer) are mapped to a load balancing rule in the external load balancer.

This architecture uses a load balancer sandwich for protecting Internet facing applications, for other use cases, see https://github.com/PaloAltoNetworks/aws-elb-autoscaling

# Features
* Support for separating the frontend firewall VPC from the backend application VPC using AWS PrivateLink or VPC peering.
* Support for specific combinations of external and internal load balancing using ALB and NLB. The early release version (Community-Supported) allows new deployment of ALB as external load balancer, and NLB as the internal load balancer. Both oc which must be deployed into new VPC's. This version may be used as a reference by advanced customers who build their own, custom, implementation of auto scaling VM-Series.
* The firewall VPC's and application VPC's can be part of same AWS account or different accounts, i.e. cross-account.

# Documentation
Use of version 2.1 is recommended only for those users already familar with the existing auto scaling solution (version 2.1). This initial release is meant to provide an early-release version of the separate VPC's capability.
* Overview steps
1. Deploy Panorama
2. Setup Panorama Device Group and Template Stack
3. Prepare bootstrap files
4. Upload Lambda functions
5. Deploy auto scaling CFTs
* More detailed set of deployment steps are available here (coming soon). Complete documentation, similar to earlier versions, will be available when version 2.1 is released.

# Support Policy: Community-Supported aka Best Effort
This CFT is released under an as-is, best effort, support policy. These scripts should be seen as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.
