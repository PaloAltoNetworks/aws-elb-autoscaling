# Auto Scaling VM-Series Firewalls on AWS 
## Recommended install version is 2.1 

This CloudFormation Template deploys a tier of [VM-Series firewalls on AWS](https://aws.amazon.com/marketplace/seller-profile?id=0ed48363-5064-4d47-b41b-a53f7c937314) that integrates with AWS Auto Scaling and Elastic Load Balancing (ELB) using a combination of AWS services (AWS Lambda, Amazon CloudWatch, S3, SNS) and PAN-OS/VM-Series automation features (API, bootstrapping). The template allows you to leverage AWS scalability features designed to manage sudden surges in demand for application workload resources by simultaneously scaling the VM-Series firewalls with changing workloads. 

CFT 1.2.2 includes  support for the PAYG and BYOL licensing options for the VM-Series firewalls.

![Alt text](/Version-1.2/cft_elb.png?raw=true "Topology for the Auto Scaling VM-Series Firewalls on AWS")
 
**Requirements**
* You can deploy this solution only in regions that support AWS Lambda. For regions that only support signature version 4 for S3  buckets, you must use PAN-OS 8.0 or later. 
* Accept the EULA for the VM-Series PAYG license bundle you plan to use.   
[VM-Series firewall Bundle 2](https://aws.amazon.com/marketplace/pp/B00PJ2V04O)  
[VM-Series firewall Bundle 1](https://aws.amazon.com/marketplace/pp/B00PJ2VDFA)

**Support Policy**
***Supported***
This project is released under the official support policy of Palo Alto Networks through the support options that you've purchased, for example Premium Support, support teams, or ASC (Authorized Support Centers) partners and Premium Partner Support options. The support scope is restricted to troubleshooting for the stated/intended use cases and product versions specified in the project documentation and does not cover customization of the scripts or templates. 
Only projects explicitly tagged with "Supported" information are officially supported. Unless explicitly tagged, all projects or work posted in our [GitHub repository](https://github.com/PaloAltoNetworks) or sites other than our official [Downloads page](https://support.paloaltonetworks.com/) are provided under the best effort policy.

**Documentation**
* Release Notes: Included in this repository.
* Technical Documentation: [VM-Series 7.1 Deployment Guide](https://www.paloaltonetworks.com/documentation/71/virtualization/virtualization/set-up-the-vm-series-firewall-in-aws/auto-scale-vm-series-firewalls-with-the-amazon-elb) and [VM-Series 8.0 Deployment Guide](https://www.paloaltonetworks.com/documentation/80/virtualization/virtualization/set-up-the-vm-series-firewall-on-aws/auto-scale-vm-series-firewalls-with-the-amazon-elb)
* [Lightboard video](https://www.youtube.com/watch?v=xiPZHzdNRmI&feature=youtu.be)
* About the [VM-Series Firewall for AWS](https://aws.paloaltonetworks.com).