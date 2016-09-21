#Auto Scaling the VM-Series in AWS

This CloudFormation Template deploys a tier of VM-Series firewalls on AWS that integrates with AWS Auto Scaling and Elastic Load Balancing (ELB) using a combination of native AWS services (AWS Lambda, Amazon CloudWatch, S3, SNS) and PAN-OS/VM-Series automation features (API, bootstrapping). The template allows you to leverage AWS scalability features designed to manage sudden surges in demand for application workload resources by simultaneously scaling the VM-Series firewalls with changing workloads. 

**Requirements**
 
- You can deploy this solution only in regions that support AWS Lambda.
- You must accept the EULA for the [VM-Series firewall Bundle 2] (https://aws.amazon.com/marketplace/pp/B00PJ2V04O) prior to launching the template.
 
**Support Policy**
 
***Supported***
 
This project is released under the official support policy of Palo Alto Networks through the support options that you've purchased, for example Premium Support, support teams, or ASC (Authorized Support Centers) partners and Premium Partner Support options. The support scope is restricted to troubleshooting for the stated/intended use cases and product versions specified in the project documentation and does not cover customization of the scripts or templates.
Only projects explicitly tagged with "Supported" information are officially supported. Unless explicitly tagged, all projects or work posted in our [GitHub repository] (https://github.com/PaloAltoNetworks) or sites other than our official [Downloads page] (https://support.paloaltonetworks.com/) are provided under the best effort policy.
 
**Documentation**
 
- Release Notes: Included in this repository.
- [VM-Series auto scaling deployment guide](https://www.paloaltonetworks.com/documentation/71/virtualization/virtualization/set-up-the-vm-series-firewall-in-aws/auto-scale-vm-series-firewalls-with-the-amazon-elb )
- [Lightboard video](https://www.youtube.com/watch?v=xiPZHzdNRmI&feature=youtu.be)
- About the [VM-Series Firewall for AWS](https://aws.paloaltonetworks.com)
 
