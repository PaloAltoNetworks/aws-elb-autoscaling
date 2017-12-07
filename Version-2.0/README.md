# Auto Scaling VM-Series Firewalls on AWS Version 2.0 BETA
This CloudFormation Template deploys a tier of [VM-Series firewalls on AWS](https://aws.amazon.com/marketplace/seller-profile?id=0ed48363-5064-4d47-b41b-a53f7c937314) that integrates with AWS Auto Scaling and Elastic Load Balancing (ELB) using a combination of AWS services (AWS Lambda, Amazon CloudWatch, S3, SNS) and PAN-OS/VM-Series automation features (API, bootstrapping). The template allows you to leverage AWS scalability features designed to manage sudden surges in demand for application workload resources by simultaneously scaling the VM-Series firewalls with changing workloads.  This solution includes support for the PAYG and BYOL licensing options for the VM-Series firewalls. 

![alt text](/Version-2.0/cft_elb20.png?raw=true "Topology for the Auto Scaling VM-Series Firewalls on AWS Version 2.0")
 
**Requirements**
* You can deploy this solution only in regions that support AWS Lambda. 
* Accept the EULA for the VM-Series PAYG license bundle you plan to use.  
[VM-Series firewall Bundle 2](https://aws.amazon.com/marketplace/pp/B00PJ2V04O)  
[VM-Series firewall Bundle 1](https://aws.amazon.com/marketplace/pp/B00PJ2VDFA)  

**Support Policy**  
***In Beta***  
The Auto Scaling VM-Series Firewalls on AWS Version 2.0 solution is currently released under beta.  It is your responsibility to not use this in a production environment as it may contain software bugs and is still undergoing testing.
 
For assistance during the beta, please post your questions either to this GitHub repo or to the Palo Alto Networks public cloud live forum at https://live.paloaltonetworks.com/t5/AWS-Azure-Discussions/bd-p/AWS_Azure_Discussions (free sign in required.)
 
Only projects explicitly tagged with "Supported" information are officially supported. Unless explicitly tagged, all projects or work posted in our GitHub repository or sites other than our official Downloads page are provided under the best effort policy. The Network ELB template is released under the community supported policy.

**Documentation**  
* Release Notes: Included in this repository.
* Technical Documentation: Included in this repository