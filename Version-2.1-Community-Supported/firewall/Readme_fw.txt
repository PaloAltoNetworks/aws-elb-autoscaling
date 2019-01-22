Read Me:

This is a auto scaling template for paloalto firewalls on aws environment.
This "firewall" folder contains:
1. template to deploy on the aws gui [firewall-new-vpc-v2.1.template]
2. lambda functions to fciliatte the working [ init.py, fw_init.py, sched_evt1.py,lib,dnslib,sha.py]
3. init.cfg with panorama bootstrapping information
4.panorama_sample_config


The requirements to get this working :

Panorama:
1. We need panorama to :
	i.boot strap the firewalls 
	ii. handle config changes and push the same to the firewalls in specific DG
	iii. delicense the firewalls

For panorama to perform the above functions we have to have the following conditions satisfied:

1. As a good practice keep a set of DG and tenplatestack for each firewall stack .
2. Configure the template on panorama with the following details and associate with corresponding templatestack: 
			Template config:
			===============
			1.Interfaces
                        Note:enable default gateway only ont he untrust interface and not on the trust interface.
			2.Zones
			3. VR [has to follow format : VR-tempstackname]
			4.DNSip [preferabbly :169.254.169.253]
			5. fqdn refresh time of 60 s
			6.Username/password as pandemo/demopassword
			
			DGconfig:
			===============
			1. Allow_All
			
			
3.Add the delicense key of the firewall on the panorama. [Can be seen using :xxxx@Panorama> request license api-key show  on the panorama cli]
