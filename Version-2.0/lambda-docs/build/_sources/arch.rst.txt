Architecture of the Palo Alto CFT Lambda Functions
==================================================
.. image:: aws.png

|
|
|

.. graphviz::

    digraph {
        subgraph fw_cft {
            size ="8.4";
            label="Firewall CFT";
            launch_fw_cft [shape=box];
            launch_fw_cft -> init [weight=8, label="deploy init_lambda"];
            init_lambda -> sched_evt1 [weight=8, label="deploy"];
            launch_fw_cft -> fwInit [weight=8, label="deploy fw_init lambda"];
            sched_evt1 -> fw_asg [weight=8, label="create fw asg"];
            fw_asg -> firewall [weight=8, label="launch firewalls"]
            nlb_sqs -> sched_evt1 [weight=8, label="read nlb IP"];
            sched_evt1 -> fw_nat_rule [weight=8, label="config fw nat rules"];
            fw_nat_rule -> fw_table [weight=8, label="update fw state"]; 
            sched_evt1 -> nlb_table [weight=8, label="update nlb table"];
            fw_table -> sched_evt1 [weight=8, label="read fw table"];
            firewall -> cloud_watch [weight=8, lable="register fw metrics"];
            fw_init -> create_eni [weight=8, label="1. create eni"];
            fw_init -> attach_eni_trust [weight=8, label="2. attach to instance"];
            fw_init -> attach_eni_mgmt [weight=8, label="3. attach to instance"];
            fw_init -> fw_table [weight=8, label="4. add/delete fw entries"];
        }
        
        subgraph nlb_cft {
            size="8.4";
            label="NLB CFT";
            launch_nlb_cft [shape=box];
            launch_nlb_cft -> nlb [weight=8, label="deploy nlb"];
            launch_nlb_cft -> nlbLambda [weight=8, label="deploy nlb lambda"];
            nlb_lambda -> nlb_sqs [weight=8, label="write nlb IP"];
        }

    }


