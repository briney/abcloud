AbCloud
==============

EC2 instance/cluster management. Still under active development, so expect changes.

Usage
--------  
`./abcloud <command> <cluster_name> [options]`  
  
Launch a basic cluster named 'test' with a master and 2 workers, all m3.large:  
`./abcloud launch test --workers 2`  
  
Launch a basic 'test' cluster with spot instance workers and a max price of $1.00/hr:  
`./abcloud launch test --workers 2 --spot-price 1.00`  
  
SSH into the master instance of the 'test' cluster:  
`./abcloud sshmaster test`
  
SSH into node001 of the 'test' cluster:  
`./abcloud sshnode test --node node001`
  
Put a file (local path: '~/myfile') onto the master instance of the 'test' cluster (remote path: '/scratch'):  
`./abcloud put test ~/myfile /scratch`
  
Put the same file onto node001 of the 'test' cluster:  
`./abcloud put test --node node001 /home/me/myfile /scratch`
  
Terminate the 'test' cluster:  
`./abcloud destroy test`  
    
Launch a single instance (r3.2xlarge) named 'jupyter' running a Jupyter server:  
`./abcloud launch jupyter --master-instance-type r3.2xlarge --jupyter`
  
Launch a single instance named 'mongo' running MongoDB with 8x500GB EBS volumes in RAID10:  
`./abcloud launch mongo --master-ebs-vol-num 8 --master-ebs-vol-size 500 --master-ebs-raid-level 10 --mongodb`  

List all AbCloud clusters/instances:  
`./abcloud list`
  
To get a full list of options and default settings:  
`./abcloud --help`


Requirements
-----------------

Python 2.7 (not tested with 3.x)  
boto  
paramiko  
