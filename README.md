# AbCloud  

EC2 instance/cluster management. Still under active development, but main commands (launch, sshmaster/sshnode, destroy, terminate, get, put) are stable and should not undergo breaking changes.

### use
  
`abcloud <command> <cluster_name> [options]`  
  
Launch a basic cluster named 'test' with a master and 2 workers, all m3.large:  
`abcloud launch test --workers 2`  
  
Launch a basic 'test' cluster with spot instance workers at a max price of $1.00/hr:  
`abcloud launch test --workers 2 --spot-price 1.00`  
  
SSH into the master instance of the 'test' cluster:  
`abcloud sshmaster test`
  
SSH into node001 of the 'test' cluster:  
`abcloud sshnode test --node node001`
  
Put a file (local path: '~/myfile') onto the master instance of the 'test' cluster (remote path: '/scratch'):  
`abcloud put test ~/myfile /scratch`
  
Put the same file onto node001 of the 'test' cluster:  
`abcloud put test --node node001 /home/me/myfile /scratch`
  
Terminate the 'test' cluster:  
`abcloud terminate test`  
  
Destroy the 'test' cluster (same as terminate, but also deletes security groups):  
`abcloud destroy test`    
    
Launch a single instance (r3.2xlarge) named 'jupyter' running a Jupyter Notebook server:  
`abcloud launch jupyter --instance-type r3.2xlarge --jupyter`  
  
Launch 'jupyter' instance running a Jupyter server, but using spot pricing:  
`abcloud launch jupyter --jupyter --spot-price 2.00 --force-spot-master`  
  
Launch a single instance named 'mongo' running MongoDB with 8x500GB EBS volumes in RAID10:  
`abcloud launch mongo --master-ebs-vol-num 8 --master-ebs-vol-size 500 --master-ebs-raid-level 10 --mongodb`  
  
To get a full list of options and default settings:  
`abcloud --help`


### requirements  
  
Python 2.7 (3.x probably doesn't work, but hasn't been tested)  
boto3  
paramiko  
  
All of the above dependencies can be installed with pip. If you're new to Python, a great way to get started is to install the Anaconda Python distribution (https://www.continuum.io/downloads), which includes pip as well as a ton of useful scientific Python packages.  
