# abcloud  

EC2 instance/cluster management. Still under active development, but main command syntax (launch, ssh/sshnode, destroy, terminate, get, put) is fairly stable and hopefully won't undergo breaking changes.  
  
## install  
  
`pip install abcloud`
  
Out of the box, `abcloud` assumes you have an EC2 key file, named `default` and located at `~/.aws/default.pem`. Both of these defaults can be changed at runtime, using the `--key-pair` option to pass an alternative key name and the `--identity-file` option to pass an alternate path to your keyfile.  
  
`abcloud` uses `boto`, which is Amazon's Python API for working with AWS. Once `boto` is installed (it will be installed automatically when you install `abcloud` with `pip`), you should [configure your AWS credentials](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#shared-credentials-file).
  
## use
  
`abcloud <command> <cluster_name> [options]`  
  
### launch clusters/instances
  
Launch a single instance named 'my-instance' (the default instance type is m5.8xlarge):  
`abcloud launch my-instance` 

Launch a cluster named 'my-cluster' with a master and 2 workers, all m5.8xlarge:  
`abcloud launch my-cluster --workers 2`  
  
Launch a cluster with spot instance workers at a max price of $1.00/hr (by default, only the workers use spot pricing and masters are on-demand):  
`abcloud launch my-cluster --workers 2 --spot-price 1.00`  

Launch a single instance using spot pricing:  
`abcloud launch my-instance --spot-price 1.00 --force-spot-master`  

Launch a cluster with 2 workers of type m5.8xlarge and a master of type m5.24xlarge:  
`abcloud launch my-cluster --workers 2 --master-instance-type m5.24xlarge --instance-type m5.8xlarge`   
  
Launch a single instance ith 8x500GB EBS volumes in RAID10 (the default is ):  
`abcloud launch my-instance --master-ebs-vol-num 8 --master-ebs-vol-size 500 --master-ebs-raid-level 10` 
  
### connect to clusters/instances  
  
SSH into the master instance of the 'test' cluster:  
`abcloud ssh test`
  
SSH into node001 of the 'test' cluster:  
`abcloud sshnode test --node node001`
  
### put/get files  

Put a file (local path: '~/myfile') onto the master instance of 'my-cluster' (remote path: '/scratch'):  
`abcloud put test ~/myfile /scratch`
  
Put the same file onto node001 of the 'test' cluster:  
`abcloud put test --node node001 ~/myfile /scratch`
  
### terminate or destroy clusters

Terminate the 'test' cluster:  
`abcloud terminate test`  
  
Destroy the 'test' cluster (same as terminate, but also deletes security groups):  
`abcloud destroy test`     
  
To get a full list of options and default settings:  
`abcloud --help`
  
  
## requirements  
  
Python 3.5+   
boto3  
paramiko  
  
All of the above dependencies can be installed with pip. If you're new to Python, a great way to get started is to install the Anaconda Python distribution (https://www.continuum.io/downloads), which includes pip as well as a ton of useful scientific Python packages.  
