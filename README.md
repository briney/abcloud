AbCloud
==============

EC2 instance/cluster management. Still under active development, so expect changes.

Usage
--------

Launch a basic cluster named 'test' with a master and 2 workers, all m3.large:  
`./abcloud launch test --workers 2`  

Terminate the 'test' cluster:  
`./abcloud destroy test`  

To get a full list of options:  
`./abcloud --help`


Requirements
-----------------

Python 2.7 (not tested with 3.x)  
boto  
paramiko  
