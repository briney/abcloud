#!/usr/bin/env python
# filename: config.py


#
# Copyright (c) 2015 Bryan Briney
# License: The MIT license (http://opensource.org/licenses/MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#


import os


ABCLOUD_VERSION = "0.0.1"

IDENTITY_FILE_PATH = os.path.expanduser('~/.aws/default.pem')

INSTANCE_TYPE = 'm3.large'

DEPLOY_TO_ROOT = ''

MASTER_TCP_PORT_RANGES = [(22, 22),  # SSH
                          (111, 111),  # NFS
                          (2049, 2049),  # NFS
                          (4040, 4045),
                          (4242, 4242),
                          (5555, 5555),  # Celery
                          (6379, 6379),  # Celery
                          (8080, 8081),
                          (8088, 8088),
                          (8899, 8899),  # Jupyter
                          (18080, 18080),
                          (19999, 19999),
                          (27017, 27017),  # MongoDB
                          (50030, 50030),
                          (50070, 50070),
                          (60070, 60070), ]


MASTER_UDP_PORT_RANGES = [(111, 111),  # NFS
                          (2049, 2049),  # NFS
                          (4242, 4242), ]


WORKER_TCP_PORT_RANGES = [(22, 22),  # SSH
                          (5555, 5555),  # Celery
                          (6379, 6379),  # Celery
                          (8080, 8081), ]


UBUNTU_AMI_MAP = {
    # 'us-east-1': 'ami-af5a4cc5',
    # 'us-west-1': 'ami-8a5529ea',
    # 'us-west-2': 'ami-50946030'
    'us-east-1': 'ami-bcdc16c6',
    'us-east-2': 'ami-49426e2c',
    'us-west-1': 'ami-1b17257b',
    'us-west-2': 'ami-19e92861'
}


# Source: http://aws.amazon.com/amazon-linux-ami/instance-type-matrix/
# Last Updated: 2015-05-08
# For easy maintainability, please keep this manually-inputted dictionary sorted by key.
EC2_INSTANCE_TYPES = {
    "c1.medium": "pvm",
    "c1.xlarge": "pvm",
    "c3.large": "pvm",
    "c3.xlarge": "pvm",
    "c3.2xlarge": "pvm",
    "c3.4xlarge": "pvm",
    "c3.8xlarge": "hvm",
    "c4.large": "hvm",
    "c4.xlarge": "hvm",
    "c4.2xlarge": "hvm",
    "c4.4xlarge": "hvm",
    "c4.8xlarge": "hvm",
    "cc1.4xlarge": "hvm",
    "cc2.8xlarge": "hvm",
    "cg1.4xlarge": "hvm",
    "cr1.8xlarge": "hvm",
    "d2.xlarge": "hvm",
    "d2.2xlarge": "hvm",
    "d2.4xlarge": "hvm",
    "d2.8xlarge": "hvm",
    "g2.2xlarge": "hvm",
    "g2.8xlarge": "hvm",
    "hi1.4xlarge": "pvm",
    "hs1.8xlarge": "pvm",
    "i2.xlarge": "hvm",
    "i2.2xlarge": "hvm",
    "i2.4xlarge": "hvm",
    "i2.8xlarge": "hvm",
    "m1.small": "pvm",
    "m1.medium": "pvm",
    "m1.large": "pvm",
    "m1.xlarge": "pvm",
    "m2.xlarge": "pvm",
    "m2.2xlarge": "pvm",
    "m2.4xlarge": "pvm",
    "m3.medium": "hvm",
    "m3.large": "hvm",
    "m3.xlarge": "hvm",
    "m3.2xlarge": "hvm",
    "m4.large": "hvm",
    "m4.xlarge": "hvm",
    "m4.2xlarge": "hvm",
    "m4.4xlarge": "hvm",
    "m4.10xlarge": "hvm",
    "r3.large": "hvm",
    "r3.xlarge": "hvm",
    "r3.2xlarge": "hvm",
    "r3.4xlarge": "hvm",
    "r3.8xlarge": "hvm",
    "t1.micro": "pvm",
    "t2.micro": "hvm",
    "t2.small": "hvm",
    "t2.medium": "hvm",
}
