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


ABCLOUD_VERSION = "0.0.1"
DEFAULT_ABTOOLS_VERSION = "0.4.7"

IDENTITY_FILE_PATH = '/Users/bryanbriney/Google_Drive/burton_lab/AWS/default.pem'

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

VALID_ABTOOLS_VERSIONS = set([
    "0.1.1",
    "0.1.2",
    "0.1.3",
    "0.1.4",
    "0.1.5",
    "0.1.6",
    "0.1.7",
    "0.1.8",
    "0.2.0",
    "0.2.1",
    "0.2.2",
    "0.3.0",
    "0.3.1",
    "0.3.2",
    "0.3.3",
    "0.3.4",
    "0.3.5",
    "0.3.6",
    "0.4.0",
    "0.4.2",
    "0.4.3",
    "0.4.4",
    "0.4.5",
    "0.4.6",
    "0.4.7",
])

ABTOOLS_AMI_MAP = {
    '0.1.0': 'ami-f2c4b39a',
    '0.1.1': 'ami-46c8bf2e',
    '0.1.2': 'ami-eabdc382',
    '0.1.3': 'ami-7cda8314',
    '0.1.4': 'ami-98684bf0',
    '0.1.5': 'ami-1293bb7a',
    '0.1.6': 'ami-4a0f3422',
    '0.1.7': 'ami-d8edd6b0',
    '0.1.8': 'ami-b2e8edda',
    '0.2.0': 'ami-00fbf068',
    '0.2.1': 'ami-2e180b46',
    '0.2.2': 'ami-056a876e',
    '0.3.0': 'ami-09b27962',
    '0.3.1': 'ami-170abb7c',
    "0.3.2": 'ami-8746feec',
    "0.3.3": 'ami-5d08b036',
    "0.3.4": 'ami-03a91268',
    "0.3.5": 'ami-5d299336',
    "0.3.6": 'ami-d11aa0ba',
    "0.4.0": 'ami-d03866ba',
    "0.4.2": 'ami-7efdda14',
    "0.4.3": 'ami-f7dbfc9d',
    "0.4.4": 'ami-981e3df2',
    "0.4.5": 'ami-f5eecd9f',
    "0.4.6": 'ami-fa725f90',
    "0.4.7": 'ami-8583adef'
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
