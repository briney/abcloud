#!/usr/bin/env python
# filename: abcloud.py


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


from __future__ import division, print_function, with_statement, absolute_import

import argparse
import codecs
from datetime import datetime
import getpass
import hashlib
import itertools
import logging
import os
import os.path
import pipes
import pkg_resources
import random
import shutil
import string
from stat import S_IRUSR
import subprocess
import sys
from sys import stderr
import tarfile
import tempfile
import textwrap
import time
import warnings

import boto3

from .utils import cluster
from .utils.config import *


__version__ = pkg_resources.require("abcloud")[0].version


def parse_args(print_help=False):
    parser = argparse.ArgumentParser(
        prog="AbCloud",
        # version="AbCloud {v}".format(v=ABCLOUD_VERSION),
        usage="abcloud [options] <action> <cluster_name>\n\n<action> can be: launch, terminate, destroy, sshmaster, sshnode, put, get, or list")

    parser.add_argument('options', nargs='+',
        help="Cluster action and action options.")
    parser.add_argument("-w", "--workers", type=int, default=0,
        help="Number of workers to launch (default: 0)")
    parser.add_argument(
        "-k", "--key-pair", default='default',
        help="Key pair to use on instances (default: default)")
    parser.add_argument(
        "-i", "--identity-file", default=IDENTITY_FILE_PATH,
        help="SSH private key file to use for logging into instances.")
    parser.add_argument(
        "-t", "--instance-type", default=INSTANCE_TYPE,
        help="Type of worker node instances to launch. \
             WARNING: must be 64-bit; small instances won't work")
    parser.add_argument(
        "-m", "--master-instance-type", default=None,
        help="Master instance type (leave empty for same as --instance-type)")
    parser.add_argument(
        "--node", default=None,
        help="Node to SSH into (use with sshmaster or sshnode actions) or for put/get operations.")
    parser.add_argument(
        "-r", "--region", default="us-east-1",
        help="EC2 region used to launch instances in, or to find them in (default: us-east-1)")
    parser.add_argument(
        "-z", "--zone", default='us-east-1c',
        help="Availability zone to launch instances in (default: us-east-1c)")
    parser.add_argument(
        "-a", "--ami", default=None,
        help="Amazon Machine Image ID to use")
    # parser.add_argument(
    #     "--abtools-version", default=DEFAULT_ABTOOLS_VERSION,
    #     help="Version of AbTools to use: 'X.Y.Z' (default: %default)")
    parser.add_argument('-l', '--log', dest='logfile', default=None,
        help='Path to logfile location. If not supplied, log will not be generated.')
    parser.add_argument(
        "--deploy-root-dir", default=False, action='store_true',
        help="If set, copies the directory specified by DEPLOY_TO_ROOT to the root directory of \
             all nodes. Must be absolute. Note that a trailing slash is handled as per rsync: \
             If you omit it, the last directory of the --deploy-root-dir path will be created \
             in / before copying its contents. If you append the trailing slash, \
             the directory is not created and its contents are copied directly into /. \
             (default: False, directory: {}).".format(DEPLOY_TO_ROOT))
    parser.add_argument(
        "--resume", action="store_true", default=False,
        help="Resume installation on a previously launched cluster \
             (for debugging)")
    parser.add_argument(
        "--master-root-vol-size", metavar="ROOT_SIZE", type=int, default=50,
        help="Size (in GB) of the root EBS volume to be attached to the master node.")
    parser.add_argument(
        "--master-ebs-vol-size", metavar="SIZE", type=int, default=25,
        help="Size (in GB) of each EBS volume to be attached to the master node.")
    parser.add_argument(
        "--master-ebs-vol-type", default="gp2",
        help="EBS volume type (e.g. 'gp2', 'standard').")
    parser.add_argument(
        "--master-ebs-vol-num", type=int, default=4,
        help="Number of EBS volumes to attach to the master node. \
             Volumes will be assembled into a RAID array and be made \
             available at /data. The array will also be NFS shared to all \
             worker nodes. The volumes will be deleted when the instances terminate. \
             Only possible on EBS-backed AMIs. \
             EBS volumes are only attached if --ebs-vol-size > 0. \
             Currently, we only support up to 12 EBS volumes.")
    parser.add_argument(
        "--master-ebs-raid-level", metavar="LEVEL", type=int, default=0,
        help="RAID level (just the number) for the array on master \
             (default: 0).")
    parser.add_argument(
        "--master-ebs-raid-dir", metavar="DIR", default='/data',
        help="Directory for the RAID array on master node \
             (default: /data).")
    parser.add_argument(
        "--ebs-vol-size", metavar="SIZE", type=int, default=0,
        help="Size (in GB) of each EBS volume.")
    parser.add_argument(
        "--ebs-vol-type", default="standard",
        help="EBS volume type (e.g. 'gp2', 'standard').")
    parser.add_argument(
        "--ebs-vol-num", type=int, default=1,
        help="Number of EBS volumes to attach to each node as /vol[x]. \
             The volumes will be deleted when the instances terminate. \
             Only possible on EBS-backed AMIs. \
             EBS volumes are only attached if --ebs-vol-size > 0. \
             Currently, we only support up to 8 EBS volumes.")
    parser.add_argument(
        "--placement-group", type=str, default=None,
        help="Which placement group to try and launch \
             instances into. Assumes placement group is already created.")
    parser.add_argument(
        "--spot-price", metavar="PRICE", type=float,
        help="If specified, launch workers as spot instances with the given \
             maximum price (in dollars)")
    parser.add_argument(
        "--force-spot-master", default=False, action='store_true',
        help="If specified, master will be launched as a spot instance \
             using --spot-price as maximum price.")
    # parser.add_argument(
    #     "--add-nodes", metavar="NODES", type="int",
    #     help="Number of nodes to add to a resized cluster.")
    # parser.add_argument(
    #     "--remove-nodes", metavar="NODES", type="int",
    #     help="Number of nodes to remove from a resized cluster.")
    parser.add_argument("--no-celery", action="store_false", dest="celery", default=True,
        help="Disable Celery configuration on the cluster.")
    parser.add_argument("--no-basespace-credentials", action="store_false", dest="basespace_credentials", default=True,
        help="If set, BaseSpace credentials file will NOT be uploaded to the server/cluster.")
    parser.add_argument("-u", "--user", default="ubuntu",
        help="The SSH user you want to connect as (default: ubuntu)")
    parser.add_argument("--delete-groups", action="store_true", default=False,
        help="When destroying a cluster, delete the security groups that were created")
    parser.add_argument("--use-existing-master", action="store_true", default=False,
        help="Launch fresh workers, but use an existing stopped master if possible")
    parser.add_argument("--no-jupyter", action="store_false", dest='jupyter', default=True,
        help="Set up a persistent Jupyter notebook server on the master node. \
        Jupyter notebook server will be launched in <master-ebs-raid-dir>/jupyter if \
        EBS volumes are attached, or in /home/ubuntu/jupyter if not. \
        If set without --jupyter-password, default password is 'abcloud'.")
    parser.add_argument("--jupyter-password", default='abcloud',
        help="Password for the Jupyter server. Ignored if '-jupyter' is not also set.")
    parser.add_argument("--mongodb", action="store_true", default=False,
        help="Set up a MongoDB server on the master instance. \
        Database will be located at <master-ebs-raid-dir>/db. \
        At the current time, auth is not enabled when launching mongod.")
    parser.add_argument("--localpath", default=None,
        help="Local path for put/get operations")
    parser.add_argument("--remotepath", default=None,
        help="Remote path for put/get operations")
    parser.add_argument('--port', dest='port', default=None,
        help='Port to forward to a remote server. \
        Default is None, which results in no port forwarding')
    parser.add_argument('--tunnel-server', dest='tunnel_server', default=None,
        help='SSH server to which the port will be forwarded, as <server_hostname>[:<server_port>]. \
        If a server_port is not provided, the port provided by "--forward-port" will be used.')
    parser.add_argument('--remote-server', dest='remote_server', default='localhost',
        help='Remote server for port forwarding. \
        Default is "localhost", which results in the port being forwarded to --forward-port-server.')
    parser.add_argument('--tunnel-user', dest='tunnel_user', default=None,
        help='SSH user for port forwarding')
    parser.add_argument('--tunnel-password', dest='tunnel_password', default=False, action='store_true',
        help='If set, will request a SSH password for port forwarding.')
    parser.add_argument('--tunnel-keyfile', dest='tunnel_keyfile', default=None,
        help='SSH keyfile for port forwarding. Default is None.')
    # parser.add_argument(
    #     "--user-data", type="string", default="",
    #     help="Path to a user-data file (most AMIs interpret this as an initialization script)")
    parser.add_argument(
        "--authorized-address", type=str, default="0.0.0.0/0",
        help="Address to authorize on created security groups (default: 0.0.0.0/0)")
    # parser.add_argument(
    #     "--additional-security-group", type="string", default="",
    #     help="Additional security group to place the machines in")
    # parser.add_argument(
    #     "--copy-aws-credentials", action="store_true", default=False,
    #     help="Add AWS credentials to hadoop configuration to allow Spark to access S3")
    parser.add_argument(
        "--subnet-id", default=None,
        help="VPC subnet to launch instances in")
    parser.add_argument(
        "--subnet-cidr-block", default='10.0.0.0/24',
        help="CIDR block for the subnet. \
        Note that this must be equal to or smaller than the size of the VPC CIDR block. \
        Default is 10.0.0.0/24, which is 256 addresses.")
    parser.add_argument(
        "--vpc-id", default=None,
        help="VPC to launch instances in. \
        If supplying a VPC ID, the VPC must alread exist and contain enough space for the requested subnet. \
        If either of these conditions aren't met, a new VPC will be created.")
    parser.add_argument(
        "--vpc-cidr-block", default='10.0.0.0/16',
        help="CIDR block for the VPC, if a new one is to be created. \
        If a VPC already exists and has enough available addresses for the desired subnet size, \
        a new VPC will not be created. \
        Default is 10.0.0.0/16, which is 65,536 addresses.")
    parser.add_argument(
        "--private-ips", action="store_true", default=False,
        help="Use private IPs for instances rather than public if VPC/subnet \
        requires that.")
    parser.add_argument('-v', '--version', action='version', \
        version='abcloud {version}'.format(version=__version__))
    parser.add_argument(
        '-D', '--debug', dest='debug', action='store_true', default=False,
        help="If set, will run in debug mode.")

    args = parser.parse_args()
    opts = args.options
    if len(opts) == 2:
        action, cluster_name = opts
        args.action = action
    elif len(opts) == 1 and opts[0] == 'list':
        action = 'list'
        cluster_name = None
    elif opts[0] in ['put', 'get'] and len(opts) == 4:
        action, cluster_name, path1, path2 = opts
        if action == 'put':
            args.localpath, args.remotepath = path1, path2
        else:
            args.remotepath, args.localpath = path1, path2
    else:
        parser.print_help()
        sys.exit(1)

    return (action, cluster_name, args)


class Args(object):
    """docstring for Args"""
    def __init__(self, action, cluster_name=None, path1=None, path2=None, localpath=None,
        remotepath=None, workers=0, key_pair='default', identity_file=IDENTITY_FILE_PATH,
        instance_type=INSTANCE_TYPE, master_instance_type=None,
        node=None, region='us-east-1', zone=None, ami=None, master_root_vol_size=50,
        deploy_root_dir=False, resume=False, master_ebs_vol_size=25, master_ebs_vol_num=4,
        master_ebs_raid_level=0, master_ebs_raid_dir='\data',
        ebs_vol_size=0, ebs_vol_type='standard', ebs_vol_num=1,
        placement_group=None, spot_price=None, force_spot_master=False,
        add_nodes=0, remove_nodes=0, celery=True, basespace_credentials=True,
        user='ubuntu', delete_groups=True, use_existing_master=False, jupyter=False,
        jupyter_port=8899, jupyter_password='abcloud', mongodb=False,
        user_data='', authorized_address='0.0.0.0/0',
        additional_security_group='', copy_aws_credentials=False, subnet_id=None,
        vpc_id=None, private_ips=False):
        super(Args, self).__init__()
        self.action = action
        self.cluster_name = cluster_name
        self.workers = workers
        self.key_pair = key_pair
        self.identity_file = identity_file
        self.instance_type = instance_type
        self.master_instance_type = master_instance_type if master_instance_type is not None else instance_type
        self.node = node
        self.region = region
        self.zone = zone
        self.ami = ami
        self.deploy_root_dir = deploy_root_dir
        self.resume = resume
        self.master_root_vol_size = master_root_vol_size
        self.master_ebs_vol_size = master_ebs_vol_size
        self.master_ebs_vol_num = master_ebs_vol_num
        self.master_ebs_raid_level = master_ebs_raid_level
        self.master_ebs_raid_dir = master_ebs_raid_dir
        self.ebs_vol_size = ebs_vol_size
        self.ebs_vol_num = ebs_vol_num
        self.placement_group = placement_group
        self.spot_price = spot_price
        self.force_spot_master = force_spot_master
        self.add_nodes = add_nodes
        self.remove_nodes = remove_nodes
        self.celery = celery
        self.basespace_credentials = basespace_credentials
        self.user = user
        self.delete_groups = delete_groups
        self.use_existing_master = use_existing_master
        self.jupyter = jupyter
        # self.jupyter_port = jupyter_port
        self.jupyter_password = jupyter_password
        self.mongodb = mongodb
        self.localpath = localpath
        self.remotepath = remotepath
        self.user_data = user_data
        self.authorized_address = authorized_address
        self.additional_security_group = additional_security_group
        self.copy_aws_credentials = copy_aws_credentials
        self.subnet_id = subnet_id
        self.vpc_id = vpc_id
        self.private_ips = private_ips

        if self.cluster_name is None and self.action != 'list':
            print('ERROR: cluster name is required')
            sys.exit(1)
        if self.action == 'put':
            self.localpath = path1 if path1 is not None else localpath
            self.remotepath = path2 if path2 is not None else remotepath
        elif self.action == 'get':
            self.localpath = path2 if path2 is not None else localpath
            self.remotepath = path1 if path1 is not None else remotepath


def validate_args(args):
    if not os.path.exists(args.identity_file):
        print("ERROR: The identity file '{}' doesn't exist.".format(args.identity_file),
            file=stderr)
        sys.exit(1)

    file_mode = os.stat(args.identity_file).st_mode
    if not (file_mode & S_IRUSR) or not oct(file_mode)[-2:] == '00':
        print("ERROR: The identity file must be accessible only by you.", file=stderr)
        print('''You can fix this with: sudo chmod 400 "{}"'''.format(args.identity_file),
            file=stderr)
        sys.exit(1)

    if args.instance_type not in EC2_INSTANCE_TYPES:
        print("Warning: Unrecognized EC2 instance type for instance-type: {}".format(
            args.instance_type), file=stderr)
        # Since we try instance types even if we can't resolve them, we check if they resolve.
        # If they do, see if they resolve to the same virtualization type.
        if args.instance_type in EC2_INSTANCE_TYPES and \
           args.master_instance_type in EC2_INSTANCE_TYPES:
            if EC2_INSTANCE_TYPES[args.instance_type] != \
               EC2_INSTANCE_TYPES[args.master_instance_type]:
                print("ERROR: AbCloud currently does not support having a master and workers "
                      "with different AMI virtualization types.", file=stderr)
                print("master instance virtualization type: {}".format(
                    EC2_INSTANCE_TYPES[args.master_instance_type]), file=stderr)
                print("worker instance virtualization type: {}".format(
                    EC2_INSTANCE_TYPES[args.instance_type]), file=stderr)
                sys.exit(1)

    if args.ebs_vol_num > 8:
        print("The number of EBS volumes (--ebs-vol-num) cannot be greater than 8", file=stderr)
        sys.exit(1)


def verify_boto_credentials():
    aws_dir = os.path.join(os.getenv('HOME'), '.aws')
    if aws_dir is None or not os.path.isfile(aws_dir + '/credentials'):
        if os.getenv('AWS_ACCESS_KEY_ID') is None:
            print("ERROR: The environment variable AWS_ACCESS_KEY_ID must be set",
                  file=stderr)
            sys.exit(1)
        if os.getenv('AWS_SECRET_ACCESS_KEY') is None:
            print("ERROR: The environment variable AWS_SECRET_ACCESS_KEY must be set",
                  file=stderr)
            sys.exit(1)


def main(action, cluster_name, args):
    # validate
    validate_args(args)
    verify_boto_credentials()
    # run
    if action == 'launch':
        clust = cluster.Cluster(cluster_name, args)
        clust.launch()

    elif action == 'terminate':
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.terminate()

    elif action == 'destroy':
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.destroy()

    elif action == 'list':
        cluster.list_clusters(args)

    elif action == 'sshmaster':
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.ssh()

    elif action == 'sshnode':
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.ssh(node_name=args.node)

    elif action == 'put':
        node = args.node if args.node is not None else 'master'
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.put(node, args.localpath, args.remotepath)

    elif action == 'get':
        node = args.node if args.node is not None else 'master'
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.get(node, args.remotepath, args.localpath)

    elif action == 'tunnel':
        if args.tunnel_password:
            args.tunnel_password = getpass.getpass('Enter SSH password: ')
        node = args.node if args.node is not None else 'master'
        clust = cluster.retrieve_cluster(cluster_name, args)
        clust.tunnel(node, args)

    else:
        print("Invalid action: {}".format(action), file=stderr)
        sys.exit(1)


def run_standalone(action, cluster_name, args):
    main(action, cluster_name, args)


def run(**kwargs):
    args = Args(**kwargs)
    main(args.action, args.cluster_name, args)


if __name__ == "__main__":
    action, cluster_name, args = parse_args()
    try:
        main(action, cluster_name, args)
    except UsageError as e:
        print("\nError:\n", e, file=stderr)
        sys.exit(1)
