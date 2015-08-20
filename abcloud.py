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


from __future__ import division, print_function, with_statement

import codecs
import hashlib
import itertools
import logging
import os
import os.path
import pipes
import random
import shutil
import string
from stat import S_IRUSR
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import warnings
from datetime import datetime
from optparse import OptionParser
from sys import stderr

import boto
from boto import ec2

from utils.config import *

if sys.version < "3":
	from urllib2 import urlopen, Request, HTTPError
else:
	from urllib.request import urlopen, Request
	from urllib.error import HTTPError
	raw_input = input
	xrange = range


# Configure and parse our command-line arguments
def parse_args():
	parser = OptionParser(
		prog="ec2-cluster",
		version="%prog {v}".format(v=EC2_CLUSTER_VERSION),
		usage="%prog [options] <action> <cluster_name>\n\n"
		+ "<action> can be: launch, destroy, sshmaster, sshnode, list, stop, " +
		"start, get-master, or reboot-workers")

	parser.add_option(
		"-w", "--workers", type="int", default=0,
		help="Number of workers to launch (default: %default)")
	parser.add_option(
		"-k", "--key-pair", default='default',
		help="Key pair to use on instances (default: %default)")
	parser.add_option(
		"-i", "--identity-file", default=IDENTITY_FILE_PATH,
		help="SSH private key file to use for logging into instances (default: %default)")
	parser.add_option(
		"-t", "--instance-type", default=WORKER_INSTANCE_TYPE,
		help="Type of worker node instances to launch (default: %default). " +
			 "WARNING: must be 64-bit; small instances won't work")
	parser.add_option(
		"-m", "--master-instance-type", default=MASTER_INSTANCE_TYPE,
		help="Master instance type (leave empty for same as instance-type)")
	parser.add_option(
		"--node", default=None,
		help="Node to SSH into (use with sshmaster or sshnode actions)")
	parser.add_option(
		"-r", "--region", default="us-east-1",
		help="EC2 region used to launch instances in, or to find them in (default: %default)")
	parser.add_option(
		"-z", "--zone", default=None,
		help="Availability zone to launch instances in, or 'all' to spread " +
			 "workers across multiple (an additional $0.01/Gb for bandwidth" +
			 "between zones applies) (default: a single zone chosen at random)")
	parser.add_option(
		"-a", "--ami", default=None,
		help="Amazon Machine Image ID to use (default: %default)")
	parser.add_option(
		"-v", "--abtools-version", default=DEFAULT_ABTOOLS_VERSION,
		help="Version of AbTools to use: 'X.Y.Z' (default: %default)")
	# parser.add_option(
	# 	"--spark-git-repo",
	# 	default=DEFAULT_SPARK_GITHUB_REPO,
	# 	help="Github repo from which to checkout supplied commit hash (default: %default)")
	# parser.add_option(
	# 	"--spark-ec2-git-repo",
	# 	default=DEFAULT_SPARK_EC2_GITHUB_REPO,
	# 	help="Github repo from which to checkout spark-ec2 (default: %default)")
	# parser.add_option(
	# 	"--spark-ec2-git-branch",
	# 	default=DEFAULT_SPARK_EC2_BRANCH,
	# 	help="Github repo branch of spark-ec2 to use (default: %default)")
	parser.add_option(
		"--deploy-root-dir", default=False, action='store_true',
		help="If set, copies the directory specified by DEPLOY_TO_ROOT to the root directory of " +
			 "all nodes. Must be absolute. Note that a trailing slash is handled as per rsync: " +
			 "If you omit it, the last directory of the --deploy-root-dir path will be created " +
			 "in / before copying its contents. If you append the trailing slash, " +
			 "the directory is not created and its contents are copied directly into /. " +
			 "(default: %default, directory: {}).".format(DEPLOY_TO_ROOT))
	# parser.add_option(
	# 	"--hadoop-major-version", default="1",
	# 	help="Major version of Hadoop. Valid options are 1 (Hadoop 1.0.4), 2 (CDH 4.2.0), yarn " +
	# 		 "(Hadoop 2.4.0) (default: %default)")
	# parser.add_option(
	# 	"-D", metavar="[ADDRESS:]PORT", dest="proxy_port",
	# 	help="Use SSH dynamic port forwarding to create a SOCKS proxy at " +
	# 		 "the given local address (for use with login)")
	parser.add_option(
		"--resume", action="store_true", default=False,
		help="Resume installation on a previously launched cluster " +
			 "(for debugging)")
	parser.add_option(
		"--master-ebs-vol-size", metavar="SIZE", type="int", default=25,
		help="Size (in GB) of each EBS volume to be attached to the master node.")
	parser.add_option(
		"--master-ebs-vol-type", default="standard",
		help="EBS volume type (e.g. 'gp2', 'standard').")
	parser.add_option(
		"--master-ebs-vol-num", type="int", default=4,
		help="Number of EBS volumes to attach to the master node. " +
			 "Volumes will be assembled into a RAID array and be made " +
			 "available at /data. The array will also be NFS shared to all " +
			 "worker nodes."
			 "The volumes will be deleted when the instances terminate. " +
			 "Only possible on EBS-backed AMIs. " +
			 "EBS volumes are only attached if --ebs-vol-size > 0." +
			 "Currently, we only support up to 12 EBS volumes.")
	parser.add_option(
		"--master-ebs-raid-level", metavar="LEVEL", type="int", default=0,
		help="RAID level (just the number) for the array on master " +
			 "(default: %default).")
	parser.add_option(
		"--master-ebs-raid-dir", metavar="DIR", default='/data',
		help="Directory for the RAID array on master node " +
			 "(default: %default).")
	parser.add_option(
		"--ebs-vol-size", metavar="SIZE", type="int", default=0,
		help="Size (in GB) of each EBS volume.")
	parser.add_option(
		"--ebs-vol-type", default="standard",
		help="EBS volume type (e.g. 'gp2', 'standard').")
	parser.add_option(
		"--ebs-vol-num", type="int", default=1,
		help="Number of EBS volumes to attach to each node as /vol[x]. " +
			 "The volumes will be deleted when the instances terminate. " +
			 "Only possible on EBS-backed AMIs. " +
			 "EBS volumes are only attached if --ebs-vol-size > 0." +
			 "Currently, we only support up to 8 EBS volumes.")
	parser.add_option(
		"--placement-group", type="string", default=None,
		help="Which placement group to try and launch " +
			 "instances into. Assumes placement group is already " +
			 "created.")
	# parser.add_option(
	# 	"--swap", metavar="SWAP", type="int", default=1024,
	# 	help="Swap space to set up per node, in MB (default: %default)")
	parser.add_option(
		"--spot-price", metavar="PRICE", type="float",
		help="If specified, launch workers as spot instances with the given " +
			 "maximum price (in dollars)")
	# parser.add_option(
	# 	"--ganglia", action="store_true", default=True,
	# 	help="Setup Ganglia monitoring on cluster (default: %default). NOTE: " +
	# 		 "the Ganglia page will be publicly accessible")
	parser.add_option(
		"--no-celery", action="store_false", dest="celery", default=True,
		help="Disable Celery configuration on the cluster.")
	parser.add_option(
		"-u", "--user", default="ubuntu",
		help="The SSH user you want to connect as (default: %default)")
	parser.add_option(
		"--delete-groups", action="store_true", default=False,
		help="When destroying a cluster, delete the security groups that were created")
	parser.add_option(
		"--use-existing-master", action="store_true", default=False,
		help="Launch fresh workers, but use an existing stopped master if possible")
	parser.add_option(
		"--jupyter", action="store_true", default=False,
		help="Set up a persistent Jupyter notebook server on the master node. " +
			 "Jupyter notebook server will be launched in <master-ebs-raid-dir>/jupyter if " +
			 "EBS volumes are attached, or in /home/ubuntu/jupyter if not."
			 "If set without --jupyter-password, default password is 'abcloud'.")
	parser.add_option(
		"--jupyter-port", default=8899, type=int,
		help="Port for the Jupyter server. Ignored if '-jupyter' is not also set.")
	parser.add_option(
		"--jupyter-password", default='abcloud',
		help="Password for the Jupyter server. Ignored if '-jupyter' is not also set.")
	parser.add_option(
		"--mongodb", action="store_true", default=False,
		help="Set up a MongoDB server on the master instance. Database will be located at <master-ebs_raid-dir>/db. " +
			 "At the current time, auth is not enabled when launching mongod.")
	# parser.add_option(
	# 	"--worker-instances", type="int", default=1,
	# 	help="Number of instances per worker: variable SPARK_WORKER_INSTANCES. Not used if YARN " +
	# 		 "is used as Hadoop major version (default: %default)")
	# parser.add_option(
	# 	"--master-opts", type="string", default="",
	# 	help="Extra options to give to master through SPARK_MASTER_OPTS variable " +
	# 		 "(e.g -Dspark.worker.timeout=180)")
	parser.add_option(
		"--user-data", type="string", default="",
		help="Path to a user-data file (most AMIs interpret this as an initialization script)")
	parser.add_option(
		"--authorized-address", type="string", default="0.0.0.0/0",
		help="Address to authorize on created security groups (default: %default)")
	parser.add_option(
		"--additional-security-group", type="string", default="",
		help="Additional security group to place the machines in")
	parser.add_option(
		"--copy-aws-credentials", action="store_true", default=False,
		help="Add AWS credentials to hadoop configuration to allow Spark to access S3")
	parser.add_option(
		"--subnet-id", default=None,
		help="VPC subnet to launch instances in")
	parser.add_option(
		"--vpc-id", default=None,
		help="VPC to launch instances in")
	parser.add_option(
		"--private-ips", action="store_true", default=False,
		help="Use private IPs for instances rather than public if VPC/subnet " +
			 "requires that.")

	(opts, args) = parser.parse_args()
	if len(args) != 2:
		parser.print_help()
		sys.exit(1)
	(action, cluster_name) = args

	# Boto config check
	# http://boto.cloudhackers.com/en/latest/boto_config_tut.html
	home_dir = os.getenv('HOME')
	if home_dir is None or not os.path.isfile(home_dir + '/.boto'):
		if not os.path.isfile('/etc/boto.cfg'):
			if os.getenv('AWS_ACCESS_KEY_ID') is None:
				print("ERROR: The environment variable AWS_ACCESS_KEY_ID must be set",
					  file=stderr)
				sys.exit(1)
			if os.getenv('AWS_SECRET_ACCESS_KEY') is None:
				print("ERROR: The environment variable AWS_SECRET_ACCESS_KEY must be set",
					  file=stderr)
				sys.exit(1)
	return (opts, action, cluster_name)


class UsageError(Exception):
	pass


def real_main():
	(opts, action, cluster_name) = parse_args()

	if not os.path.exists(opts.identity_file):
		print("ERROR: The identity file '{f}' doesn't exist.".format(f=opts.identity_file),
			  file=stderr)
		sys.exit(1)

		file_mode = os.stat(opts.identity_file).st_mode
		if not (file_mode & S_IRUSR) or not oct(file_mode)[-2:] == '00':
			print("ERROR: The identity file must be accessible only by you.", file=stderr)
			print('You can fix this with: chmod 400 "{f}"'.format(f=opts.identity_file),
				  file=stderr)
			sys.exit(1)

	if opts.instance_type not in EC2_INSTANCE_TYPES:
		print("Warning: Unrecognized EC2 instance type for instance-type: {t}".format(
			  t=opts.instance_type), file=stderr)

	if opts.master_instance_type != "":
		if opts.master_instance_type not in EC2_INSTANCE_TYPES:
			print("Warning: Unrecognized EC2 instance type for master-instance-type: {t}".format(
				  t=opts.master_instance_type), file=stderr)
		# Since we try instance types even if we can't resolve them, we check if they resolve first
		# and, if they do, see if they resolve to the same virtualization type.
		if opts.instance_type in EC2_INSTANCE_TYPES and \
		   opts.master_instance_type in EC2_INSTANCE_TYPES:
			if EC2_INSTANCE_TYPES[opts.instance_type] != \
			   EC2_INSTANCE_TYPES[opts.master_instance_type]:
				print("ERROR: ec2-cluster currently does not support having a master and workers "
					  "with different AMI virtualization types.", file=stderr)
				print("master instance virtualization type: {t}".format(
					  t=EC2_INSTANCE_TYPES[opts.master_instance_type]), file=stderr)
				print("worker instance virtualization type: {t}".format(
					  t=EC2_INSTANCE_TYPES[opts.instance_type]), file=stderr)
				sys.exit(1)

	if opts.ebs_vol_num > 8:
		print("The number of EBS volumes (--ebs-vol-num) cannot be greater than 8", file=stderr)
		sys.exit(1)

	# if not (opts.deploy_root_dir is None or
	# 		(os.path.isabs(opts.deploy_root_dir) and
	# 		 os.path.isdir(opts.deploy_root_dir) and
	# 		 os.path.exists(opts.deploy_root_dir))):
	# 	print("--deploy-root-dir must be an absolute path to a directory that exists "
	# 		  "on the local file system", file=stderr)
	# 	sys.exit(1)

	try:
		conn = ec2.connect_to_region(opts.region)
	except Exception as e:
		print((e), file=stderr)
		sys.exit(1)

	# Select an Availability Zone at random if it was not specified in opts.
	if not opts.zone:
		opts.zone = random.choice(conn.get_all_zones()).name

	if action == "launch":
		# Launch a new cluster
		if opts.workers < 0:
			print("ERROR: You can't start a negative number of workers.", file=sys.stderr)
			sys.exit(1)

		from utils.cluster import launch_cluster
		launch_cluster(conn, opts, cluster_name)

	elif action == "destroy":
		# Destroy an existing cluster
		from utils.cluster import destroy_cluster
		destroy_cluster(conn, opts, cluster_name)

	# elif action == "login":
	# 	# Login (via SSH) to an existing cluster
	# 	from utils.cluster import login
	# 	login(conn, opts, cluster_name)

	elif action == 'list':
		from utils.cluster import list_instances
		list_instances(conn, opts)

	elif action == "sshmaster":
		# Login (via SSH) to the master node on an existing cluster
		from utils.cluster import ssh_node
		ssh_node(conn, opts, cluster_name)

	elif action == "sshnode":
		# Login (via SSH) to a worker node on an existing cluster
		from utils.cluster import ssh_node
		ssh_node(conn, opts, cluster_name, node_type='node')

	elif action == "reboot-workers":
		# Reboot worker nodes on an existing cluster
		response = raw_input(
			"Are you sure you want to reboot the workers on {}?\n".format(cluster_name) +
			"Reboot " + cluster_name + " (y/N): ")
		if response.upper() == "Y":
			from utils.cluster import reboot_workers
			reboot_workers(conn, opts, cluster_name)
		else:
			print("Cluster reboot has been aborted.")
			sys.exit(1)

	elif action == "get-master":
		# Get public IP address of the master node
		(master_nodes, worker_nodes) = get_existing_cluster(conn, opts, cluster_name)
		if not master_nodes[0].public_dns_name and not opts.private_ips:
			print("Master has no public DNS name.  Maybe you meant to specify --private-ips?")
		else:
			print(get_dns_name(master_nodes[0], opts.private_ips))

	elif action == "stop":
		# Stop an existing cluster (diff from 'destroy' -- a stopped cluster can be restarted)
		response = raw_input(
			"Are you sure you want to stop  " + cluster_name +
			"?\nDATA ON EPHEMERAL DISKS WILL BE LOST, " +
			"BUT THE CLUSTER WILL KEEP USING SPACE ON\n" +
			"AMAZON EBS IF IT IS EBS-BACKED!!\n" +
			"All data on spot-instance workers will be lost.\n" +
			"Stop " + cluster_name + " (y/N): ")
		if response.upper() == "Y":
			from utils.cluster import stop_cluster
			stop_cluster(conn, opts, cluster_name, die_on_error=False)

	# Start an existing (but stopped) cluster
	elif action == "start":
		from utils.cluster import start_cluster
		start_cluster(conn, opts, cluster_name)

	else:
		print("Invalid action: %s" % action, file=stderr)
		sys.exit(1)


def main():
	try:
		real_main()
	except UsageError as e:
		print("\nError:\n", e, file=stderr)
		sys.exit(1)


if __name__ == "__main__":
	logging.basicConfig()
	main()
