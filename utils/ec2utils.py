#!/usr/bin/env python
# filename: ec2utils.py


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


from __future__ import print_function

import itertools
import sys


def get_or_make_group(conn, name, vpc_id):
	"""
	Get the EC2 security group of the given name,
	creating it if it doesn't exist
	"""
	groups = conn.get_all_security_groups()
	group = [g for g in groups if g.name == name]
	if len(group) > 0:
		return group[0]
	else:
		print("Creating security group " + name)
		return conn.create_security_group(name, "EC2 Cluster group", vpc_id)


def get_existing_cluster(conn, opts, cluster_name, die_on_error=True, quiet=False):
	"""
	Get the EC2 instances in an existing cluster if available.
	Returns a tuple of lists of EC2 instance objects for the masters and workers.
	"""
	if not quiet:
		print("\nSearching for existing cluster '{c}' in region {r}...".format(
			  c=cluster_name, r=opts.region))

	def get_instances(group_names):
		"""
		Get all non-terminated instances that belong to any of the provided security groups.

		EC2 reservation filters and instance states are documented here:
			http://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html#options
		"""
		reservations = conn.get_all_reservations(
			filters={"instance.group-name": group_names})
		instances = itertools.chain.from_iterable(r.instances for r in reservations)
		return [i for i in instances if i.state not in ["shutting-down", "terminated"]]

	master_instances = get_instances(['@abcloud-' + cluster_name + "-master"])
	worker_instances = get_instances(['@abcloud-' + cluster_name + "-workers"])

	if any((master_instances, worker_instances)):
		if not quiet:
			print("Found {m} master{plural_m} and {s} worker{plural_s}.".format(
				  m=len(master_instances),
				  plural_m=('' if len(master_instances) == 1 else 's'),
				  s=len(worker_instances),
				  plural_s=('' if len(worker_instances) == 1 else 's')))

	if not master_instances and die_on_error:
		print("ERROR: Could not find a master for cluster {c} in region {r}.".format(
			  c=cluster_name, r=opts.region), file=sys.stderr)
		sys.exit(1)

	return (master_instances, worker_instances)


def get_zones(conn, opts):
	"""
	Gets a list of zones in which instances should be launched.
	"""
	if opts.zone == 'all':
		zones = [z.name for z in conn.get_all_zones()]
	else:
		zones = [opts.zone]
	return zones


def get_partition(total, num_partitions, current_partitions):
	"""
	Gets the number of items in a partition.
	"""
	num_workers_this_zone = total // num_partitions
	if (total % num_partitions) - current_partitions > 0:
		num_workers_this_zone += 1
	return num_workers_this_zone


def get_ip_address(instance, private_ips=False):
	"""
	Gets the IP address, taking into account the --private-ips flag.
	"""
	ip = instance.ip_address if not private_ips else \
		instance.private_ip_address
	return ip


def get_dns_name(instance, private_ips=False):
	"""
	Gets the DNS name, taking into account the --private-ips flag.
	"""
	dns = instance.public_dns_name if not private_ips else \
		instance.private_ip_address
	return dns


def get_num_disks(instance_type):
	"""
	Get number of local disks available for a given EC2 instance type.
	Source: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html
	Last Updated: 2015-05-08
	For easy maintainability, please keep this manually-inputted dictionary sorted by key.
	"""
	disks_by_instance = {
		"c1.medium": 1,
		"c1.xlarge": 4,
		"c3.large": 2,
		"c3.xlarge": 2,
		"c3.2xlarge": 2,
		"c3.4xlarge": 2,
		"c3.8xlarge": 2,
		"c4.large": 0,
		"c4.xlarge": 0,
		"c4.2xlarge": 0,
		"c4.4xlarge": 0,
		"c4.8xlarge": 0,
		"cc1.4xlarge": 2,
		"cc2.8xlarge": 4,
		"cg1.4xlarge": 2,
		"cr1.8xlarge": 2,
		"d2.xlarge": 3,
		"d2.2xlarge": 6,
		"d2.4xlarge": 12,
		"d2.8xlarge": 24,
		"g2.2xlarge": 1,
		"g2.8xlarge": 2,
		"hi1.4xlarge": 2,
		"hs1.8xlarge": 24,
		"i2.xlarge": 1,
		"i2.2xlarge": 2,
		"i2.4xlarge": 4,
		"i2.8xlarge": 8,
		"m1.small": 1,
		"m1.medium": 1,
		"m1.large": 2,
		"m1.xlarge": 4,
		"m2.xlarge": 1,
		"m2.2xlarge": 1,
		"m2.4xlarge": 2,
		"m3.medium": 1,
		"m3.large": 1,
		"m3.xlarge": 2,
		"m3.2xlarge": 2,
		"r3.large": 1,
		"r3.xlarge": 1,
		"r3.2xlarge": 1,
		"r3.4xlarge": 1,
		"r3.8xlarge": 2,
		"t1.micro": 0,
		"t2.micro": 0,
		"t2.small": 0,
		"t2.medium": 0,
	}
	if instance_type in disks_by_instance:
		return disks_by_instance[instance_type]
	else:
		print("WARNING: Don't know number of disks on instance type %s; assuming 1"
			  % instance_type, file=stderr)
		return 1
