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

from datetime import datetime
import itertools
import sys
import time

from abcloud.utils import progbar
from abcloud.utils.config import *


def get_or_make_group(ec2, name, vpc_id=None, quiet=False):
	"""
	Get the EC2 security group of the given name,
	creating it if it doesn't exist
	"""
	groups = ec2.security_groups.all()
	groups = [g for g in groups if g.group_name == name]
	if len(groups) > 0:
		return groups[0]
	else:
		if not quiet:
			print("Creating security group " + name)
		vpc_id = vpc_id if vpc_id is not None else ''
		sg = ec2.create_security_group(
			GroupName=name,
			Description='AbStar cluster group',
			VpcId=vpc_id)
		return sg


def get_instances(ec2, security_group_name=None):
	instances = list(ec2.instances.all())
	if security_group_name is None:
		return instances
	security_groups = [[g['GroupName'] for g in i.security_groups] for i in instances]
	return [i for i, sg in zip(instances, security_groups) if security_group_name in sg]


def authorize_ports(security_group, protocol, port_ranges, authorized_address):
	for from_port, to_port in port_ranges:
		security_group.authorize_ingress(
			IpProtocol=protocol,
			FromPort=int(from_port),
			ToPort=int(to_port),
			CidrIp=authorized_address)


def intracluster_auth(master, worker):
	for group in [master, worker]:
		for src_group in [master.group_name, worker.group_name]:
			group.authorize_ingress(SourceSecurityGroupName=src_group)


def get_existing_instances(ec2, cluster_name, quiet=False):
	if not quiet:
		print("Searching for existing nodes in cluster '{}'...".format(cluster_name))
	master_instances = get_instances(ec2, '@abcloud-' + cluster_name + '-master')
	worker_instances = get_instances(ec2, '@abcloud-' + cluster_name + '-worker')
	return master_instances, worker_instances


def get_availability_zones(ec2c):
	zone_names = []
	zresponse = ec2c.describe_availability_zones()
	for zone in zresponse['AvailabilityZones']:
		if zone['State'] == 'available':
			zone_names.append(zone['ZoneName'])
	return zone_names


def request_spot_instance(ec2c, group_name=None, price=None, num=1, ami=None,
		key_pair=None, instance_type=None, availability_zone=None,
		block_device_mappings=None):
	'''
	docstring
	'''
	# check required kwargs
	reqs = [r is not None for r in [group_name, price, ami, key_pair, instance_type]]
	if not all(reqs):
		err = 'ERROR: The following fields are required to request a spot instance:\n'
		err += 'group_name, price, ami, key_pair and instance_type'
		print(err)
		sys.exit(1)
	# build launch specification
	launch_spec = {'ImageId': ami,
				   'KeyName': key_pair,
				   'SecurityGroups': [group_name],
				   'InstanceType': instance_type}
	if availability_zone:
		launch_spec['Placement'] = {'AvailabilityZone': availability_zone}
	if block_device_mappings:
		launch_spec['BlockDeviceMappings'] = block_device_mappings
	# request spot instances
	response = ec2c.request_spot_instance(
		SpotPrice=price,
		InstanceCount=num,
		Type='one-time',
		LaunchSpecification=launch_spec)
	return response


def wait_for_instance_state(ec2c, instance_ids, state):
	print('')
	print("Waiting for instance{} to be in a '{}' state".format(
		's' if len(instance_ids) > 1 else '', state))
	start = datetime.now()
	response = ec2c.describe_instances(InstanceIds=instance_ids)
	instances = [i for r in response['Reservations'] for i in r['Instances']]
	states = [i['State']['Name'] for i in instances]
	pending = [s != state for s in states]
	while any(pending):
		total = len(instances)
		finished = total - sum(pending)
		progbar.progress_bar(finished, total, start)
		time.sleep(15)
		response = ec2c.describe_instances(InstanceIds=instance_ids)
		instances = [i for r in response['Reservations'] for i in r['Instances']]
		states = [i['State']['Name'] for i in instances]
		pending = [s != state for s in states]
	progbar.progress_bar(total, total, start)


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
		print("WARNING: Don't know number of disks on instance type {}; assuming 1".format(
			instance_type), file=stderr)
		return 1
