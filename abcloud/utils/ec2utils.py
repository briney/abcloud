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


from __future__ import print_function, absolute_import

from datetime import datetime
import itertools
import sys
import time

from abutils.utils import progbar

from .config import *


def get_or_make_vpc(ec2, ec2c, cluster_name, vpc_id, cidr_block):
    # TODO: Need to rework this. We're only allowed 5 VPCs, so it's not the best idea
    # to create a new VPC for each cluster. Instead, I should create a VPC only if there
    # isn't sufficient address space in all existing VPCs. This also means that I should
    # change the default subnet size (currently 10.0.0.0/16) to something more reasonable (otherwise
    # each new subnet will consume all of the address space in a VPC)
    if vpc_id is not None:
        print('\nSearching for VPC {}...'.format(vpc_id))
        vpc_ids = [v.id for v in ec2.vpcs.all()]
        if vpc_id in vpc_ids:
            print('Found VPC {}.'.format(vpc_id))
            return [v for v in ec2.vpcs.all() if v.id == vpc_id][0]
        else:
            print('VPC {} was not found.'.format(vpc_id))
    # check for an existing VPC
    all_vpcs = list(ec2.vpcs.all())
    cluster_vpcs = []
    for vpc in all_vpcs:
        if vpc.tags is None:
            continue
        tags = [tag['Value'] for tag in vpc.tags if tag['Key'] == 'Name' and tag['Value'] == cluster_name]
        if tags:
            cluster_vpcs.append(vpc)
    # if a VPC already exists, use that one
    if cluster_vpcs:
        vpc = cluster_vpcs[0]
        print('\nFound an existing VPC: {}'.format(vpc.id))
    # if a VPC doesn't exist, create a new one
    else:
        print('\nCreating a new VPC: ', end='')
        vpc = ec2.create_vpc(CidrBlock=cidr_block)
        # waiter = self.ec2c.get_waiter('vpc_available')
        # vpc_waiter.wait(VpcIds=[vpc.id])
        print(vpc.id)
        print('Naming the VPC')
        vpc.create_tags(Tags=[{'Key': 'Name', 'Value': cluster_name}])
    return vpc


def get_or_make_internet_gateway(ec2, vpc):
    print('\nLooking for an internet gateway in VPC {}'.format(vpc.id))
    igws = list(vpc.internet_gateways.all())
    # print('Existing gateways: {}'.format(', '.join([i.id for i in igws])))
    if igws:
        print('An gateway already exists and is attached to your VPC.')
        return igws[0]
    print('Creating an internet gateway: ', end='')
    igw = ec2.create_internet_gateway()
    print(igw.id)
    print('Attaching internet gateway to VPC')
    igw.attach_to_vpc(VpcId=vpc.id)
    return igw


def create_subnet(ec2, vpc, cidr_block):
   # check to make sure there's VPC address space to add the desired subnet
    vpc_addresses = 10**(32 - int(vpc.cidr_block.split('/')[1]))
    subnet_addresses = 0
    existing_cidrs = []
    for subnet in vpc.subnets.all():
        existing_cidrs.append(subnet.cidr_block)
        subnet_addresses += 10**(32 - int(subnet.cidr_block.split('/')[1]))
    available_addresses = vpc_addresses - subnet_addresses
    if available_addresses < 10**(32 - int(cidr_block.split('/')[1])):
        print('\n\nERROR: VPC does not have enough available addresses for a subnet \
            of the requested size ({})\n\n'.format(cidr_block))
        sys.exit()
    # check to see if the requested CIDR block is already in use
    print(existing_cidrs)
    if cidr_block in existing_cidrs:
        requested_cidr = cidr_block
        cidr_prefix = '.'.join(cidr_block.split('.')[:2]) + '.'
        cidr_suffix = '.' + cidr_block.split('.')[3]
        while cidr_block in existing_cidrs:
            cidr_counter = int(cidr_block.split('.')[2])
            cidr_block = cidr_prefix + str(cidr_counter + 1) + cidr_suffix
        print('Requested subnet CIDR block ({}) is already being used.'.format(requested_cidr))
        print('Using {} instead.'.format(cidr_block))
    # create the subnet
    return ec2.create_subnet(VpcId=vpc.id, CidrBlock=cidr_block)


def get_or_make_group(ec2, name, vpc_id=None, quiet=False):
    """
    Get the EC2 security group of the given name,
    creating it if it doesn't exist
    """
    groups = ec2.security_groups.all()
    groups = [g for g in groups if g.group_name == name and g.vpc_id == vpc_id]
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


def intracluster_auth(cluster):
    master = cluster.master_group
    worker = cluster.worker_group
    for group in [master, worker]:
        for src_group in [master, worker]:
            # group.authorize_ingress(SourceSecurityGroupName=src_group)
            group.authorize_ingress(IpPermissions=[{'IpProtocol': '-1',
                                                    'UserIdGroupPairs': [{'VpcId': cluster.vpc.id,
                                                                          'GroupId': src_group.id}]}])


def get_existing_instances(ec2, cluster_name, quiet=False):
    if not quiet:
        print("Searching for existing nodes in cluster '{}'...".format(cluster_name))
    master_instances = get_instances(ec2, '@abcloud-' + cluster_name + '-master')
    worker_instances = get_instances(ec2, '@abcloud-' + cluster_name + '-worker')
    return master_instances, worker_instances


def retrieve_existing_security_group(ec2, name):
    groups = ec2.security_groups.all()
    groups = [g for g in groups if g.group_name == name]
    if len(groups) == 0:
        return None
    return groups[0]


def get_availability_zones(ec2c):
    zone_names = []
    zresponse = ec2c.describe_availability_zones()
    for zone in zresponse['AvailabilityZones']:
        if zone['State'] == 'available':
            zone_names.append(zone['ZoneName'])
    return zone_names


def request_spot_instance(ec2c, group_name=None, price=None, num=1, ami=None,
        key_pair=None, subnet_id=None, instance_type=None, availability_zone=None,
        block_device_mappings=None, security_group_ids=None):
    '''
    docstring
    '''
    # check required kwargs
    reqs = [r is not None for r in [security_group_ids, price, ami, key_pair, instance_type]]
    if not all(reqs):
        err = 'ERROR: The following fields are required to request a spot instance:\n'
        err += 'group_name, price, ami, key_pair and instance_type'
        print(err)
        sys.exit(1)
    # build launch specification
    launch_spec = {'ImageId': ami,
                   'KeyName': key_pair,
                   # 'SecurityGroups': [group_name],
                   'InstanceType': instance_type,
                   'SubnetId': subnet_id,
                   'SecurityGroupIds': security_group_ids}
    if availability_zone:
        launch_spec['Placement'] = {'AvailabilityZone': availability_zone}
    if block_device_mappings:
        launch_spec['BlockDeviceMappings'] = block_device_mappings
    # request spot instances
    response = ec2c.request_spot_instances(
        SpotPrice=str(price),
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
        # total = len(instances)
        # finished = total - sum(pending)
        finished = len(instances) - sum(pending)
        progbar.progress_bar(finished, len(instances), start)
        time.sleep(15)
        response = ec2c.describe_instances(InstanceIds=instance_ids)
        instances = [i for r in response['Reservations'] for i in r['Instances']]
        states = [i['State']['Name'] for i in instances]
        pending = [s != state for s in states]
    progbar.progress_bar(len(instances), len(instances), start)


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
