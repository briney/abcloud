#!/usr/bin/env python
# filename: cluster.py


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
import json
import multiprocessing as mp
import os
import random
import string
import subprocess
import sys
import time
import traceback

import boto3

import paramiko

from abutils.utils import progbar 
from abutils.utils.jobs import monitor_mp_jobs

from . import ec2utils
from .config import *

if sys.version_info[0] > 2:
    import pickle
    raw_input = input
else:
    import cPickle as pickle
    


class Cluster(object):
    """docstring for Cluster"""
    def __init__(self, name, opts=None, vpc=None, master_instance=None):
        super(Cluster, self).__init__()
        self.ec2 = boto3.resource('ec2')
        self.ec2c = boto3.client('ec2')
        self.name = name
        if opts is not None:
            self.opts = opts
        elif master_instance is not None:
            self.opts = self.retrieve_opts(master_instance)
        else:
            self.opts = None
        self._vpc = vpc
        self._internet_gateway = None
        self._subnet = None
        self._route_table = None
        self.master_group_name = '@abcloud-' + self.name + '-master'
        self.worker_group_name = '@abcloud-' + self.name + '-worker'
        self._master_group = None
        self._worker_group = None
        self._master = None
        self.master_name = None
        self.master_instance = None
        self._workers = None
        self._worker_names = None
        self._worker_instances = None
        self._image = None


    @property
    def vpc(self):
        if self._vpc is None:
            # check to see if security groups for the cluster have already been created
            # if so, use the VPC associated with the master security group
            master_sg_name = '@abcloud-' + self.name + '-master'
            master_group = ec2utils.retrieve_existing_security_group(self.ec2, master_sg_name)
            if master_group is not None:
                self._vpc = [v for v in self.ec2.vpcs.all() if v.id == master_group.vpc_id][0]
            else:
                # if we're launching a new cluster without workers, use the 'singletons' VPC
                if all([self.opts.action == 'launch', self.opts.workers == 0]):
                    vpc_name = 'singletons'
                else:
                    vpc_name = self.name
                self._vpc = ec2utils.get_or_make_vpc(self.ec2,
                                                     self.ec2c,
                                                     vpc_name,
                                                     self.opts.vpc_id,
                                                     self.opts.vpc_cidr_block)
            # Verify that the other VPC-related resources exist
            self.master_group
            self.worker_group
            self.internet_gateway
            self.subnet
            self.route_table
            # make sure the main route_table for the VPC directs traffic to the internet gateway
            # print('Adding route to the internet gateway in the main VPC route table')
            vpc_main_route_table = [r for r in self._vpc.route_tables.all() if any([a['Main'] for a in r.associations_attribute])][0]
            vpc_main_route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                              GatewayId=self.internet_gateway.id)
        return self._vpc

    @vpc.setter
    def vpc(self, vpc):
        self._vpc = vpc


    @property
    def internet_gateway(self):
        if self._internet_gateway is None:
            # print('Getting or making internet gateway')
            self._internet_gateway = ec2utils.get_or_make_internet_gateway(self.ec2, self.vpc)
        return self._internet_gateway

    @internet_gateway.setter
    def internet_gateway(setlf, igw):
        self._internet_gateway = igw


    @property
    def subnet(self):
        if self._subnet is None:
            # check for an existing subnet
            all_subnets = list(self.ec2.subnets.all())
            cluster_subnets = []
            existing_cidrs = []
            for subnet in all_subnets:
                existing_cidrs.append(subnet.cidr_block)
                if subnet.tags is None:
                    continue
                tags = [tag['Value'] for tag in subnet.tags if tag['Key'] == 'Name' and tag['Value'] == self.name]
                if tags:
                    cluster_subnets.append(subnet)
            # if a subnet already exists, use that one
            if cluster_subnets:
                # print('\nSubnet already exists for this cluster')
                self._subnet = cluster_subnets[0]
            else:
                cidr_block = self.opts.subnet_cidr_block
                if self.opts.subnet_cidr_block in existing_cidrs:
                    requested_cidr = self.opts.subnet_cidr_block
                    cidr_prefix = '.'.join(self.opts.subnet_cidr_block.split('.')[:2]) + '.'
                    cidr_suffix = '.' + self.opts.subnet_cidr_block.split('.')[3]
                    while self.opts.subnet_cidr_block in existing_cidrs:
                        cidr_counter = int(self.opts.subnet_cidr_block.split('.')[2])
                        self.opts.subnet_cidr_block = cidr_prefix + str(cidr_counter + 1) + cidr_suffix
                    print('\nRequested subnet CIDR block ({}) is already being used.'.format(requested_cidr))
                    print('Using {} instead.'.format(self.opts.subnet_cidr_block))
                print('\nCreating a new subnet: ', end='')
                self._subnet = self.ec2.create_subnet(VpcId=self.vpc.id,
                                                      CidrBlock=self.opts.subnet_cidr_block,
                                                      AvailabilityZone=self.opts.zone)
                subnet_waiter = self.ec2c.get_waiter('subnet_available')
                subnet_waiter.wait(SubnetIds=[self._subnet.id])
                print(self._subnet.id)
                self._subnet.create_tags(Tags=[{'Key': 'Name', 'Value': self.name}])
                print('Naming subnet')
                self.ec2c.modify_subnet_attribute(SubnetId=self._subnet.id,
                                                  MapPublicIpOnLaunch={'Value': True})
                print('Modifying subnet to map public IP addresses upon instance launch')
        return self._subnet

    @subnet.setter
    def subnet(self, subnet):
        self._subnet = subnet


    @property
    def route_table(self):
        if self._route_table is None:
            # check for an existing route table
            all_route_tables = list(self.ec2.route_tables.all())
            cluster_route_tables = []
            for route_table in all_route_tables:
                if route_table.tags is None:
                    continue
                tags = [tag['Value'] for tag in route_table.tags if tag['Key'] == 'Name' and tag['Value'] == self.name]
                if tags:
                    cluster_route_tables.append(route_table)
            # if a route table already exists, use that one
            if cluster_route_tables:
                # print('Route table already exists for this cluster')
                self._route_table = cluster_route_tables[0]
            else:
                print('Creating a new route table: ', end='')
                self._route_table = self.ec2.create_route_table(VpcId=self.vpc.id)
                print(self._route_table.id)
                print("Naming subnet's route table")
                self._route_table.create_tags(Tags=[{'Key': 'Name', 'Value': self.name}])
                print('Creating a route to the internet gateway')
                self._route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                               GatewayId=self.internet_gateway.id)
                print('Associating route table with the subnet')
                self._route_table.associate_with_subnet(SubnetId=self.subnet.id)
        return self._route_table


    @property
    def master_group(self):
        if self._master_group is None:
            # vpc_id = None if self.opts is None else self.opts.vpc_id
            self._master_group = ec2utils.get_or_make_group(
                self.ec2,
                self.master_group_name,
                vpc_id=self.vpc.id)
        return self._master_group

    @master_group.setter
    def master_group(self, security_group):
        self._master_group = security_group


    @property
    def worker_group(self):
        if self._worker_group is None:
            # vpc_id = None if self.opts is None else self.opts.vpc_id
            self._worker_group = ec2utils.get_or_make_group(
                self.ec2,
                self.worker_group_name,
                vpc_id=self.vpc.id)
        return self._worker_group

    @worker_group.setter
    def worker_group(self, security_group):
        self._worker_group = security_group


    @property
    def master(self):
        if self._master is None:
            return {}
        return self._master

    @master.setter
    def master(self, master):
        self._master = master


    @property
    def workers(self):
        if self._workers is None:
            return {}
        return self._workers

    @workers.setter
    def workers(self, workers):
        self._workers = workers


    @property
    def worker_names(self):
        if self._worker_names is None:
            return []
        return self._worker_names

    @worker_names.setter
    def worker_names(self, worker_names):
        self._worker_names = worker_names


    @property
    def worker_instances(self):
        if self._worker_instances is None:
            return []
        return self._worker_instances

    @worker_instances.setter
    def worker_instances(self, worker_instances):
        self._worker_instances = worker_instances


    @property
    def image(self):
        if self._image is None:
            # TODO - parse the image from master instance,
            # probably through the ec2utils module
            pass
        return self._image

    @image.setter
    def image(self, image):
        self._image = image


    def _retrieve_vpc(self, vpc_id):
        if vpc_id is None:
            return None
        vpcs = [v for v in self.vpcs.all() if v.id == vpc_id]
        if vpcs:
            return vpcs[0]
        return None


    def _retrieve_subnet(self, subnet_id):
        if subnet_id is None:
            return None
        subnets = [s for s in self.subnets.all() if s.id == subnet_id]
        if subnets:
            return subnets[0]
        return None


    def _retrieve_internet_gateway(self, internet_gateway_id):
        if internet_gateway_id is None:
            return None
        internet_gateways = [i for i in self.internet_gateways.all() if i.id == internet_gateway_id]
        if internet_gateways:
            return internet_gateways[0]
        return None


    def _retrieve_route_table(self, route_table_id):
        if route_table_id is None:
            return None
        route_tables = [r for r in self.route_tables.all() if r.id == route_table_id]
        if route_tables:
            return route_tables[0]
        return None


    def load(self):
        masters, workers = ec2utils.get_existing_instances(
            self.ec2,
            self.name,
            quiet=True)
        masters = [m for m in masters if m.state['Name'] == 'running']
        workers = [w for w in workers if w.state['Name'] == 'running']
        if not masters:
            return self
        self.master_instance = masters[0]
        self.worker_instances = workers

        # get master instance information
        if self.master_instance.tags is not None:
            self.master_name = [d['Value'] for d in self.master_instance.tags if 'Name' in d.values()][0]
        else:
            self.master_name = 'master'
        self.master = {self.master_name: self.master_instance}

        # get worker instance information
        self.workers = {}
        for count, i in enumerate(self.worker_instances):
            if i.tags is not None:
                worker_name = [d['Value'] for d in i.tags if 'Name' in d.values()][0]
            else:
                worker_name = 'node{}'.format(count)
            self.workers[worker_name] = i
        self.worker_names = sorted(list(self.workers.keys()))


    def launch(self):
        print('')
        # authorize ingress ports for master and worker security groups
        auth_master = False if len(self.master_group.ip_permissions) > 0 else True
        auth_worker = False if len(self.worker_group.ip_permissions) > 0 else True
        if any([auth_master, auth_worker]):
            ec2utils.intracluster_auth(self)
        if auth_master:
            ec2utils.authorize_ports(
                self.master_group,
                'tcp',
                MASTER_TCP_PORT_RANGES,
                self.opts.authorized_address)
            ec2utils.authorize_ports(
                self.master_group,
                'udp',
                MASTER_UDP_PORT_RANGES,
                self.opts.authorized_address)
        if auth_worker:
            ec2utils.authorize_ports(
                self.worker_group,
                'tcp',
                WORKER_TCP_PORT_RANGES,
                self.opts.authorized_address)

        # check whether instances are already running in the cluster security groups
        print('')
        masters, workers = ec2utils.get_existing_instances(self.ec2, self.name)
        masters = [m for m in masters if m.state['Name'] not in ['shutting-down', 'terminated']]
        workers = [w for w in workers if w.state['Name'] not in ['shutting-down', 'terminated']]
        if any([workers, masters]):
            print("ERROR: There are already instances running in group {} or {}".format(
                self.master_group.group_name,
                self.worker_group.group_name),
                file=sys.stderr)
            sys.exit(1)
        else:
            print('No running instances were found.')

        # get AMI
        if self.opts.ami is None:
            self.opts.ami = UBUNTU_AMI_MAP[self.opts.region]
        try:
            self.image = [i for i in self.ec2.images.filter(ImageIds=[self.opts.ami])][0]
        except:
            print("Could not find AMI " + self.opts.ami, file=sys.stderr)
            sys.exit(1)

        # setup master BlockDeviceMappings
        master_block_device_mappings = []
        # first thing to add to master_block_device_mapping is the root volume
        root_map = {'DeviceName': '/dev/sda1', 'Ebs': {'VolumeSize': self.opts.master_root_vol_size,
                                                       'VolumeType': 'gp2'}}
        master_block_device_mappings.append(root_map)
        for i in range(self.opts.master_ebs_vol_num):
            # EBS volumes are /dev/xvdaa, /dev/xvdab...
            device_name = "/dev/xvda" + string.ascii_lowercase[i]
            ebs = {'VolumeSize': self.opts.master_ebs_vol_size,
                   'VolumeType': self.opts.master_ebs_vol_type}
            device_map = {'DeviceName': device_name,
                          'Ebs': ebs}
            master_block_device_mappings.append(device_map)
        # ephemeral drives must be added to the BlockDeviceMappings for m3 instances
        # see: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html
        if self.opts.master_instance_type is None:
            self.opts.master_instance_type = self.opts.instance_type
        if self.opts.master_instance_type.split('.')[0] in ['m3', ]:
            for i in range(ec2utils.get_num_disks(self.opts.master_instance_type)):
                virtual_name = 'ephemeral{}'.format(i)
                # ephemeral drives start at /dev/xvdb.
                device_name = '/dev/xvd' + string.ascii_lowercase[i + 1]
                device_map = {'VirtualName': virtual_name,
                              'DeviceName': device_name}
                master_block_device_mappings.append(device_map)

        # launch workers
        if self.opts.workers > 0:
            if self.opts.spot_price:
                print('')
                print('Requesting {0} spot instance{1} for worker node{1}...'.format(
                    self.opts.workers, '' if self.opts.workers == 1 else 's'))
                worker_response = ec2utils.request_spot_instance(
                    self.ec2c,
                    # group_name=self.worker_group_name,
                    price=self.opts.spot_price,
                    ami=self.opts.ami,
                    num=self.opts.workers,
                    key_pair=self.opts.key_pair,
                    instance_type=self.opts.instance_type,
                    subnet_id=self.subnet.id,
                    security_group_ids=[self.worker_group.id, ])
            else:
                worker_response = {'SpotInstanceRequests': []}
                self.worker_instances = self.ec2.create_instances(
                    ImageId=self.opts.ami,
                    MinCount=self.opts.workers,
                    MaxCount=self.opts.workers,
                    KeyName=self.opts.key_pair,
                    InstanceType=self.opts.instance_type,
                    SecurityGroupIds=[self.worker_group.id],
                    SubnetId=self.subnet.id)
        else:
            worker_response = {'SpotInstanceRequests': []}

        # launch masters
        if all([self.opts.force_spot_master, self.opts.spot_price is not None]):
            print('Requesting a spot instance for master node...')
            master_response = ec2utils.request_spot_instance(
                self.ec2c,
                # group_name=self.master_group_name,
                price=self.opts.spot_price,
                ami=self.opts.ami,
                num=1,
                key_pair=self.opts.key_pair,
                instance_type=self.opts.master_instance_type,
                subnet_id=self.subnet.id,
                security_group_ids=[self.master_group.id, ],
                block_device_mappings=master_block_device_mappings)
        else:
            master_response = {'SpotInstanceRequests': []}
            master_instances = self.ec2.create_instances(
                ImageId=self.opts.ami,
                MinCount=1,
                MaxCount=1,
                KeyName=self.opts.key_pair,
                InstanceType=self.opts.master_instance_type,
                SecurityGroupIds=[self.master_group.id, ],
                SubnetId=self.subnet.id,
                BlockDeviceMappings=master_block_device_mappings)
            self.master_instance = master_instances[0]

        # wait for spot requests to be fulfilled
        master_requests = master_response['SpotInstanceRequests']
        worker_requests = worker_response['SpotInstanceRequests']
        spot_requests = master_requests + worker_requests
        if spot_requests:
            # wait for AWS to populate the list of spot instance requests
            time.sleep(10)
            print('')
            print('Waiting for spot requests to be fulfulled...')
            spot_request_ids = [r['SpotInstanceRequestId'] for r in spot_requests]
            waiter = self.ec2c.get_waiter('spot_instance_request_fulfilled')
            waiter.wait(SpotInstanceRequestIds=spot_request_ids)
        if master_requests:
            master_requests = self.ec2c.describe_spot_instance_requests(
                SpotInstanceRequestIds=[r['SpotInstanceRequestId'] for r in master_requests])
            master_instance_ids = [r['InstanceId'] for r in master_requests['SpotInstanceRequests']]
            self.master_instance = [self.ec2.Instance(id=i) for i in master_instance_ids][0]
        if worker_requests:
            worker_requests = self.ec2c.describe_spot_instance_requests(
                SpotInstanceRequestIds=[r['SpotInstanceRequestId'] for r in worker_requests])
            worker_instance_ids = [r['InstanceId'] for r in worker_requests['SpotInstanceRequests']]
            self.worker_instances = [self.ec2.Instance(id=i) for i in worker_instance_ids]

        # wait for instances to state == 'running'
        all_instances = [self.master_instance] + self.worker_instances
        ec2utils.wait_for_instance_state(self.ec2c, [i.id for i in all_instances], 'running')

        # wait for instances to be reachable
        print('')
        print('Waiting for instance{} to be reachable...'.format(
            's' if len(all_instances) > 1 else ''))
        instance_ids = [i.id for i in all_instances]
        waiter = self.ec2c.get_waiter('instance_status_ok')
        waiter.wait(InstanceIds=instance_ids)

        # name all instances
        if self.opts.workers:
            self.workers = {}
            self.master_name = 'master'
            self.worker_names = []
            self.master = {self.master_name: self.master_instance}
            self.master_instance.create_tags(Tags=[{'Key': 'Name',
                                                    'Value': 'master'}])
            for i, inst in enumerate(self.worker_instances):
                zeros = 3 - len(str(i + 1))
                name = 'node{}{}'.format('0' * zeros, i + 1)
                self.workers[name] = inst
                self.worker_names.append(name)
                inst.create_tags(Tags=[{'Key': 'Name',
                                        'Value': name}])
        else:
            self.master_name = self.name
            self.worker_names = []
            self.master = {self.master_name: self.master_instance}
            self.master_instance.create_tags(Tags=[{'Key': 'Name',
                                                    'Value': self.master_name}])

        # configure the cluster instances
        self.configure()


    def destroy(self):
        self.terminate()
        print('Retrieving cluster configuration information...')
        self.vpc
        print('')
        print('Deleting security groups (this may take some time)...')
        # remove rules from security groups before deleting
        print('Deleting rules in {}'.format(self.master_group_name))
        master_permissions = self.master_group.ip_permissions
        for p in master_permissions:
            for u in p['UserIdGroupPairs']:
                u['GroupName'] = ''
        self.master_group.revoke_ingress(IpPermissions=master_permissions)
        print('Deleting rules in {}'.format(self.worker_group_name))
        worker_permissions = self.worker_group.ip_permissions
        for p in worker_permissions:
            for u in p['UserIdGroupPairs']:
                u['GroupName'] = ''
        self.worker_group.revoke_ingress(IpPermissions=worker_permissions)
        # delete security groups
        print('Deleting {}'.format(self.master_group_name))
        self.master_group.delete()
        print('Deleting {}'.format(self.worker_group_name))
        self.worker_group.delete()
        # delete subnet
        print('')
        print('Deleting subnet...')
        subnet_id = self.subnet.id
        self.subnet.delete()
        subnet_ids = [s.id for s in self.vpc.subnets.all()]
        print('Waiting for subnet to be gone')
        while subnet_id in subnet_ids:
            subnet = [s for s in self.vpc.subnets.all() if s.id == subnet_id][0]
            print('Subnet state: {}'.format(subnet.state))
            time.wait(10)
            subnet_ids = [s.id for s in vpc.subnets.all()]
            # print(', '.join(subnet_ids))
        # delete route table
        print('Deleting route table...')
        self.route_table.delete()
        # we only want to delete the internet gateway and VPC
        # if no other subnets exist in the VPC.
        if self.vpc.subnets.all():
            print('Additional subnets exist within VPC {}, so the VPC and internet gateway will not be deleted.'.format(self.vpc.id))
            subnet_ids = [s.id for s in self.vpc.subnets.all()]
            # print(', '.join(subnet_ids))
        else:
            # delete internet gateway
            print('Deleting internet gateway...')
            self.internet_gateway.detach_from_vpc(VpcId=self.vpc.id)
            self.internet_gateway.delete()
            # delete VPC
            print('Deleting VPC...')
            self.vpc.delete()
        print('\n\n')


    def terminate(self):
        terminate_string = 'TERMINATING CLUSTER: {}'.format(self.name)
        print('')
        print('-' * (len(terminate_string) + 4))
        print('  ' + terminate_string)
        print('-' * (len(terminate_string) + 4))
        print('')
        all_instances = list(self.master.items()) + list(self.workers.items())
        if any(all_instances):
            for name, instance in all_instances:
                print("> {} ({})".format(name, instance.public_dns_name))
            print('')
            print('WARNING: ALL DATA ON ALL NODES WILL BE LOST!!')
        msg = 'Are you sure you want to terminate this cluster? (y/N) '
        response = raw_input(msg)
        if response.upper() == 'Y':
            if any(all_instances):
                instances = [instance for name, instance in all_instances]
                self.terminate_instances(self.ec2c, instances)
        else:
            print('\nAborting cluster termination.\n\n')
            sys.exit()

    @staticmethod
    def terminate_instances(ec2c, instances):
        print('')
        print('Terminating instances...')
        for instance in instances:
            instance.terminate()
        waiter = ec2c.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=[i.id for i in instances])


    def ssh(self, node_name=None):
        if node_name is None or node_name.lower() == 'master':
            node_name = list(self.master.keys())[0]
            instance = self.master[node_name]
        else:
            if node_name not in self.workers:
                err = 'ERROR: the supplied node name ({}) does not exist'.format(
                    node_name)
                raise RuntimeError(err)
            instance = self.workers[node_name]
        inst_ip = instance.public_ip_address
        print('')
        print('Logging into node {}...'.format(node_name))
        cmd = self.ssh_cmd(self.opts.identity_file)
        cmd += ['-t', '-t', '{}@{}'.format(self.opts.user, inst_ip)]
        try:
            subprocess.check_call(cmd, stderr=subprocess.PIPE)
        except:
            pass

    @staticmethod
    def ssh_cmd(identity_file):
        cmd = ['ssh']
        cmd += ['-o', 'StrictHostKeyChecking=no']
        cmd += ['-o', 'UserKnownHostsFile=/dev/null']
        cmd += ['-i', identity_file]
        return cmd

    @staticmethod
    def scp_cmd(identity_file):
        cmd = ['scp']
        cmd += ['-o', 'StrictHostKeyChecking=no']
        cmd += ['-o', 'UserKnownHostsFile=/dev/null']
        cmd += ['-i', identity_file]
        return cmd


    def run(self, instance, cmd, stdin=None):
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                instance.public_ip_address,
                username=self.opts.user,
                key_filename=self.opts.identity_file)
            _stdin, stdout, stderr = ssh.exec_command(cmd)
            if stdin is not None:
                _stdin.write(stdin)
            while not stdout.channel.exit_status_ready():
                time.sleep(1)
        return stdout.read(), stderr.read()


    def put(self, node_name, local, remote):
        if node_name in ['master', self.master_name]:
            instance = self.master_instance
        elif node_name in self.worker_names:
            instance = self.workers[node_name]
        else:
            err = 'Node name {} cannot be found in this cluster'.format(
                node_name)
            raise RuntimeError(err)
        mkdir_cmd = 'sudo mkdir -p {0} && sudo chmod 777 {0}'.format(
            os.path.dirname(remote))
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(instance.public_ip_address,
                username=self.opts.user,
                key_filename=self.opts.identity_file)
            ssh.exec_command(mkdir_cmd)
        scp_cmd = self.scp_cmd(self.opts.identity_file)
        scp_cmd += [local]
        scp_cmd += ['{}@{}:{}'.format(self.opts.user, instance.public_ip_address, remote)]
        subprocess.check_call(scp_cmd, stderr=subprocess.PIPE)


    def get(self, node_name, remote, local):
        if node_name in ['master', self.master_name]:
            instance = self.master_instance
        elif node_name in self.worker_names:
            instance = self.workers[node_name]
        else:
            err = 'Node name {} cannot be found in this cluster'.format(
                node_name)
            raise RuntimeError(err)
        scp_cmd = self.scp_cmd(self.opts.identity_file)
        scp_cmd += ['{}@{}:{}'.format(self.opts.user, instance.public_ip_address, remote)]
        scp_cmd += [local]
        subprocess.check_call(scp_cmd, stderr=subprocess.PIPE)


    def tunnel(self, node_name, args):
        print('')
        print('Forwarding port {} to {}'.format(
            args.port,
            args.tunnel_server))
        if node_name in ['master', self.master_name]:
            instance = self.master_instance
        elif node_name in self.worker_names:
            instance = self.workers[node_name]
        tunnel_cmd = 'ssh_tunnel -p {} -u {}'.format(
            args.port,
            args.tunnel_user)
        tunnel_cmd += ' -r {}'.format(args.remote_server)
        if args.tunnel_keyfile is not None:
            tunnel_cmd += ' -k {}'.format(args.tunnel_keyfile)
        else:
            tunnel_cmd += ' --no-key'
        if args.tunnel_password:
            tunnel_cmd += ' -P {}'.format(args.tunnel_password)
        tunnel_cmd += ' {}'.format(args.tunnel_server)
        cmd = '''screen -d -m bash -c "{}"'''.format(tunnel_cmd)
        self.run(instance, cmd)


    def configure(self):
        instances = [self.master_instance] + self.worker_instances
        instance_lookup = dict(self.master, **self.workers)
        instance_names = sorted(list(instance_lookup.keys()))

        # build base image
        print('')
        if len(instances) == 1:
            print('Building base image...')
            configure_base_image(instances[0].public_ip_address,
                                 self.opts.user,
                                 self.opts.identity_file,
                                 self.opts.debug)
        else:
            print('Building base image on all nodes...')
            p = mp.Pool(len(instances))
            async_results = []
            for instance in instances:
                async_results.append(p.apply_async(configure_base_image,
                                                   args=(instance.public_ip_address,
                                                         self.opts.user,
                                                         self.opts.identity_file,
                                                         self.opts.debug)))
            monitor_mp_jobs(async_results)
            p.close()
            p.join()

        # deploy SSH key to nodes for passwordless SSH
        print('')
        print("Generating cluster's SSH key on master...")
        key_setup = """
            [ -f ~/.ssh/id_rsa ] ||
            (ssh-keygen -q -t rsa -N '' -f ~/.ssh/id_rsa &&
            cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys)"""
        self.run(self.master_instance, key_setup)
        get_ssh_tar = 'tar c - .ssh'
        dot_ssh_tar, _ = self.run(self.master_instance, get_ssh_tar)
        if self.worker_instances:
            print("Transferring SSH key to workers:")
            put_ssh_tar = 'tar x'
            for i, worker in enumerate(self.worker_instances):
                progbar.progress_bar(i, len(self.worker_instances))
                self.run(worker, put_ssh_tar, stdin=dot_ssh_tar)
            progbar.progress_bar(len(self.worker_instances), len(self.worker_instances))
            print('')

        # modify /etc/hosts on all nodes
        print('\nUpdating /etc/hosts on all nodes...')
        hosts = ['{} {}'.format(self.get_ip(i), n) for n, i in instance_lookup.items()]
        host_string = '\n'.join(hosts)
        host_cmd = """sudo -- sh -c 'echo "{}" >> /etc/hosts'""".format(host_string)
        for instance in instances:
            self.run(instance, host_cmd)

        # build and share an EBS volumne on the master node
        devices = ['/dev/xvda' + string.ascii_lowercase[i] for i in range(self.opts.master_ebs_vol_num)]
        if len(devices) > 1:
            volume = self.build_ebs_raid_volume(devices)
        elif len(devices) == 1:
            volume = self.format_single_ebs_device(devices[0])
        if len(self.worker_instances) > 0:
            self.share_nfs_volume(volume)

        # start Celery workers on all nodes
        if self.opts.celery and len(self.worker_instances) > 0:
            self.start_redis_server(self.master_instance)
            self.start_celery_workers(self.worker_instances)
            self.start_flower()

        # upload BaseSpace credentials file
        if self.opts.basespace_credentials:
            print('')
            print('Uploading BaseSpace credentials file...')
            cred_file = os.path.expanduser('~/.abstar/basespace_credentials')
            remote_path = '/home/{}/.abstar/basespace_credentials'.format(self.opts.user)
            if os.path.exists(cred_file):
                self.put(self.master_name, cred_file, remote_path)
            else:
                print('ERROR: Local credentials file was not found. No credentials were uploaded.')

        # configure and start a Jupyter Notebook server
        if self.opts.jupyter:
            self.setup_jupyter_notebook()

        # configure and start a MongoDB server
        if self.opts.mongodb:
            self.setup_mongodb()
        else:
            self.stop_mongod()

        # write config information to master
        self.write_config_info()
        print('')


    def get_ip(self, instance):
        if self.opts.private_ips:
            return instance.private_ip_address
        else:
            return instance.public_ip_address


    def build_ebs_raid_volume(self, devices, node_name=None, mount=None, raid_level=None):
        if node_name is None or node_name.lower == 'master':
            node_name = self.master_name
            instance = self.master_instance
        else:
            if node_name not in self.worker_names:
                print('\nERROR: EBS was not configured on {} because the supplied node name is not a worker.'.format(node_name))
                # sys.exit(1)
                return mount
            instance = self.workers[node_name]
        mount = mount if mount is not None else self.opts.master_ebs_raid_dir
        raid_level = raid_level if raid_level else self.opts.master_ebs_raid_level
        print('')
        print('Building a {}-member RAID{} array on {}...'.format(
            len(devices),
            raid_level,
            node_name))
        raid_cmd = 'sudo mdadm --verbose --create /dev/md0 '
        raid_cmd += '--level={} --chunk=256 --raid-devices={} {}'.format(
            raid_level,
            len(devices),
            ' '.join(devices))
        # MongoDB prefers a readahead of 32 (16KB)
        if self.opts.mongodb:
            for device in devices:
                raid_cmd += '&& sudo blockdev --setra 32 {} '.format(device)
        raid_cmd += "&& sudo dd if=/dev/zero of=/dev/md0 bs=512 count=1 \
            && sudo pvcreate /dev/md0 \
            && sudo vgcreate vg0 /dev/md0 "
        if self.opts.mongodb:
            raid_cmd += "&& sudo lvcreate -l 90%vg -n data vg0 \
               && sudo lvcreate -l 5%vg -n journal vg0 \
               && sudo lvcreate -l 5%vg -n log vg0 \
               && sudo mke2fs -t ext4 -F /dev/vg0/data \
               && sudo mke2fs -t ext4 -F /dev/vg0/journal \
               && sudo mke2fs -t ext4 -F /dev/vg0/log \
               && sudo mkdir /log \
               && sudo mkdir /journal \
               && echo '/dev/vg0/journal /journal ext4 defaults,auto,noatime,noexec 0 0' | sudo tee -a /etc/fstab \
               && echo '/dev/vg0/log /log ext4 defaults,auto,noatime,noexec 0 0' | sudo tee -a /etc/fstab \
               && sudo mount /journal \
               && sudo mount /log \
               && sudo chmod 777 /journal \
               && sudo chmod 777 /log "
        else:
            raid_cmd += "&& sudo lvcreate -l 100%vg -n data vg0 \
               && sudo mke2fs -t ext4 -F /dev/vg0/data "
        raid_cmd += "&& sudo mkdir {0} \
           && echo '/dev/vg0/data {0} ext4 defaults,auto,noatime,noexec 0 0' | sudo tee -a /etc/fstab \
           && sudo mount {0} \
           && sudo chmod 777 {0}".format(mount)
        self.run(instance, raid_cmd)
        return mount


    def format_single_ebs_device(self, device, node_name=None, mount=None):
        if node_name is None or node_name.lower == 'master':
            node_name = self.master_name
            instance = self.master_instance
        else:
            if node_name not in self.worker_names:
                print('\nERROR: EBS was not configured on {} because the supplied node name is not a worker.'.format(node_name))
                # sys.exit(1)
                return mount
            instance = self.workers[node_name]
        mount = mount if mount is not None else self.opts.master_ebs_raid_dir
        print('')
        print('Formatting an EBS volume on {}...'.format(node_name))
        fmt_cmd = 'sudo mke2fs -t ext4 -F {} '.format(device)
        fmt_cmd += '&& sudo mkdir {} '.format(mount)
        fmt_cmd += "&& echo '{} {} ext4 defaults,auto,noatime,noexec 0 0' | sudo tee -a /etc/fstab ".format(
            device, mount)
        fmt_cmd += '&& sudo mount {0} && sudo chmod 777 {0}'.format(mount)
        self.run(instance, fmt_cmd)
        return mount


    def share_nfs_volume(self, volume):
        print('Adding workers to /etc/exports on master node...')
        for node_name in [self.master_name] + self.worker_names:
            export_cmd = """sudo -- sh -c 'echo "{} {}(async,no_root_squash,no_subtree_check,rw)" >> /etc/exports'""".format(
                volume, node_name)
            self.run(self.master_instance, export_cmd)
        nfs_start_cmd = 'sudo exportfs -a && sudo /etc/init.d/nfs-kernel-server start'
        self.run(self.master_instance, nfs_start_cmd)
        print('Mounting NFS share ({}:{}) on each node:'.format(
            self.master_name, volume))
        nfs_mount_cmd = "sudo mkdir {0} && sudo mount {1}:{0} {0} && sudo chmod 777 {0}".format(
            volume, self.master_name)
        run_ssh_multi(nfs_mount_cmd,
                      self.worker_instances,
                      self.opts.user,
                      self.opts.identity_file)


    def start_redis_server(self, instance):
        redis_conf = 'daemonize yes\npidfile /var/run/redis_6379.pid\n'
        redis_conf += 'port 6379\nlogfile /var/redis/redis_6379.log\ndir /var/redis/6379'
        redis_cmd = "sudo mkdir /etc/redis \
            && sudo mkdir /var/redis \
            && sudo chmod 777 /var/redis \
            && sudo mkdir /var/redis/6379 \
            && printf '{}' | sudo tee /etc/redis/6379.conf \
            && /home/ubuntu/anaconda3/bin/redis-server /etc/redis/6379.conf".format(redis_conf)
        self.run(instance, redis_cmd)


    def start_celery_workers(self, instances):
        print('')
        print('Starting Celery worker processes:')
        celery_cmd = '/home/ubuntu/anaconda3/bin/celery '
        celery_cmd += '-A abstar.utils.queue.celery worker -l info --detach'
        run_ssh_multi(celery_cmd,
                      self.worker_instances,
                      self.opts.user,
                      self.opts.identity_file)


    def start_flower(self):
        print('')
        print('Starting Flower server on master...')
        flower_cmd = '''/home/ubuntu/anaconda3/bin/pip install flower \
            && screen -d -m bash -c "/home/ubuntu/anaconda3/bin/flower -A abstar.utils.queue.celery"'''
        self.run(self.master_instance, flower_cmd)
        print('Flower URL: http://{}:5555'.format(self.master_instance.public_ip_address))


    def setup_jupyter_notebook(self):
        print('')
        print('Launching a Jupyter Notebook server on {}...'.format(
            self.master_name))

        # hash/salt the Jupyter login password
        sha1_py = 'from notebook.auth import passwd; print(passwd("{}"))'.format(
            self.opts.jupyter_password)
        sha1_cmd = "/home/ubuntu/anaconda3/bin/python -c '{}'".format(sha1_py)
        raw_passwd = self.run(self.master_instance, sha1_cmd)[0].strip()
        if sys.version_info[0] > 2:
            passwd = raw_passwd.decode('utf-8')
        else:
            passwd = raw_passwd

        # make a new Jupyter profile and directory; edit the config
        create_profile_cmd = '/home/ubuntu/anaconda3/bin/jupyter notebook --generate-config'
        self.run(self.master_instance, create_profile_cmd)
        if self.opts.master_ebs_vol_num > 0:
            notebook_dir = os.path.join(self.opts.master_ebs_raid_dir, 'jupyter')
        else:
            notebook_dir = '/home/ubuntu/jupyter'
        mkdir_cmd = 'sudo mkdir {0} && sudo chmod 777 {0}'.format(notebook_dir)
        self.run(self.master_instance, mkdir_cmd)
        profile_config_string = '\n'.join([
            "c.NotebookApp.ip = '*'",
            "c.NotebookApp.open_browser = False",
            "c.NotebookApp.password = u'%s'" % passwd,
            "c.NotebookApp.port = 8899"])
        profile_config_cmd = 'echo "{}" '.format(profile_config_string)
        profile_config_cmd += '| sudo tee /home/ubuntu/.jupyter/jupyter_notebook_config.py'
        self.run(self.master_instance, profile_config_cmd)

        # start a backgroud Jupyter instance
        jupyter_start_cmd = "/home/ubuntu/anaconda3/bin/jupyter notebook --notebook-dir={} > /dev/null 2>&1 &".format(notebook_dir)
        self.run(self.master_instance, jupyter_start_cmd)
        print("Jupyter notebook URL: http://{}:{}".format(self.master_instance.public_ip_address, 8899))
        print("Password for the Jupyter notebook is '{}'".format(self.opts.jupyter_password))


    def setup_mongodb(self):
        print('')
        print('Configuring MongoDB on master...')

        # prepare MongoDB's database directory
        dbpath = os.path.join(self.opts.master_ebs_raid_dir, 'db')
        init_cmd = ' && '.join([
            'sudo service mongod stop',
            'sudo mkdir %s' % dbpath,
            'sudo chmod 777 %s' % dbpath,
            'sudo useradd mongod',
            'sudo chown mongod:mongod /data /journal /log',
            'sudo ln -s /journal /data/journal'])
        self.run(self.master_instance, init_cmd)

        # start mongod
        print('Starting mongod...')
        mongod_start_cmd = 'mongod --fork --logpath /log/mongod.log '
        mongod_start_cmd += '--dbpath {} --rest --bind_ip 0.0.0.0'.format(dbpath)
        self.run(self.master_instance, mongod_start_cmd)
        print('MongoDB database location: {}'.format(dbpath))
        print('MongoDB log location: /log/mongod.log')


    def stop_mongod(self):
        mongod_stop_cmd = 'sudo service mongod stop'
        self.run(self.master_instance, mongod_stop_cmd)


    def write_config_info(self):
        # pickle the cluster's opts
        opts_file = '/home/ubuntu/.abcloud_opts'
        pstring = pickle.dumps(self.opts)
        write_opts_cmd = "sudo echo '{}' >> {}".format(pstring, opts_file)
        self.run(self.master_instance, write_opts_cmd)

        # write cluster parameters
        config_file = '/home/ubuntu/.abcloud_config'
        config = {}
        config['vpc_id'] = self.vpc.id
        config['subnet_id'] = self.subnet.id
        config['internet_gateway_id'] = self.internet_gateway.id
        config['route_table_id'] = self.route_table.id
        config['master_ebs_volume_num'] = self.opts.master_ebs_vol_num
        config['master_ebs_volume_size'] = self.opts.master_ebs_vol_size
        config['master_ebs_raid_level'] = self.opts.master_ebs_raid_level
        config['master_ebs_raid_dir'] = self.opts.master_ebs_raid_dir
        config['basespace'] = self.opts.basespace_credentials
        config['celery'] = self.opts.celery
        config['mongo'] = self.opts.mongodb
        config['jupyter'] = self.opts.jupyter
        config['jupyter_port'] = 8899
        config['jupyter_password'] = self.opts.jupyter_password
        jstring = json.dumps(config)
        write_config_cmd = "sudo echo '{}' >> {}".format(jstring, config_file)
        self.run(self.master_instance, write_config_cmd)


    def retrieve_opts(self, instance):
        opts_file = '/home/ubuntu/.abcloud_opts'
        read_opts_cmd = "sudo cat '{}'".format(opts_file)
        stdout, _ = self.run(instance, read_opts_cmd)
        return pickle.loads(stdout)


    def retrieve_cfg(self):
        cfg_file = '/home/ubuntu/.abcloud_config'
        read_cfg_cmd = "sudo cat '{}'".format(cfg_file)
        stdout, _ = self.run(self.master_instance, read_cfg_cmd)
        return json.loads(stdout)


def configure_base_image(ip_address, user, identity_file, debug=False):
    # fix hostname mapping
    hostname_cmd = 'echo "$(cat /etc/hostname)"'
    o, e = run_ssh(hostname_cmd, ip_address, user, identity_file)
    if sys.version_info[0] > 2:
        o = o.decode('utf-8')
    hostname = o.strip()
    update_hosts_cmd = "sudo sed -i 's/127.0.0.1 localhost/127.0.0.1 localhost {}/g' /etc/hosts".format(hostname)
    o, e = run_ssh(update_hosts_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nFIX HOSTNAME MAPPING')
        print(o)
        print(e)

    # Initial configuration
    init_cmd = 'sudo debconf-set-selections <<< "postfix postfix/mailname string your.hostname.com"'
    init_cmd += ''' && sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"'''
    init_cmd += ' && sudo apt-get update --fix-missing \
        && sudo apt-get install -y build-essential wget bzip2 fail2ban htop default-jre \
        ca-certificates libglib2.0-0 libxext6 libsm6 libxrender1 pigz s3cmd git mercurial \
        subversion libtool automake zlib1g-dev libbz2-dev pkg-config muscle mafft cd-hit unzip \
        libfontconfig1 lvm2 mdadm nfs-kernel-server \
        && sudo ln -s /usr/bin/cdhit /usr/bin/cd-hit \
        && sudo mkdir /tools \
        && sudo chmod 777 /tools'
    o, e = run_ssh(init_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nINITIAL CONFIGURATION')
        print(o)
        print(e)

    # Anaconda
    conda_cmd = "echo 'export PATH=/home/ubuntu/anaconda3/bin:$PATH' | sudo tee /etc/profile.d/conda.sh \
        && cd /tools \
        && wget --quiet https://repo.continuum.io/archive/Anaconda3-5.0.1-Linux-x86_64.sh \
        && /bin/bash ./Anaconda3-5.0.1-Linux-x86_64.sh -b -p /home/ubuntu/anaconda3 \
        && rm /tools/Anaconda3-5.0.1-Linux-x86_64.sh \
        && export PATH=/home/ubuntu/anaconda3/bin:$PATH \
        && sudo add-apt-repository -y ppa:chronitis/jupyter \
        && sudo apt-get update --fix-missing \
        && sudo apt-get install -y ijulia irkernel ijavascript"
    o, e = run_ssh(conda_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nANACONDA')
        print(o)
        print(e)

    # MongoDB
    mongo_cmd = 'sudo apt-key adv --keyserver ha.pool.sks-keyservers.net --recv-keys "DFFA3DCF326E302C4787673A01C4E7FAAAB2461C" \
        && sudo apt-key adv --keyserver ha.pool.sks-keyservers.net --recv-keys "42F3E95A2C4F08279C4960ADD68FA50FEA312927" \
        && export MONGO_MAJOR=3.2 \
        && export MONGO_VERSION=3.2.4 \
        && echo "deb http://repo.mongodb.org/apt/debian wheezy/mongodb-org/$MONGO_MAJOR main" | sudo tee /etc/apt/sources.list.d/mongodb-org.list \
        && sudo apt-get update \
        && sudo apt-get install -y \
            mongodb-org=$MONGO_VERSION \
            mongodb-org-server=$MONGO_VERSION \
            mongodb-org-shell=$MONGO_VERSION \
            mongodb-org-mongos=$MONGO_VERSION \
            mongodb-org-tools=$MONGO_VERSION \
        && sudo rm -rf /var/lib/apt/lists/* \
        && sudo rm -rf /var/lib/mongodb \
        && sudo mv /etc/mongod.conf /etc/mongod.conf.orig'
    o, e = run_ssh(mongo_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nMONGODB')
        print(o)
        print(e)

    # PANDAseq
    panda_cmd = 'cd /tools \
        && git clone https://github.com/neufeld/pandaseq \
        && cd pandaseq \
        && sudo ./autogen.sh \
        && sudo ./configure \
        && sudo make \
        && sudo make install \
        && sudo ldconfig'
    o, e = run_ssh(panda_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nPANDASEQ')
        print(o)
        print(e)

    # BaseSpace Python SDK
    bs_cmd = 'cd /tools \
        && git clone https://github.com/basespace/basespace-python-sdk \
        && cd basespace-python-sdk/src \
        && /home/ubuntu/anaconda3/bin/python setup.py install'
    o, e = run_ssh(bs_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nBASESPACE PYTHON SDK')
        print(o)
        print(e)

    # USEARCH
    usearch_cmd = 'cd /tools \
        && wget http://burtonlab.s3.amazonaws.com/software/usearch \
        && sudo chmod 777 usearch \
        && sudo cp usearch /usr/local/bin/'
    o, e = run_ssh(usearch_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nUSEARCH')
        print(o)
        print(e)

    # FASTQC
    fastqc_cmd = 'cd /tools \
        && wget http://www.bioinformatics.babraham.ac.uk/projects/fastqc/fastqc_v0.11.5.zip \
        && unzip fastqc_v0.11.5.zip \
        && sudo ln -s FastQC/fastqc /usr/local/bin/fastqc'
    o, e = run_ssh(fastqc_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nFASTQC')
        print(o)
        print(e)

    # cutadapt
    cutadapt_cmd = '/home/ubuntu/anaconda3/bin/pip install cutadapt'
    o, e = run_ssh(cutadapt_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nCUTADAPT')
        print(o)
        print(e)

    # Sickle
    sickle_cmd = 'cd /tools \
        && wget http://zlib.net/zlib128.zip \
        && unzip zlib128.zip \
        && cd zlib-1.2.8 \
        && ./configure \
        && make \
        && sudo make install \
        && cd /tools \
        && git clone https://github.com/najoshi/sickle \
        && cd sickle \
        && make \
        && sudo ln -s ./sickle /usr/local/bin/sickle'
    o, e = run_ssh(sickle_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nSICKLE')
        print(o)
        print(e)

    # AbStar
    abstar_cmd = '/home/ubuntu/anaconda3/bin/pip install abstar'
    o, e = run_ssh(abstar_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nABSTAR')
        print(o)
        print(e)

    # celery[redis]
    celery_cmd = '/home/ubuntu/anaconda3/bin/pip install celery[redis]'
    o, e = run_ssh(celery_cmd, ip_address, user, identity_file)
    if debug:
        if sys.version_info[0] > 2:
            o = o.decode('utf-8')
            e = e.decode('utf-8')
        print('\n\nCELERY[REDIS]')
        print(o)
        print(e)


def run_ssh(cmd, ip_address, user, identity_file, stdin=None):
    with paramiko.SSHClient() as ssh:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            ip_address,
            username=user,
            key_filename=identity_file)
        _stdin, stdout, stderr = ssh.exec_command(cmd)
        if stdin is not None:
            _stdin.write(stdin)
        while not stdout.channel.exit_status_ready():
            time.sleep(1)
    return stdout.read(), stderr.read()


def run_ssh_multi(cmd, instances, user, identity_file):
    p = mp.Pool(len(instances))
    async_results = []
    for instance in instances:
        async_results.append(p.apply_async(run_ssh, args=(cmd,
                                                          instance.public_ip_address,
                                                          user,
                                                          identity_file)))
    monitor_mp_jobs(async_results)
    p.close()
    p.join()


def retrieve_cluster(cluster_name, opts):
    ec2 = boto3.resource('ec2')
    master_group_name = '@abcloud-' + cluster_name + '-master'
    master_instances = ec2utils.get_instances(ec2, master_group_name)
    master_instances = [i for i in master_instances if i.state['Name'] == 'running']
    if len(master_instances) == 0:
        return Cluster(cluster_name, opts=opts)
    vpc_id = master_instances[0].vpc_id
    vpc = [v for v in ec2.vpcs.all() if v.id == vpc_id][0]
    c = Cluster(cluster_name, opts=opts, vpc=vpc)
    c.load()
    return c


def list_clusters(opts):
    ec2 = boto3.resource('ec2')
    groups = ec2.security_groups.all()
    abcloud_groups = sorted(list(set(['-'.join(g.group_name.split('-')[1:-1]) for g in groups if g.group_name.startswith('@abcloud')])))
    print_groups_info(abcloud_groups)
    for ag in abcloud_groups:
        c = retrieve_cluster(ag, opts)
        print_cluster_info(ag, c)


def print_groups_info(groups):
    print('\nFound {} AbCloud clusters:\n{}\n'.format(len(groups), ', '.join(groups)))


def print_cluster_info(name, cluster):
    cname_string = '     {}     '.format(name)
    try:
        # cluster.opts = cluster.retrieve_opts(cluster.master_instance)
        cfg = cluster.retrieve_cfg()
    except:
        print('')
        print(traceback.format_exc())
        return
    print('\n{}'.format(cname_string))
    print('=' * len(cname_string))
    if len(cluster.master) + len(cluster.workers) == 0:
        print('No instances found.')
    else:
        mcount = 1 if cluster.master_instance is not None else 0
        wcount = len(cluster.worker_instances)
        mtype = cluster.master_instance.instance_type if cluster.master_instance is not None else 'None'
        mip = cluster.master_instance.public_ip_address if cluster.master_instance is not None else 'None'
        print('size: {}'.format(mcount + wcount))
        print('')
        # print('number of master instances: {}'.format(mcount))
        print('master instance type: {}'.format(mtype))
        print('master instance IP address: {}'.format(mip))

        if cluster.workers:
            wtype = cluster.worker_instances[0].instance_type
            wips = ', '.join([w.public_ip_address for w in cluster.worker_instances])
            wplural = 'es' if wcount > 1 else ''
            print('')
            print('number of worker instances: {}'.format(wcount))
            print('worker instance type: {}'.format(wtype))
            # print('worker instance IP address{}: {}'.format(wplural, wips))
        # if cluster.opts.basespace_credentials:
        if cfg['basespace']:
            print('\nBaseSpace credentials have been uploaded')
        elif check_for_basespace_credentials(cluster):
            print('\nBaseSpace credentials have been uploaded')
        # if cluster.opts.mongodb:
        if cfg['mongo']:
            print('\nMaster node is configured as a MongoDB server.')
            # print('MongoDB database is located at: {}'.format(os.path.join(cluster.opts.master_ebs_raid_dir, 'db')))
            print('MongoDB database is located at: {}'.format(os.path.join(cfg['master_ebs_raid_dir'], 'db')))
        # if cluster.opts.jupyter:
        if cfg['jupyter']:
            jupyter_location = 'http://{}:8899'.format(cluster.master_instance.public_ip_address)
            print('\nMaster node is configured as a Jupyter notebook server.')
            print("Jupyter notebook URL: {}".format(jupyter_location))
            print('Jupyter password: {}'.format(cluster.opts.jupyter_password))
        # if cluster.opts.celery and cluster.workers:
        if cfg['celery'] and cluster.workers:
            total, running = get_celery_info(cluster)
            print('\nCluster is configured to use Celery.')
            print('Number of Celery workers: {}'.format(total))
            print("Workers reporting 'OK' status: {}".format(running))
            print('Flower is available at: http://{}:5555'.format(cluster.master_instance.public_ip_address))
    print('')


def get_config(ip_address, user, identity_file):
    get_config_cmd = 'cat /home/ubuntu/.abcloud_config'
    cfg_string = run_ssh(get_config_cmd, ip_address, user, identity_file)[0]
    if cfg_string.strip():
        cfg = json.loads(cfg_string)
        return cfg
    return None


def check_for_basespace_credentials(cluster):
    cred_dir = '/home/{}/.abstar/'.format(cluster.opts.user)
    cred_cmd = 'ls %s' % cred_dir
    stdout, stderr = cluster.run(cluster.master_instance, cred_cmd)
    if 'basespace_credentials' in stdout:
        return True
    return False


def get_celery_info(cluster):
    celery_info_cmd = '/home/ubuntu/anaconda3/bin/celery -A abstar.utils.queue.celery status'
    info = cluster.run(cluster.master_instance, celery_info_cmd)[0]
    total = 0
    running = 0
    for inst in info.split('\n'):
        if 'celery@' in inst:
            total += 1
        else:
            continue
        if 'OK' in inst:
            running += 1
    return total, running
