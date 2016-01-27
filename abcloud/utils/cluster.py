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


from __future__ import print_function

import cPickle as pickle
from datetime import datetime
import json
import os
import random
import string
import subprocess
import sys
import time

import boto3

import paramiko

from abcloud.utils import ec2utils, progbar
from abcloud.utils.config import *


class Cluster(object):
    """docstring for Cluster"""
    def __init__(self, name, opts=None, master_instance=None):
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
    def master_group(self):
        if self._master_group is None:
            vpc_id = None if self.opts is None else self.opts.vpc_id
            self._master_group = ec2utils.get_or_make_group(
                self.ec2,
                self.master_group_name,
                vpc_id)
        return self._master_group

    @master_group.setter
    def master_group(self, security_group):
        self._master_group = security_group


    @property
    def worker_group(self):
        if self._worker_group is None:
            vpc_id = None if self.opts is None else self.opts.vpc_id
            self._worker_group = ec2utils.get_or_make_group(
                self.ec2,
                self.worker_group_name,
                vpc_id)
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
        # self.opts = self.retrieve_opts(self.master_instance)
        # get master instance information
        self.master_name = [d['Value'] for d in self.master_instance.tags if 'Name' in d.values()][0]
        self.master = {self.master_name: self.master_instance}
        # get worker instance information
        self.workers = {}
        for i in self.worker_instances:
            worker_name = [d['Value'] for d in i.tags if 'Name' in d.values()][0]
            self.workers[worker_name] = i
        self.worker_names = sorted(self.workers.keys())


    def launch(self):
        print('')
        # authorize ingress ports for master and worker security groups
        auth_master = False if len(self.master_group.ip_permissions) > 0 else True
        auth_worker = False if len(self.worker_group.ip_permissions) > 0 else True
        if any([auth_master, auth_worker]):
            ec2utils.intracluster_auth(self.master_group, self.worker_group)
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
            self.opts.ami = ABTOOLS_AMI_MAP[self.opts.abtools_version]
        try:
            self.image = [i for i in self.ec2.images.filter(ImageIds=[self.opts.ami])][0]
        except:
            print("Could not find AMI " + self.opts.ami, file=sys.stderr)
            sys.exit(1)

        # setup master BlockDeviceMappings
        master_block_device_mappings = []
        for i in range(self.opts.master_ebs_vol_num):
            # EBS volumes are /dev/xvdaa, /dev/xvdab...
            device_name = "/dev/xvda" + string.ascii_lowercase[i]
            ebs = {'VolumeSize': self.opts.master_ebs_vol_size,
                   'VolumeType': self.opts.master_ebs_vol_type}
            device_map = {'DeviceName': device_name,
                          'Ebs': ebs}
            master_block_device_mappings.append(device_map)
        # ephemeral drives must be added to the BlockDeviceMappings for m3 instances
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
                print('Requesting')
                worker_response = ec2utils.request_spot_instance(
                    self.ec2c,
                    group_name=self.worker_group_name,
                    price=self.opts.spot_price,
                    ami=self.opts.ami,
                    num=self.opts.workers,
                    key_pair=self.opts.key_pair,
                    instance_type=self.opts.instance_type)
            else:
                worker_response = {'SpotInstanceRequests': []}
                self.worker_instances = self.ec2.create_instances(
                    ImageId=self.opts.ami,
                    MinCount=self.opts.workers,
                    MaxCount=self.opts.workers,
                    InstanceType=self.opts.instance_type,
                    SecurityGroups=[self.worker_group_name])
        else:
            worker_response = {'SpotInstanceRequests': []}

        # launch masters
        if all([self.opts.force_spot_master, self.opts.spot_price is not None]):
            master_response = ec2utils.request_spot_instance(
                self.ec2c,
                group_name=self.master_group_name,
                price=self.opts.spot_price,
                ami=self.opts.ami,
                num=1,
                key_pair=self.opts.key_pair,
                instance_type=self.opts.master_instance_type,
                block_device_mappings=master_block_device_mappings)
        else:
            master_response = {'SpotInstanceRequests': []}
            master_instances = self.ec2.create_instances(
                ImageId=self.opts.ami,
                MinCount=1,
                MaxCount=1,
                InstanceType=self.opts.master_instance_type,
                SecurityGroups=[self.master_group_name],
                BlockDeviceMappings=master_block_device_mappings)
            self.master_instance = master_instances[0]

        # wait for spot requests to be fulfilled
        master_requests = master_response['SpotInstanceRequests']
        worker_requests = worker_response['SpotInstanceRequests']
        spot_requests = master_requests + worker_requests
        if spot_requests:
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
            self.master_instance.create_tags(Tags=[{'Key': 'Name',
                                                    'Value': self.master_name}])

        # configure the cluster instances
        self.configure()


    def destroy(self):
        self.terminate()
        print('')
        print('Deleting security groups (this may take some time)...')
        print('')
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


    def terminate(self):
        all_instances = self.master.items() + self.workers.items()
        if any(all_instances):
            for name, instance in all_instances:
                print("> {} ({})".format(name, instance.public_dns_name))
            print('')
            print('WARNING: ALL DATA ON ALL NODES WILL BE LOST!!')
        msg = 'Are you sure you want to terminate this cluster? (y/N) '
        response = raw_input(msg)
        if response.upper() == 'Y':
            instances = [instance for name, instance in all_instances]
            self.terminate_instances(self.ec2c, instances)

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
            node_name = self.master.keys()[0]
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
        instance_names = sorted(instance_lookup.keys())

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
        print('Updating /etc/hosts on all nodes...')
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
                print('ERROR: The supplied node name ({})is not a worker.'.format(node_name))
                sys.exit(1)
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
                print('ERROR: The supplied node name ({})is not a worker.'.format(node_name))
                sys.exit(1)
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
        progbar.progress_bar(0, len(self.worker_instances))
        for i, instance in enumerate(self.worker_instances):
            self.run(instance, nfs_mount_cmd)
            progbar.progress_bar(i + 1, len(self.worker_instances))
        print('')


    def start_redis_server(self, instance):
        redis_cmd = 'redis-server'
        self.run(instance, redis_cmd)


    def start_celery_workers(self, instances):
        print('')
        print('Starting Celery worker processes:')
        celery_cmd = '/home/ubuntu/anaconda/bin/celery '
        celery_cmd += '-A abstar.utils.queue.celery worker -l info --detach'
        progbar.progress_bar(0, len(instances))
        for i, instance in enumerate(instances):
            self.run(instance, celery_cmd)
            progbar.progress_bar(i + 1, len(instances))
        print('')


    def start_flower(self):
        print('')
        print('Starting Flower server on master...')
        flower_cmd = '''screen -d -m bash -c "/home/ubuntu/anaconda/bin/flower -A abstar.utils.queue.celery"'''
        self.run(self.master_instance, flower_cmd)
        print('Flower URL: http://{}:5555'.format(self.master_instance.public_ip_address))


    def setup_jupyter_notebook(self):
        print('')
        print('Launching a Jupyter Notebook server on {}...'.format(
            self.master_name))
        # hash/salt the Jupyter login password
        sha1_py = 'from IPython.lib import passwd; print passwd("{}")'.format(
            self.opts.jupyter_password)
        sha1_cmd = "/home/ubuntu/anaconda/bin/python -c '{}'".format(sha1_py)
        passwd = self.run(self.master_instance, sha1_cmd)[0].strip()
        # make a new Jupyter profile and directory; edit the config
        create_profile_cmd = '/home/ubuntu/anaconda/bin/ipython profile create'
        self.run(self.master_instance, create_profile_cmd)
        if self.opts.master_ebs_vol_num > 0:
            notebook_dir = os.path.join(self.opts.master_ebs_raid_dir, 'jupyter')
        else:
            notebook_dir = '/home/ubuntu/jupyter'
        mkdir_cmd = 'sudo mkdir {0} && sudo chmod 777 {0}'.format(notebook_dir)
        self.run(self.master_instance, mkdir_cmd)
        profile_config_string = '\n'.join([
            "c = get_config()",
            "c.IPKernelApp.pylab = 'inline'",
            "c.NotebookApp.ip = '*'",
            "c.NotebookApp.open_browser = False",
            "c.NotebookApp.password = u'%s'" % passwd,
            "c.NotebookApp.port = 8899"])
        profile_config_cmd = 'echo "{}" '.format(profile_config_string)
        profile_config_cmd += '| sudo tee /home/ubuntu/.ipython/profile_default/ipython_notebook_config.py'
        self.run(self.master_instance, profile_config_cmd)
        # start a backgroud Jupyter instance
        jupyter_start_cmd = "/home/ubuntu/anaconda/bin/ipython notebook --notebook-dir={} > /dev/null 2>&1 &".format(notebook_dir)
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
        config['abtools_version'] = self.opts.abtools_version
        jstring = json.dumps(config)
        write_config_cmd = "sudo echo '{}' >> {}".format(jstring, config_file)
        self.run(self.master_instance, write_config_cmd)


    def retrieve_opts(self, instance):
        opts_file = '/home/ubuntu/.abcloud_opts'
        read_opts_cmd = "sudo cat '{}'".format(opts_file)
        stdout, _ = self.run(instance, read_opts_cmd)
        return pickle.loads(stdout)


def retrieve_cluster(cluster_name, opts):
    ec2 = boto3.resource('ec2')
    master_group_name = '@abcloud-' + cluster_name + '-master'
    master_instances = ec2utils.get_instances(ec2, master_group_name)
    master_instances = [i for i in master_instances if i.state['Name'] == 'running']
    if len(master_instances) == 0:
        return Cluster(cluster_name)
    c = Cluster(cluster_name, opts=opts)
    c.load()
    return c
