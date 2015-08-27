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

import itertools
import json
import os
import pipes
import random
import string
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from sys import stderr

import boto
from boto.ec2.blockdevicemapping import BlockDeviceMapping, BlockDeviceType, EBSBlockDeviceType
from boto import ec2

import paramiko

from utils import ec2utils
import progbar


def launch_cluster(conn, opts, cluster_name):
	if opts.resume:
		(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(conn, opts, cluster_name)
	else:
		(master_nodes, worker_nodes) = _launch_cluster(conn, opts, cluster_name)
	wait_for_cluster_state(
		conn=conn,
		opts=opts,
		cluster_instances=(master_nodes + worker_nodes),
		cluster_state='ssh-ready'
	)
	setup_cluster(conn, master_nodes, worker_nodes, opts, True)


def destroy_cluster(conn, opts, cluster_name):
	(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(
		conn, opts, cluster_name, die_on_error=False)
	if any(master_nodes + worker_nodes):
		print("\nThe following instances will be terminated:")
		for inst in master_nodes + worker_nodes:
			try:
				name = inst.tags['Name']
			except KeyError:
				name = 'unnamed node'
			print("> %s (%s)" % (name, ec2utils.get_dns_name(inst, opts.private_ips)))
		print("\nWARNING: ALL DATA ON ALL NODES WILL BE LOST!!")

	msg = "Are you sure you want to destroy this cluster? (y/N) "
	response = raw_input(msg)
	if response.upper() == "Y":
		_destroy_cluster(conn, opts, cluster_name, master_nodes, worker_nodes)
	print('\nDone!\n\n')


def ssh_node(conn, opts, cluster_name, node_type='master'):
	(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(conn, opts, cluster_name)
	if node_type == 'master':
		if len(master_nodes) == 1:
			instance = master_nodes[0]
			node = ec2utils.get_dns_name(master_nodes[0], opts.private_ips)
		else:
			if not opts.node:
				print('ERROR: Master node name must be specified (with --node) for' +
					'clusters with multiple masters.')
				sys.exit(1)
			instance = [m for m in master_nodes if m.tags['Name'] == opts.node][0]
			node = ec2utils.get_dns_name(instance, opts.private_ips)
	else:
		if not opts.node:
			print('ERROR: Master node name must be specified (with --node) for' +
				'clusters with multiple masters.')
		instance = [w for w in worker_nodes if w.tags['Name'] == opts.node][0]
		node = ec2utils.get_dns_name(instance, opts.private_ips)
	print("Logging into node " + instance.tags['Name'] + "...")
	proxy_opt = []
	subprocess.check_call(
		ssh_command(opts) + proxy_opt + ['-t', '-t', "%s@%s" % (opts.user, node)],
		stderr=subprocess.PIPE)


def reboot_workers(conn, opts, cluster_name):
	(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(
		conn, opts, cluster_name, die_on_error=False)
	print("Rebooting workers...")
	for inst in worker_nodes:
		if inst.state not in ["shutting-down", "terminated"]:
			print("Rebooting " + inst.id)
			inst.reboot()


def stop_cluster(conn, opts, cluster_name):
	(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(
		conn, opts, cluster_name, die_on_error=False)
	print("Stopping master...")
	for inst in master_nodes:
		if inst.state not in ["shutting-down", "terminated"]:
			inst.stop()
	print("Stopping workers...")
	for inst in worker_nodes:
		if inst.state not in ["shutting-down", "terminated"]:
			if inst.spot_instance_request_id:
				inst.terminate()
			else:
				inst.stop()


def start_cluster(conn, opts, cluster_name):
	(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(conn, opts, cluster_name)
	print("Starting workers...")
	for inst in worker_nodes:
		if inst.state not in ["shutting-down", "terminated"]:
			inst.start()
	print("Starting master...")
	for inst in master_nodes:
		if inst.state not in ["shutting-down", "terminated"]:
			inst.start()
	wait_for_cluster_state(
		conn=conn,
		opts=opts,
		cluster_instances=(master_nodes + worker_nodes),
		cluster_state='ssh-ready'
	)

	# Determine types of running instances
	existing_master_type = master_nodes[0].instance_type
	existing_worker_type = worker_nodes[0].instance_type
	# Setting opts.master_instance_type to 'None' indicates we wish to
	# use the same instance type for the master and the workers
	if existing_master_type == existing_worker_type:
		existing_master_type = None
	opts.master_instance_type = existing_master_type
	opts.instance_type = existing_worker_type

	setup_cluster(conn, master_nodes, worker_nodes, opts, False)


def wait_for_cluster_state(conn, opts, cluster_instances, cluster_state):
	"""
	Wait for all the instances in the cluster to reach a designated state.

	cluster_instances: a list of boto.ec2.instance.Instance
	cluster_state: a string representing the desired state of all the instances in the cluster
		   value can be 'ssh-ready' or a valid value from boto.ec2.instance.InstanceState such as
		   'running', 'terminated', etc.
		   (would be nice to replace this with a proper enum: http://stackoverflow.com/a/1695250)
	"""
	sys.stdout.write(
		"Waiting for {n} cluster instance{plural_n} to enter '{s}' state:\n".format(
			s=cluster_state,
			plural_n=('' if len(cluster_instances) == 1 else 's'),
			n=len(cluster_instances)
		)
	)
	sys.stdout.flush()

	start_time = datetime.now()
	num_attempts = 0

	while True:
		time.sleep(5)  # seconds

		for i in cluster_instances:
			i.update()

		max_batch = 100
		statuses = []
		for j in xrange(0, len(cluster_instances), max_batch):
			batch = [i.id for i in cluster_instances[j:j + max_batch]]
			statuses.extend(conn.get_all_instance_status(instance_ids=batch))

		if cluster_state == 'ssh-ready':
			inst_ok = [s for s in statuses if s.instance_status.status == 'ok']
			progbar.cluster_state_progbar(len(inst_ok), len(cluster_instances), start_time)
			if all(i.state == 'running' for i in cluster_instances) and \
			   all(s.system_status.status == 'ok' for s in statuses) and \
			   all(s.instance_status.status == 'ok' for s in statuses) and \
			   is_cluster_ssh_available(cluster_instances, opts):
				print()
				break
		else:
			if all(i.state == cluster_state for i in cluster_instances):
				break

		num_attempts += 1

		# sys.stdout.write(".")
		# sys.stdout.flush()

	sys.stdout.write("\n")

	end_time = datetime.now()
	print("Cluster is now in '{s}' state. Waited {t} seconds.".format(
		s=cluster_state,
		t=(end_time - start_time).seconds
	))


def is_cluster_ssh_available(cluster_instances, opts):
	"""
	Check if SSH is available on all the instances in a cluster.
	"""
	for i in cluster_instances:
		dns_name = ec2utils.get_dns_name(i, opts.private_ips)
		if not is_ssh_available(host=dns_name, opts=opts):
			return False
	else:
		return True


def is_ssh_available(host, opts, print_ssh_output=True):
	"""
	Check if SSH is available on a host.
	"""
	s = subprocess.Popen(
		ssh_command(opts) + ['-t', '-t', '-o', 'ConnectTimeout=3',
							 '%s@%s' % (opts.user, host), stringify_command('true')],
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT  # we pipe stderr through stdout to preserve output order
	)
	cmd_output = s.communicate()[0]  # [1] is stderr, which we redirected to stdout

	if s.returncode != 0 and print_ssh_output:
		# extra leading newline is for spacing in wait_for_cluster_state()
		print(textwrap.dedent("""\n
			Warning: SSH connection error. (This could be temporary.)
			Host: {h}
			SSH return code: {r}
			SSH output: {o}
		""").format(
			h=host,
			r=s.returncode,
			o=cmd_output.strip()
		))

	return s.returncode == 0


def ssh_args(opts):
	parts = ['-o', 'StrictHostKeyChecking=no']
	parts += ['-o', 'UserKnownHostsFile=/dev/null']
	if opts.identity_file is not None:
		parts += ['-i', opts.identity_file]
	return parts


def ssh_command(opts):
	return ['ssh'] + ssh_args(opts)


def stringify_command(parts):
	if isinstance(parts, str):
		return parts
	else:
		return ' '.join(map(pipes.quote, parts))


def ssh(host, opts, command, quiet=False):
	"""
	Run a command on a host through ssh, retrying up to five times
	and then throwing an exception if ssh continues to fail.
	"""
	tries = 0
	while True:
		try:
			output = subprocess.PIPE if quiet else None
			return subprocess.check_call(
				ssh_command(opts) + ['-t', '-t', '%s@%s' % (opts.user, host),
									 stringify_command(command)],
				stdout=output, stderr=output)
		except subprocess.CalledProcessError as e:
			if tries > 5:
				# If this was an ssh failure, provide the user with hints.
				if e.returncode == 255:
					raise UsageError(
						"Failed to SSH to remote host {0}.\n" +
						"Please check that you have provided the correct --identity-file and " +
						"--key-pair parameters and try again.".format(host))
				else:
					raise e
			print("Error executing remote command, retrying after 30 seconds: {0}".format(e),
				  file=stderr)
			time.sleep(30)
			tries = tries + 1


def run_remote_cmd(node, opts, cmd, user=None):
		'''
		Remotely runs 'cmd' on 'node' and blocks until 'cmd' completes.
		Returns 'cmd' stdout.
		'''
		if not user:
			user = opts.user
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(node, username=user, key_filename=opts.identity_file)
		stdin, stdout, stderr = ssh.exec_command(cmd)
		channel = stdout.channel
		while not channel.exit_status_ready():
			time.sleep(1)
		return stdout.read(), stderr.read()


def _check_output(*popenargs, **kwargs):
	"""
	Backported from Python 2.7 for compatiblity with 2.6 (See SPARK-1990)
	"""
	if 'stdout' in kwargs:
		raise ValueError('stdout argument not allowed, it will be overridden.')
	process = subprocess.Popen(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
		*popenargs, **kwargs)
	output, unused_err = process.communicate()
	retcode = process.poll()
	if retcode:
		cmd = kwargs.get("args")
		if cmd is None:
			cmd = popenargs[0]
		raise subprocess.CalledProcessError(retcode, cmd, output=output)
	return output


def ssh_read(host, opts, command):
	return _check_output(
		ssh_command(opts) + ['%s@%s' % (opts.user, host), stringify_command(command)])


def ssh_write(host, opts, command, arguments):
	tries = 0
	while True:
		proc = subprocess.Popen(
			ssh_command(opts) + ['%s@%s' % (opts.user, host), stringify_command(command)],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		proc.stdin.write(arguments)
		proc.stdin.close()
		status = proc.wait()
		if status == 0:
			break
		elif tries > 5:
			raise RuntimeError("ssh_write failed with error %s" % proc.returncode)
		else:
			print("Error {0} while executing remote command, retrying after 30 seconds".
				  format(status), file=stderr)
			time.sleep(30)
			tries = tries + 1



def setup_cluster(conn, master_nodes, worker_nodes, opts, deploy_ssh_key):
	all_nodes = master_nodes + worker_nodes
	# master_names = [n.tags['Name'] for n in master_nodes]
	# worker_names = [n.tags['Name'] for n in worker_nodes]
	# worker_ips = [ec2utils.get_ip_address(n) for n in worker_nodes]
	node_names = [n.tags['Name'] for n in all_nodes]

	# deploy SSH key to nodes for password-less SSH
	master = ec2utils.get_dns_name(master_nodes[0], opts.private_ips)
	if deploy_ssh_key:
		print("\nGenerating cluster's SSH key on master...")
		key_setup = """
		  [ -f ~/.ssh/id_rsa ] ||
			(ssh-keygen -q -t rsa -N '' -f ~/.ssh/id_rsa &&
			 cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys)
		"""
		ssh(master, opts, key_setup, quiet=True)
		dot_ssh_tar = ssh_read(master, opts, ['tar', 'c', '.ssh'])
		if opts.workers > 0:
			print("Transferring cluster's SSH key to workers...")
			for i, worker in enumerate(worker_nodes):
				worker_address = ec2utils.get_dns_name(worker, opts.private_ips)
				ssh_write(worker_address, opts, ['tar', 'x'], dot_ssh_tar)
				progbar.distribute_ssh_keys_progbar(i + 1, len(worker_nodes), worker.tags['Name'])
			print()

	# modify /etc/hosts on all nodes
	print('Updating /etc/hosts on all nodes...')
	ips = [str(n.ip_address) for n in all_nodes]
	host_string = '\n'.join(['{} {}'.format(i, n) for i, n in zip(ips, node_names)])
	host_cmd = """sudo -- sh -c 'echo "{}" >> /etc/hosts'""".format(host_string)
	for node in all_nodes:
		node_address = ec2utils.get_dns_name(node, opts.private_ips)
		stdout, stderr = run_remote_cmd(node_address, opts, host_cmd)

	# build and share an EBS RAID array on master node
	if opts.master_ebs_vol_num > 0:
		build_ebs_raid_volume(master, master_nodes, worker_nodes, opts)

	# start celery workers on all nodes (including master):
	if opts.celery and opts.workers > 0:
		start_celery_workers(master, worker_nodes, opts)
		start_flower(master_nodes[0], opts)

	# configure and start a Jupyter server
	if opts.jupyter:
		setup_jupyter_notebook(master, master_nodes, opts)

	# configure and start a MongoDB server
	if opts.mongodb:
		setup_mongodb(master, master_nodes, opts)

	write_config_info(master, opts)

	print("\nDeploying files to master...")
	# deploy_files(
	# 	conn=conn,
	# 	root_dir=SPARK_EC2_DIR + "/" + "deploy.generic",
	# 	opts=opts,
	# 	master_nodes=master_nodes,
	# 	slave_nodes=slave_nodes,
	# 	modules=modules
	# )

	# if opts.deploy_root_dir is not None:
	# 	print("Deploying {s} to master...".format(s=opts.deploy_root_dir))
	# 	deploy_user_files(
	# 		root_dir=opts.deploy_root_dir,
	# 		opts=opts,
	# 		master_nodes=master_nodes
	# 	)

	print("\nRunning setup on master...")
	# setup_spark_cluster(master, opts)
	print("\nDone!\n\n")


def build_ebs_raid_volume(master, master_nodes, worker_nodes, opts):
	all_nodes = master_nodes + worker_nodes
	node_names = [n.tags['Name'] for n in all_nodes]

	# build and share an EBS RAID array on master node
	print('\nBuilding a {}-member RAID{} array on the master node...'.format(
		opts.master_ebs_vol_num, opts.master_ebs_raid_level))
	drives = ["/dev/xvda" + chr(ord('a') + i) for i in range(opts.master_ebs_vol_num)]
	raid_cmd = "sudo mdadm --verbose --create /dev/md0 --level={2} --chunk=256 --raid-devices={0} {1} ".format(
		len(drives), ' '.join(drives), opts.master_ebs_raid_level)
	if opts.mongodb:
		for drive in drives:
			raid_cmd += '&& sudo blockdev --setra 32 {} '.format(drive)
	raid_cmd += "&& sudo dd if=/dev/zero of=/dev/md0 bs=512 count=1 \
		&& sudo pvcreate /dev/md0 \
		&& sudo vgcreate vg0 /dev/md0 "
	if opts.mongodb:
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
	   && sudo chmod 777 {0}".format(opts.master_ebs_raid_dir)
	run_remote_cmd(master, opts, raid_cmd)

	# share the EBS RAID array with worker nodes via NFS
	if opts.workers > 0:
		print('Adding nodes to /etc/exports on master node...')
		for node in node_names:
			export_cmd = """sudo -- sh -c 'echo "{} {}(async,no_root_squash,no_subtree_check,rw)" >> /etc/exports'""".format(
				opts.master_ebs_raid_dir, node)
			run_remote_cmd(master, opts, export_cmd)
		nfs_start_cmd = 'sudo exportfs -a && sudo /etc/init.d/nfs-kernel-server start'
		run_remote_cmd(master, opts, nfs_start_cmd)
		print('Mounting NFS share ({}:{}) on each node:'.format(
			master_nodes[0].tags['Name'], opts.master_ebs_raid_dir))
		nfs_mount_cmd = "sudo mkdir {0}\
		   && sudo mount {1}:{0} {0}\
		   && sudo chmod 777 {0}".format(opts.master_ebs_raid_dir, master_nodes[0].tags['Name'])
		progbar.distribute_ssh_keys_progbar(0, len(worker_nodes), '')
		for i, worker in enumerate(worker_nodes):
			worker_address = ec2utils.get_dns_name(worker)
			run_remote_cmd(worker_address, opts, nfs_mount_cmd)
			progbar.distribute_ssh_keys_progbar(i + 1, len(worker_nodes), worker.tags['Name'])
		print()


def start_celery_workers(master, worker_nodes, opts):
	worker_ips = [ec2utils.get_ip_address(n) for n in worker_nodes]

	# start celery workers on all nodes (including master)
	print("\nStarting Celery worker processes on all worker nodes...")
	master_cpus = int(run_remote_cmd(master, opts, 'nproc')[0].strip())
	master_celery_processes = master_cpus - 4
	celery_cmd = 'cd /abstar && /home/ubuntu/anaconda/bin/celery -A utils.queue.celery worker -l info --detach'
	if master_celery_processes > 0:
		master_celery_cmd = celery_cmd + ' --concurrency={}'.format(master_celery_processes)
		run_remote_cmd(master, opts, master_celery_cmd)
	progbar.distribute_ssh_keys_progbar(0, len(worker_nodes), '')
	for i, worker_node in enumerate(worker_nodes):
		worker = worker_node.ip_address
		run_remote_cmd(worker, opts, celery_cmd)
		progbar.distribute_ssh_keys_progbar(i + 1, len(worker_nodes), worker_node.tags['Name'])


def start_flower(master, opts):
	print('\nStarting Flower server...')
	flower_cmd = '''cd /abstar && screen -d -m bash -c "/home/ubuntu/anaconda/bin/flower -A utils.queue.celery"'''
	run_remote_cmd(master.ip_address, opts, flower_cmd)
	print('Flower URL: http://{}:5555'.format(master.ip_address))


def setup_jupyter_notebook(master, master_nodes, opts):
	print('\nLaunching a Jupyter notebook server on master node...')

	# hash/salt the Jupyter login password
	sha1_py = 'from IPython.lib import passwd; print passwd("%s")' % opts.jupyter_password
	sha1_cmd = "/home/ubuntu/anaconda/bin/python -c '%s'" % sha1_py
	passwd = run_remote_cmd(master, opts, sha1_cmd)[0].strip()

	# make a new Jupyter profile, edit the config
	create_profile_cmd = '/home/ubuntu/anaconda/bin/ipython profile create'
	stdout, stderr = run_remote_cmd(master, opts, create_profile_cmd)
	notebook_dir = '/home/ubuntu/jupyter'
	if opts.master_ebs_vol_num > 0:
		notebook_dir = os.path.join(opts.master_ebs_raid_dir, 'jupyter')
	run_remote_cmd(master, opts, 'sudo mkdir %s && sudo chmod 777 %s' % (notebook_dir, notebook_dir))
	profile_config_string = '\n'.join(["c = get_config()",
									   "c.IPKernelApp.pylab = 'inline'",
									   "c.NotebookApp.ip = '*'",
									   "c.NotebookApp.open_browser = False",
									   "c.NotebookApp.password = u'%s'" % passwd,
									   "c.NotebookApp.port = %s" % opts.jupyter_port, ])
	profile_config_cmd = 'echo "%s" | sudo tee /home/ubuntu/.ipython/profile_default/ipython_notebook_config.py' % profile_config_string
	stdout, stderr = run_remote_cmd(master, opts, profile_config_cmd)

	# start a backgroud Jupyter instance
	jupyter_start_cmd = "/home/ubuntu/anaconda/bin/ipython notebook --notebook-dir=%s > /dev/null 2>&1 &" % notebook_dir
	run_remote_cmd(master, opts, jupyter_start_cmd)
	master_ip = ec2utils.get_ip_address(master_nodes[0])
	print("Jupyter notebook URL: http://{}:{}".format(master_ip, opts.jupyter_port))
	print("Password for the Jupyter notebook is '{}'".format(opts.jupyter_password))


def setup_mongodb(master, master_nodes, opts):
	print('\nConfiguring MongoDB...')
	dbpath = os.path.join(opts.master_ebs_raid_dir, 'db')
	init_cmd = ' && '.join(['sudo service mongod stop',
						'sudo mkdir %s' % dbpath,
						'sudo chmod 777 %s' % dbpath,
						'sudo useradd mongod',
						'sudo chown mongod:mongod /data /journal /log',
						'sudo ln -s /journal /data/journal'])
	stdout, stderr = run_remote_cmd(master, opts, init_cmd)

	# start mongod
	print('Starting mongod...')
	mongod_start_cmd = 'mongod --fork --logpath /log/mongod.log --dbpath %s --rest --bind_ip 0.0.0.0' % dbpath
	stdout, stderr = run_remote_cmd(master, opts, mongod_start_cmd)
	print('MongoDB database location: {}'.format(dbpath))
	print('MongoDB log location: /log/mongod.log')


def write_config_info(master, opts):
	config_file = '/home/ubuntu/.abcloud_config'
	config = {}
	config['master_ebs_volume_num'] = opts.master_ebs_vol_num
	config['master_ebs_volume_size'] = opts.master_ebs_vol_size
	config['master_ebs_raid_level'] = opts.master_ebs_raid_level
	config['master_ebs_raid_dir'] = opts.master_ebs_raid_dir
	config['celery'] = opts.celery
	config['mongo'] = opts.mongodb
	config['jupyter'] = opts.jupyter
	config['jupyter_port'] = opts.jupyter_port
	config['jupyter_password'] = opts.jupyter_password
	config['abtools_version'] = opts.abtools_version
	jstring = json.dumps(config)
	write_config_cmd = "sudo echo '%s' >> %s" % (jstring, config_file)
	run_remote_cmd(master, opts, write_config_cmd)


def _launch_cluster(conn, opts, cluster_name):
	"""
	Launch a cluster of the given name, by setting up its security groups
	and then starting new instances inside them.
	Returns a tuple of EC2 reservation objects for the master and workers
	Fails if there already instances running in the cluster's groups.
	"""
	if not opts.identity_file:
		print("ERROR: Must provide an identity file (-i) for ssh connections.", file=stderr)
		sys.exit(1)

	if not opts.key_pair:
		print("ERROR: Must provide a key pair name (-k) to use on instances.", file=stderr)
		sys.exit(1)

	user_data_content = None
	if opts.user_data:
		with open(opts.user_data) as user_data_file:
			user_data_content = user_data_file.read()

	print("\nSetting up security groups...")
	master_group = ec2utils.get_or_make_group(conn, '@abcloud-' + cluster_name + "-master", opts.vpc_id)
	worker_group = ec2utils.get_or_make_group(conn, '@abcloud-' + cluster_name + "-workers", opts.vpc_id)
	authorized_address = opts.authorized_address
	if master_group.rules == []:  # Group was just now created
		if opts.vpc_id is None:
			master_group.authorize(src_group=master_group)
			master_group.authorize(src_group=worker_group)
		else:
			master_group.authorize(ip_protocol='icmp', from_port=-1, to_port=-1,
								   src_group=master_group)
			master_group.authorize(ip_protocol='tcp', from_port=0, to_port=65535,
								   src_group=master_group)
			master_group.authorize(ip_protocol='udp', from_port=0, to_port=65535,
								   src_group=master_group)
			master_group.authorize(ip_protocol='icmp', from_port=-1, to_port=-1,
								   src_group=worker_group)
			master_group.authorize(ip_protocol='tcp', from_port=0, to_port=65535,
								   src_group=worker_group)
			master_group.authorize(ip_protocol='udp', from_port=0, to_port=65535,
								   src_group=worker_group)
		master_group.authorize('tcp', 22, 22, authorized_address)
		master_group.authorize('tcp', 8080, 8081, authorized_address)
		master_group.authorize('tcp', 18080, 18080, authorized_address)
		master_group.authorize('tcp', 19999, 19999, authorized_address)
		master_group.authorize('tcp', 50030, 50030, authorized_address)
		master_group.authorize('tcp', 50070, 50070, authorized_address)
		master_group.authorize('tcp', 60070, 60070, authorized_address)
		master_group.authorize('tcp', 4040, 4045, authorized_address)
		# HDFS NFS gateway requires 111,2049,4242 for tcp & udp
		master_group.authorize('tcp', 111, 111, authorized_address)
		master_group.authorize('udp', 111, 111, authorized_address)
		master_group.authorize('tcp', 2049, 2049, authorized_address)
		master_group.authorize('udp', 2049, 2049, authorized_address)
		master_group.authorize('tcp', 4242, 4242, authorized_address)
		master_group.authorize('udp', 4242, 4242, authorized_address)
		# RM in YARN mode uses 8088
		master_group.authorize('tcp', 8088, 8088, authorized_address)
		if opts.celery:
			master_group.authorize('tcp', 5555, 5555, authorized_address)
			master_group.authorize('tcp', 6379, 6379, authorized_address)
		if opts.jupyter:
			master_group.authorize('tcp', opts.jupyter_port, opts.jupyter_port, authorized_address)
		if opts.mongodb:
			master_group.authorize('tcp', 27017, 27017, authorized_address)
	if opts.workers > 0:
		if worker_group.rules == []:  # Group was just now created
			if opts.vpc_id is None:
				worker_group.authorize(src_group=master_group)
				worker_group.authorize(src_group=worker_group)
			else:
				worker_group.authorize(ip_protocol='icmp', from_port=-1, to_port=-1,
									  src_group=master_group)
				worker_group.authorize(ip_protocol='tcp', from_port=0, to_port=65535,
									  src_group=master_group)
				worker_group.authorize(ip_protocol='udp', from_port=0, to_port=65535,
									  src_group=master_group)
				worker_group.authorize(ip_protocol='icmp', from_port=-1, to_port=-1,
									  src_group=worker_group)
				worker_group.authorize(ip_protocol='tcp', from_port=0, to_port=65535,
									  src_group=worker_group)
				worker_group.authorize(ip_protocol='udp', from_port=0, to_port=65535,
									  src_group=worker_group)
			worker_group.authorize('tcp', 22, 22, authorized_address)
			worker_group.authorize('tcp', 8080, 8081, authorized_address)
			worker_group.authorize('tcp', 50060, 50060, authorized_address)
			worker_group.authorize('tcp', 50075, 50075, authorized_address)
			worker_group.authorize('tcp', 60060, 60060, authorized_address)
			worker_group.authorize('tcp', 60075, 60075, authorized_address)
			if opts.celery:
				worker_group.authorize('tcp', 5555, 5555, authorized_address)
				worker_group.authorize('tcp', 6379, 6379, authorized_address)

	# Check if instances are already running in our groups
	existing_masters, existing_workers = ec2utils.get_existing_cluster(conn, opts, cluster_name,
															 die_on_error=False)
	if existing_workers or (existing_masters and not opts.use_existing_master):
		print("ERROR: There are already instances running in group %s or %s" %
			  (master_group.name, worker_group.name), file=stderr)
		sys.exit(1)

	# Figure out AbTools AMI
	if opts.ami is None:
		from utils.config import ABTOOLS_AMI_MAP
		opts.ami = ABTOOLS_AMI_MAP[opts.abtools_version]

	# we use group ids to work around https://github.com/boto/boto/issues/350
	additional_group_ids = []
	if opts.additional_security_group:
		additional_group_ids = [sg.id
								for sg in conn.get_all_security_groups()
								if opts.additional_security_group in (sg.name, sg.id)]
	print("\nLaunching instances...")

	try:
		image = conn.get_all_images(image_ids=[opts.ami])[0]
	except:
		print("Could not find AMI " + opts.ami, file=stderr)
		sys.exit(1)

	# Create master node block device mapping so that we can add EBS volumes.
	master_block_map = BlockDeviceMapping()
	if opts.master_ebs_vol_num > 0:
		for i in range(opts.master_ebs_vol_num):
			device = EBSBlockDeviceType()
			device.size = opts.master_ebs_vol_size
			device.volume_type = opts.master_ebs_vol_type
			device.delete_on_termination = True
			master_block_map["/dev/xvda" + chr(ord('a') + i)] = device

	# Create block device mapping so that we can add EBS volumes if asked to.
	# The first drive is attached as /dev/sds, 2nd as /dev/sdt, ... /dev/sdz
	block_map = BlockDeviceMapping()
	if opts.ebs_vol_size > 0:
		for i in range(opts.ebs_vol_num):
			device = EBSBlockDeviceType()
			device.size = opts.ebs_vol_size
			device.volume_type = opts.ebs_vol_type
			device.delete_on_termination = True
			block_map["/dev/xvda" + chr(ord('a') + i)] = device

	# AWS ignores the AMI-specified block device mapping for M3 (see SPARK-3342).
	if opts.instance_type.split('.')[0] in ['m3', ]:
		for i in range(ec2utils.get_num_disks(opts.instance_type)):
			dev = BlockDeviceType()
			dev.ephemeral_name = 'ephemeral%d' % i
			# The first ephemeral drive is /dev/xvdb.
			name = '/dev/xvd' + string.letters[i + 1]
			block_map[name] = dev

	# Launch workers
	if opts.workers == 0:
		worker_nodes = []
	else:
		if opts.spot_price is not None:
			# Launch spot instances with the requested price
			print("Requesting %d workers as spot instances with max price $%.3f" %
				  (opts.workers, opts.spot_price))
			zones = ec2utils.get_zones(conn, opts)
			num_zones = len(zones)
			i = 0
			my_req_ids = []
			for zone in zones:
				num_workers_this_zone = ec2utils.get_partition(opts.workers, num_zones, i)
				worker_reqs = conn.request_spot_instances(
					price=opts.spot_price,
					image_id=opts.ami,
					launch_group="launch-group-%s" % cluster_name,
					placement=zone,
					count=num_workers_this_zone,
					key_name=opts.key_pair,
					security_group_ids=[worker_group.id] + additional_group_ids,
					instance_type=opts.instance_type,
					block_device_map=block_map,
					subnet_id=opts.subnet_id,
					placement_group=opts.placement_group,
					user_data=user_data_content)
				my_req_ids += [req.id for req in worker_reqs]
				i += 1

			print("Waiting for spot instances to be granted...")
			try:
				while True:
					time.sleep(10)
					reqs = conn.get_all_spot_instance_requests()
					id_to_req = {}
					for r in reqs:
						id_to_req[r.id] = r
					active_instance_ids = []
					for i in my_req_ids:
						if i in id_to_req and id_to_req[i].state == "active":
							active_instance_ids.append(id_to_req[i].instance_id)
					if len(active_instance_ids) == opts.workers:
						print("All %d workers granted" % opts.workers)
						reservations = conn.get_all_reservations(active_instance_ids)
						worker_nodes = []
						for r in reservations:
							worker_nodes += r.instances
						break
					else:
						num_active = len(active_instance_ids)
						print("\r%d of %d workers granted, still waiting for %d workers" % (
							num_active, opts.workers, opts.workers - num_active))
			except:
				print("Canceling spot instance requests")
				conn.cancel_spot_instance_requests(my_req_ids)
				# Log a warning if any of these requests actually launched instances:
				(master_nodes, worker_nodes) = ec2utils.get_existing_cluster(
					conn, opts, cluster_name, die_on_error=False)
				running = len(master_nodes) + len(worker_nodes)
				if running:
					print(("WARNING: %d instances are still running" % running), file=stderr)
				sys.exit(0)
		else:
			# Launch non-spot instances
			zones = ec2utils.get_zones(conn, opts)
			num_zones = len(zones)
			i = 0
			worker_nodes = []
			for zone in zones:
				num_workers_this_zone = ec2utils.get_partition(opts.workers, num_zones, i)
				if num_workers_this_zone > 0:
					worker_res = image.run(key_name=opts.key_pair,
										  security_group_ids=[worker_group.id] + additional_group_ids,
										  instance_type=opts.instance_type,
										  placement=zone,
										  min_count=num_workers_this_zone,
										  max_count=num_workers_this_zone,
										  block_device_map=block_map,
										  subnet_id=opts.subnet_id,
										  placement_group=opts.placement_group,
										  user_data=user_data_content)
					worker_nodes += worker_res.instances
					print("Launched {s} worker{plural_s} in {z}, regid = {r}".format(
						  s=num_workers_this_zone,
						  plural_s=('' if num_workers_this_zone == 1 else 's'),
						  z=zone,
						  r=worker_res.id))
				i += 1

	# Launch or resume masters
	if existing_masters:
		print("Starting master...")
		for inst in existing_masters:
			if inst.state not in ["shutting-down", "terminated"]:
				inst.start()
		master_nodes = existing_masters
	else:
		master_type = opts.master_instance_type
		if not master_type:
			master_type = opts.instance_type
		if opts.zone == 'all':
			opts.zone = random.choice(conn.get_all_zones()).name
		master_res = image.run(key_name=opts.key_pair,
							   security_group_ids=[master_group.id] + additional_group_ids,
							   instance_type=master_type,
							   placement=opts.zone,
							   min_count=1,
							   max_count=1,
							   block_device_map=master_block_map,
							   subnet_id=opts.subnet_id,
							   placement_group=opts.placement_group,
							   user_data=user_data_content)

		master_nodes = master_res.instances
		print("Launched master in %s, regid = %s" % (opts.zone, master_res.id))

	# This wait time corresponds to SPARK-4983
	print("\nWaiting for AWS to propagate instance metadata...")
	time.sleep(5)
	# Give the instances descriptive names
	for i, master in enumerate(master_nodes):
		if len(master_nodes) > 1:
			zeroes = 2 - len(str(i + 1))
			master_num = '0' * zeroes + str(i + 1)
			master_prefix = 'master'.format(cluster_name)
		else:
			master_num = ''
			if opts.workers == 0:
				master_prefix = cluster_name
			else:
				master_prefix = 'master'.format(cluster_name)
		master.add_tag(
			key='Name',
			# value='{cn}-master{num}'.format(cn=cluster_name, num=master_num))
			value='{prefix}{num}'.format(prefix=master_prefix, num=master_num))
	for i, worker in enumerate(worker_nodes):
		zeroes = 3 - len(str(i + 1))
		worker_num = '0' * zeroes + str(i + 1)
		worker.add_tag(
			key='Name',
			# value='{cn}-worker{num}'.format(cn=cluster_name, num=worker_num))
			value='node{num}'.format(num=worker_num))

	# Return all the instances
	return (master_nodes, worker_nodes)


def _destroy_cluster(conn, opts, cluster_name, master_nodes, worker_nodes):
	"""
	Destroys the cluster. Cluster can no be restarted and all data will be lost.
	"""

	print("\nTerminating master...")
	for inst in master_nodes:
		inst.terminate()
	print("Terminating workers...")
	for inst in worker_nodes:
		inst.terminate()

	# Delete security groups as well
	if opts.delete_groups:
		group_names = ['@abcloud-' + cluster_name + "-master", '@abcloud-' + cluster_name + "-workers"]
		wait_for_cluster_state(
			conn=conn,
			opts=opts,
			cluster_instances=(master_nodes + worker_nodes),
			cluster_state='terminated'
		)
		print("Deleting security groups (this will take some time)...")
		attempt = 1
		while attempt <= 3:
			print("Attempt %d" % attempt)
			groups = [g for g in conn.get_all_security_groups() if g.name in group_names]
			success = True
			# Delete individual rules in all groups before deleting groups to
			# remove dependencies between them
			for group in groups:
				print("Deleting rules in security group " + group.name)
				for rule in group.rules:
					for grant in rule.grants:
						success &= group.revoke(ip_protocol=rule.ip_protocol,
												from_port=rule.from_port,
												to_port=rule.to_port,
												src_group=grant)

			# Sleep for AWS eventual-consistency to catch up, and for instances
			# to terminate
			time.sleep(30)  # Yes, it does have to be this long :-(
			for group in groups:
				try:
					# It is needed to use group_id to make it work with VPC
					conn.delete_security_group(group_id=group.id)
					print("Deleted security group %s" % group.name)
				except boto.exception.EC2ResponseError:
					success = False
					print("Failed to delete security group %s" % group.name)

			# Unfortunately, group.revoke() returns True even if a rule was not
			# deleted, so this needs to be rerun if something fails
			if success:
				break

			attempt += 1

		if not success:
			print("Failed to delete all security groups after 3 tries.")
			print("Try re-running in a few minutes.")
