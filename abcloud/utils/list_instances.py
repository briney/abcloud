#!/usr/bin/env python
# filename: list_instances.py


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


import json
import os
import sys

# from utils import ec2utils
# from utils.cluster import run_remote_cmd


def list_instances(conn, opts):
    all_groups = conn.get_all_security_groups()
    abcloud_groups = sorted(list(set(['-'.join(g.name.split('-')[1:-1]) for g in all_groups if g.name.startswith('@abcloud')])))
    print_groups_info(abcloud_groups)
    for ag in abcloud_groups:
        master_instances, worker_instances = ec2utils.get_existing_cluster(conn, opts, ag, quiet=True)
        print_cluster_info(ag, master_instances, worker_instances, opts)


def print_groups_info(groups):
    print('\nFound {} AbCloud clusters:\n{}\n'.format(len(groups), ', '.join(groups)))


def print_cluster_info(name, masters, workers, opts):
    cname_string = '     {}     '.format(name)
    cfg = get_config(masters[0], opts)
    print('\n{}'.format(cname_string))
    print('=' * len(cname_string))
    region = masters[0].placement

    if len(masters) + len(workers) == 0:
        print('No instances found.')

    else:
        mcount = len(masters)
        wcount = len(workers)
        mtype = masters[0].instance_type
        mips = ', '.join([m.ip_address for m in masters])
        mplural = 'es' if mcount > 1 else ''
        print('size: {}'.format(mcount + wcount))
        print('region: {}'.format(region))
        print('')
        print('number of master instances: {}'.format(mcount))
        print('master instance type: {}'.format(mtype))
        print('master instance IP address{}: {}'.format(mplural, mips))

        if workers:
            wtype = workers[0].instance_type
            wips = ', '.join([w.ip_address for w in workers])
            wplural = 'es' if wcount > 1 else ''
            print('')
            print('number of worker instances: {}'.format(wcount))
            print('worker instance type: {}'.format(wtype))
            print('worker instance IP address{}: {}'.format(wplural, wips))

        if cfg:
            if cfg['basespace']:
                print('\nBaseSpace credentials have been uploaded')
            elif check_for_basespace_credentials(master, opts):
                print('\nBaseSpace credentials have been uploaded')
            if cfg['mongo']:
                print('\nMaster node is configured as a MongoDB server.')
                print('MongoDB database is located at: {}'.format(os.path.join(opts.master_ebs_raid_dir, 'db')))
            if cfg['jupyter']:
                jupyter_location = 'http://{}:{}'.format(masters[0].ip_address, cfg['jupyter_port'])
                print('\nMaster node is configured as a Jupyter notebook server.')
                print("Jupyter notebook URL: {}".format(jupyter_location))
                print('Jupyter password: {}'.format(cfg['jupyter_password']))
            if cfg['celery'] and workers:
                total, running = get_celery_info(masters[0], opts)
                print('\nCluster is configured to use Celery.')
                print('Number of Celery workers: {}'.format(total))
                print("Workers reporting 'OK' status: {}".format(running))
                print('Flower is available at: http://{}:5555'.format(masters[0].ip_address))
    print('')


def get_config(master, opts):
    get_config_cmd = 'cat /home/ubuntu/.abcloud_config'
    cfg_string = run_remote_cmd(master.ip_address, opts, get_config_cmd)[0]
    if cfg_string.strip():
        cfg = json.loads(cfg_string)
        return cfg
    return None


def get_celery_info(master, opts):
    celery_info_cmd = 'cd /abstar && /home/ubuntu/anaconda/bin/celery -A utils.queue.celery status'
    info = run_remote_cmd(master.ip_address, opts, celery_info_cmd)[0]
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


def check_for_basespace_credentials(master, opts):
    cred_dir = '/home/{}/.abstar/'.format(opts.user)
    cred_cmd = 'ls %s' % cred_dir
    stdout, stderr = run_remote_cmd(master, opts, cred_cmd)
    if 'basespace_credentials' in stdout:
        return True
    return False
