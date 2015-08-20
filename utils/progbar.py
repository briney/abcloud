#!/usr/bin/env python
# filename: progbar.py


from __future__ import print_function

import sys
from datetime import datetime


def distribute_ssh_keys_progbar(finished, total, name):
	pct = int(100. * finished / total)
	ticks = pct / 2
	spaces = 50 - ticks
	prog_bar = '\r({}/{}) |{}{}|  {}% ({})'.format(finished, total, '|' * ticks, ' ' * spaces, pct, name)
	sys.stdout.write(prog_bar)
	sys.stdout.flush()


def cluster_state_progbar(finished, total, start):
	pct = int(100. * finished / total)
	ticks = pct / 2
	spaces = 50 - ticks
	elapsed = (datetime.now() - start).seconds
	minutes = elapsed / 60
	seconds = elapsed % 60
	minute_str = '0' * (2 - len(str(minutes))) + str(minutes)
	second_str = '0' * (2 - len(str(seconds))) + str(seconds)
	prog_bar = '\r({}/{}) |{}{}|  {}% ({}:{})'.format(finished, total,
		'|' * ticks, ' ' * spaces, pct, minute_str, second_str)
	sys.stdout.write(prog_bar)
	sys.stdout.flush()
