#!/usr/bin/env python
# filename: progbar.py


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

import sys
from datetime import datetime


def progress_bar(finished, total, start_time=None):
    pct = int(100. * finished / total)
    ticks = pct / 2
    spaces = 50 - ticks
    if start_time is not None:
        elapsed = (datetime.now() - start_time).seconds
        minutes = elapsed / 60
        seconds = elapsed % 60
        minute_str = '0' * (2 - len(str(minutes))) + str(minutes)
        second_str = '0' * (2 - len(str(seconds))) + str(seconds)
        prog_bar = '\r({}/{}) |{}{}|  {}% ({}:{})'.format(finished, total,
            '|' * ticks, ' ' * spaces, pct, minute_str, second_str)
    else:
        prog_bar = '\r({}/{}) |{}{}|  {}%  '.format(finished, total,
            '|' * ticks, ' ' * spaces, pct)
    sys.stdout.write(prog_bar)
    sys.stdout.flush()
