#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2021 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from hatsploit.core.cli.badges import Badges
from hatsploit.core.cli.colors import Colors
from hatsploit.core.cli.fmt import FMT
from hatsploit.core.cli.parser import Parser
from hatsploit.core.cli.tables import Tables


class Session(FMT, Badges, Colors, Parser, Tables):
    details = {
        'Platform': "",
        'Type': ""
    }

    def open(self, client):
        pass

    def close(self):
        pass

    def heartbeat(self):
        pass

    def send_command(self, command, output=False, timeout=10, decode=True):
        return None

    def download(self, remote_file, local_path, timeout=None):
        pass

    def upload(self, local_file, remote_path, timeout=None):
        pass

    def interact(self):
        pass
