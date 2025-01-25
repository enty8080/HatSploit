"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import socket

from typing import Tuple, Optional

from hatsploit.lib.ui.option import (
    IPv4Option,
    PortOption,
    IntegerOption
)

from hatsploit.lib.core.handler import PayloadHandler

from hatsploit.lib.ui.jobs import Job

from hatsploit.lib.core.session import Session
from hatsploit.lib.core.session.misc import HatSploitSession

from pex.proto.tcp import TCPListener, TCPTools


class ReverseTCPHandler(PayloadHandler):
    """ Subclass of hatsploit.lib.core.handler module.

    This subclass of hatsploit.lib.core.handler is an interface
    for handling reverse TCP payloads.
    """

    def __init__(self, info: dict = {}) -> None:
        """ Initialize reverse TCP handler.

        :param dict info: mixin info
        :return None: None
        """

        super().__init__(info)

        self.lhost = IPv4Option(
            'LHOST',
            TCPTools.get_local_host(),
            "Host to start TCP listener on.",
            required=True,
        )
        self.lport = PortOption(
            'LPORT',
            8888,
            "Port to start TCP listener on.",
            required=True,
        )

        self.listen_timeout = IntegerOption(
            'HANDLER::TIMEOUT',
            None,
            "TCP listener timeout.",
            required=False,
            advanced=True
        )

        self.rhost = IPv4Option(
            'RHOST',
            TCPTools.get_local_host(),
            "Host for payload to connect to.",
            required=True,
        )
        self.rport = PortOption(
            'RPORT',
            8888,
            "Port for payload to connect to.",
            required=True,
        )

        self.type = "reverse_tcp"

    def handle_implant(self, client: socket.socket) -> Session:
        """ Handle final stage of payload (implant).

        :param socket.socket client: client
        :return Session: session
        """

        session = self.info.get('Session', HatSploitSession)()
        session.open(client)

        return session

    def handle_all(self, *args, **kwargs) -> Tuple[socket.socket, list]:
        """ Handle payload.

        :return Tuple[socket.socket, list]: client and address
        """

        job = kwargs.get('job', None)

        listener = TCPListener(
            self.lhost.value,
            self.lport.value,
            self.listen_timeout.value
        )

        def shutdown_submethod(server):
            self.print_process(f"Terminating TCP listener on port {str(self.lport.value)}...")

            try:
                server.stop()
            except RuntimeError:
                return

        if job:
            job.set_exit(target=shutdown_submethod, args=(listener,))

        self.print_process(f"Starting TCP listener on port {str(self.lport.value)}...")

        listener.listen()
        listener.accept()

        address = listener.address
        client = listener.client

        self.print_process(
            f"Establishing connection ({address[0]}:{str(address[1])} -> {self.lhost.value}:{str(self.lport.value)})...")
        listener.stop()

        return client, address
