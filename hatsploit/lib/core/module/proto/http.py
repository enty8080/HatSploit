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

from hatsploit.lib.base import BaseMixin

from pex.proto.http import HTTPClient, HTTPListener

from hatsploit.lib.ui.option import (
    IPv4Option,
    PortOption,
    IntegerOption,
    BooleanOption
)


class HTTP(BaseMixin):
    """ Subclass of hatsploit.lib.module.proto module.

    This subclass of hatsploit.lib.module.proto module is a representation
    of a wrapper of HTTP client for a module.
    """

    def __init__(self, info: dict = {}) -> None:
        """ Initialize HTTP mixin.

        :param dict info: mixin info
        :return None: None
        """

        super().__init__(info)

        self.timeout = IntegerOption('TIMEOUT', 10, "Connection timeout.", False)
        self.host = IPv4Option('HOST', None, "HTTP host.", True)
        self.port = PortOption('PORT', 80, "HTTP port.", True)
        self.ssl = BooleanOption('SSL', 'no', "Use SSL.", False)

    def http_request(self, *args, **kwargs) -> str:
        """ Send request to HTTP server.

        :return str: HTTP response
        """

        return HTTPClient().http_request(
            host=self.host.value,
            port=self.port.value,
            ssl=self.ssl.value,
            timeout=self.timeout.value,
            *args, **kwargs
        )

    def listen_http(self, *args, **kwargs) -> None:
        """ Start HTTP listener.

        :return None: None
        """

        limit = kwargs.get('limit', None)
        job = kwargs.get('job', None)

        def shutdown_submethod(server):
            self.print_process(f"Terminating HTTP server on port {str(self.port.value)}...")

            try:
                server.stop()
            except RuntimeError:
                return

        server = HTTPListener(
            host=self.host.value,
            port=self.port.value,
            *args, **kwargs
        )

        if job:
            job.set_exit(target=shutdown_submethod, args=(server,))

        self.print_process(f"Starting HTTP server on port {str(self.port.value)}...")
        server.listen()

        if limit:
            for _ in range(limit):
                server.accept()
        else:
            while True:
                server.accept()
