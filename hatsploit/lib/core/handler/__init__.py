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
import datetime

from hatsploit.lib.base import BaseMixin

from typing import (
    Optional,
    Callable,
    Tuple,
    Any,
    Union
)

from pex.proto.tcp import TCPTools

from hatsploit.lib.ui.option import BooleanOption
from hatsploit.lib.complex import (
    PayloadOption,
    DropperOption
)

from hatsploit.lib.ui.sessions import Sessions
from hatsploit.lib.pseudo import Pseudo

from hatsploit.lib.core.session import Session
from hatsploit.lib.core.payload import Payload
from hatsploit.lib.core.module import Module

from hatsploit.lib.core.handler.send import Send

from hatsploit.lib.complex import EncoderOption


class PayloadHandler(BaseMixin):
    """ Main class of hatsploit.lib.core.handler module.

    This main class of hatsploit.lib.core.handler module is intended
    for providing handler wrapper for payload.
    """

    def __init__(self, info: dict = {}) -> None:
        """ Initialize handler mixin.

        :param dict info: mixin info
        :return None: None
        """

        super().__init__(info)

        self.type = None
        self.encoder = EncoderOption(
            'ENCODER',
            None,
            "Encoder to use.",
            False
        )

    def handle_implant(self, client: Any) -> Session:
        """ Handle final stage of payload (implant).

        :param Any client: client (normally socket.socket)
        :return Session: session
        """

        return

    def handle_all(self, *args, **kwargs) -> Tuple[Any, list]:
        """ Handle payload.

        :return Tuple[Any, list]: client and address
        (index 0 - host, index 1 - port)
        """

        return None, ()


class Handler(BaseMixin, Sessions):
    """ Main class of hatsploit.lib.handler module.

    This main class of hatsploit.lib.handler module is intended
    for providing tools for working with payloads and sessions.
    """

    def __init__(self, info: dict = {}) -> None:
        """ Initialize handler mixin.

        :param dict info: mixin info
        :return None: None
        """

        super().__init__(info)

        self.payload = PayloadOption(
            'PAYLOAD',
            None,
            "Payload to use.",
            True,
            object=Module
        )
        self.pseudo = BooleanOption(
            'HANDLER::PSEUDO',
            'no',
            "Use pseudo shell instead of payload.",
            False,
            object=Module,
            advanced=True
        )
        self.dropper = DropperOption(
            'HANDLER::DROPPER',
            'auto',
            "Method used to deliver payload.",
            False,
            object=Module,
            advanced=True
        )

    def open_session(self, session: Session,
                     on_session: Optional[Callable[..., Any]] = None,
                     info: Optional[dict] = {}) -> None:
        """ Open session and interact with it if allowed.

        Note: This method does not open session, it just saves opened session to the
        local storage and interacts with it if allowed.

        :param Session session: session object
        :param Optional[Callable[..., Any]] on_session: function of an action that
        should be performed right after session was opened
        :param Optional[dict] info: session info to add
        :return None: None
        """

        if info:
            session.info.update(info)

        session_id = self.add_session(session)
        time = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

        session.info.update({
            'Time': time
        })

        self.print_success(
            f"{session.info['Type'].title()} session {str(session_id)} opened at {time}!")

        if on_session:
            on_session()

        if self.get_auto_interaction():
            self.interact_with_session(session_id)

    def module_handle(self, *args, **kwargs) -> None:
        """ Handle session from module.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if not self.payload.value:
            raise RuntimeError("Module has not payload!")

        if self.pseudo.value:
            sender = kwargs.pop('sender', None)

            if sender:
                return Pseudo().shell(sender)

        self.handle(
            payload=self.payload,
            *args, **kwargs
        )

    def handle(self, payload: PayloadOption,
               on_session: Optional[Callable[..., Any]] = None,
               **kwargs) -> None:
        """ Handle session.

        :param PayloadOption payload: payload option object
        :param Optional[Callable[..., Any]] on_session: function of an action that
        should be performed right after session was opened
        :return None: None
        """

        if not payload.mixin.inline:
            result = Send().drop_payload(
                payload=payload,
                dropper=self.dropper,
                **kwargs
            )

        else:
            result = Send().inline_payload(
                payload=payload,
                **kwargs
            )

        if not result:
            raise RuntimeWarning("Payload sent, but no session was opened.")

        session, address = result
        print(session, address)

        if session:
            self.open_session(
                session=session,
                on_session=on_session,
                info={
                    'Platform': payload.info['Platform'],
                    'Arch': payload.info['Arch'],
                    'Host': address[0],
                    'Port': address[1]
                }
            )

    def module_handle_session(self, on_session: Optional[Callable[..., Any]] = None,
                              *args, **kwargs) -> None:
        """ Handle session from module.

        :param Optional[Callable[..., Any]] on_session: function of an action that
        should be performed right after session was opened
        :return None: None
        """

        session, address = Send().handle_session(
            payload=self.payload,
            *args, **kwargs
        )

        if session:
            self.open_session(
                session=session,
                on_session=on_session,
                info={
                    'Platform': self.payload.info['Platform'],
                    'Arch': self.payload.info['Arch'],
                    'Host': address[0],
                    'Port': address[1]
                }
            )
