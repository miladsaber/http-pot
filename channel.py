# -*- coding: utf-8 -*-

import time
import json
import cgi
from urlparse import urlparse

from twisted.protocols import policies, basic
from twisted.web.server import Request
from twisted.web.http import _IdentityTransferDecoder
from models import *
from twisted.python import log

from twisted.web.http import _MalformedChunkedDataError


def _respondToBadRequestAndDisconnect(transport):
    """
    This is a quick and dirty way of responding to bad requests.

    As described by HTTP standard we should be patient and accept the
    whole request from the client before sending a polite bad request
    response, even in the case when clients send tons of data.

    @param transport: Transport handling connection to the client.
    @type transport: L{interfaces.ITransport}
    """
    transport.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    transport.loseConnection()

class AvaHTTPChannel(basic.LineReceiver, policies.TimeoutMixin):
    """
    A receiver for HTTP requests.

    @ivar MAX_LENGTH: Maximum length for initial request line and each line
        from the header.

    @ivar _transferDecoder: C{None} or a decoder instance if the request body
        uses the I{chunked} Transfer-Encoding.
    @type _transferDecoder: L{_ChunkedTransferDecoder}

    @ivar maxHeaders: Maximum number of headers allowed per request.
    @type maxHeaders: C{int}

    @ivar totalHeadersSize: Maximum bytes for request line plus all headers
        from the request.
    @type totalHeadersSize: C{int}

    @ivar _receivedHeaderSize: Bytes received so far for the header.
    @type _receivedHeaderSize: C{int}
    """

    maxHeaders = 500
    totalHeadersSize = 16384
    __timeoutCall = None


    length = 0
    persistent = 1
    __header = ''
    __first_line = 1
    __content = None

    # set in instances or subclasses
    requestFactory = Request

    _savedTimeOut = None
    _receivedHeaderCount = 0
    _receivedHeaderSize = 0

    attacker = None

    def __init__(self):
        # the request queue
        self.requests = []
        self._transferDecoder = None

    def connectionMade(self):
        self.setTimeout(10)

    def lineReceived(self, line):
        """
        Called for each line from request until the end of headers when
        it enters binary mode.
        """
        self.resetTimeout()

        self._receivedHeaderSize += len(line)
        if (self._receivedHeaderSize > self.totalHeadersSize):
            _respondToBadRequestAndDisconnect(self.transport)
            self.save_in_db(line, [400, "BAD REQUEST"])
            return

        if self.__first_line:
            # if this connection is not persistent, drop any data which
            # the client (illegally) sent after the last request.
            if not self.persistent:
                self.dataReceived = self.lineReceived = lambda *args: None
                return

            # IE sends an extraneous empty line (\r\n) after a POST request;
            # eat up such a line, but only ONCE
            if not line and self.__first_line == 1:
                self.__first_line = 2
                return

            # create a new Request object
            request = self.requestFactory(self, len(self.requests))
            self.requests.append(request)
            # print dir(self.requests[0])

            self.__first_line = 0
            parts = line.split()
            if len(parts) != 3:
                _respondToBadRequestAndDisconnect(self.transport)
                return
            command, request, version = parts
            self._command = command
            self.command_requested =self._command
            self._path = request
            self.url_requested = self._path
            self._version = version
        elif line == b'':
            # End of headers.
            if self.__header:
                self.headerReceived(self.__header)
            self.__header = ''
            self.allHeadersReceived()
            if self.length == 0:
                self.allContentReceived()
            else:
                self.setRawMode()
        elif line[0] in b' \t':
            # Continuation of a multi line header.
            self.__header = self.__header + '\n' + line
        # Regular header line.
        # Processing of header line is delayed to allow accumulating multi
        # line headers.
        else:
            if self.__header:
                self.headerReceived(self.__header)
            self.__header = line


    def _finishRequestBody(self, data):
        self.allContentReceived()
        self.setLineMode(data)


    def headerReceived(self, line):
        """
        Do pre-processing (for content-length) and store this header away.
        Enforce the per-request header limit.

        @type line: C{bytes}
        @param line: A line from the header section of a request, excluding the
            line delimiter.
        """
        header, data = line.split(b':', 1)
        header = header.lower()
        data = data.strip()

        if header == b'content-length':
            try:
                self.length = int(data)
            except ValueError:
                _respondToBadRequestAndDisconnect(self.transport)
                self.length = None
                return
            self._transferDecoder = _IdentityTransferDecoder(
                self.length, self.requests[-1].handleContentChunk, self._finishRequestBody)
        elif header == b'transfer-encoding' and data.lower() == b'chunked':
            # XXX Rather poorly tested code block, apparently only exercised by
            # test_chunkedEncoding
            self.length = None
            self._transferDecoder = _ChunkedTransferDecoder(
                self.requests[-1].handleContentChunk, self._finishRequestBody)
        elif header == b'user-agent':
            self.requests[-1].user_agent = data

        reqHeaders = self.requests[-1].requestHeaders
        self.requests[-1].content_type = reqHeaders._rawHeaders.get('content-type')
        if self.requests[-1].content_type:
            self.requests[-1].content_type = self.requests[-1].content_type[0]

        # self.user_agent = reqHeaders['']
        values = reqHeaders.getRawHeaders(header)
        if values is not None:
            values.append(data)
        else:
            reqHeaders.setRawHeaders(header, [data])

        self._receivedHeaderCount += 1
        if self._receivedHeaderCount > self.maxHeaders:
            _respondToBadRequestAndDisconnect(self.transport)
            return


    def allContentReceived(self):
        command = self._command
        path = self._path
        version = self._version

        # reset ALL state variables, so we don't interfere with next request
        self.length = 0
        self._receivedHeaderCount = 0
        self._receivedHeaderSize = 0
        self.__first_line = 1
        self._transferDecoder = None
        del self._command, self._path, self._version

        # Disable the idle timeout, in case this request takes a long
        # time to finish generating output.
        if self.timeOut:
            self._savedTimeOut = self.setTimeout(None)

        req = self.requests[-1]
        req.requestReceived(command, path, version)


    def rawDataReceived(self, data):
        self.resetTimeout()
        try:
            self._transferDecoder.dataReceived(data)
        except _MalformedChunkedDataError:
            _respondToBadRequestAndDisconnect(self.transport)


    def allHeadersReceived(self):
        req = self.requests[-1]
        req.parseCookies()
        self.cookie = self.requests[-1].received_cookies
        self.persistent = self.checkPersistence(req, self._version)
        req.gotLength(self.length)
        # Handle 'Expect: 100-continue' with automated 100 response code,
        # a simplistic implementation of RFC 2686 8.2.3:
        expectContinue = req.requestHeaders.getRawHeaders(b'expect')
        if (expectContinue and expectContinue[0].lower() == b'100-continue' and
            self._version == b'HTTP/1.1'):
            req.transport.write(b"HTTP/1.1 100 Continue\r\n\r\n")

    def checkPersistence(self, request, version):
        """
        Check if the channel should close or not.

        @param request: The request most recently received over this channel
            against which checks will be made to determine if this connection
            can remain open after a matching response is returned.

        @type version: C{bytes}
        @param version: The version of the request.

        @rtype: C{bool}
        @return: A flag which, if C{True}, indicates that this connection may
            remain open to receive another request; if C{False}, the connection
            must be closed in order to indicate the completion of the response
            to C{request}.
        """
        connection = request.requestHeaders.getRawHeaders(b'connection')
        if connection:
            tokens = [t.lower() for t in connection[0].split(b' ')]
        else:
            tokens = []

        # Once any HTTP 0.9 or HTTP 1.0 request is received, the connection is
        # no longer allowed to be persistent.  At this point in processing the
        # request, we don't yet know if it will be possible to set a
        # Content-Length in the response.  If it is not, then the connection
        # will have to be closed to end an HTTP 0.9 or HTTP 1.0 response.

        # If the checkPersistence call happened later, after the Content-Length
        # has been determined (or determined not to be set), it would probably
        # be possible to have persistent connections with HTTP 0.9 and HTTP 1.0.
        # This may not be worth the effort, though.  Just use HTTP 1.1, okay?

        if version == b"HTTP/1.1":
            if b'close' in tokens:
                request.responseHeaders.setRawHeaders(b'connection', [b'close'])
                return False
            else:
                return True
        else:
            return False

    def requestDone(self, request):
        """
        Called by first request in queue when it is done.
        """
        if request != self.requests[0]: raise TypeError
        del self.requests[0]

        if self.persistent:
            # notify next request it can start writing
            if self.requests:
                self.requests[0].noLongerQueued()
            else:
                if self._savedTimeOut:
                    self.setTimeout(self._savedTimeOut)
        else:
            self.transport.loseConnection()

    def save_in_db(self, line, code):
        """ Log Unreadable Request """
        pass