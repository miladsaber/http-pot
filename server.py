import cgi
import copy
import json
import time
from urlparse import urlparse

from twisted.internet import reactor
from twisted.internet.defer import gatherResults, Deferred
from twisted.web import static, server, resource, script
from twisted.web.twcgi import *
from twisted.python import log, filepath, failure
from twisted.python.compat import networkString, escape, nativeString, intToBytes

from twisted.web import http # AvaRequest
from twisted.web.http import unquote # AvaRequest

from twisted.web.error import UnsupportedMethod

##########################################
from http.channel import AvaHTTPChannel
from http.models import *
from http.config import get_server_ip
from general import *
import datetime
from twisted.internet.defer import gatherResults
import avaReporter

supportedMethods = (b'GET', b'HEAD', b'POST')

version = networkString('Apache httpd 2.3.10')

NOT_DONE_YET = 1


class AvaHTTPErrorPage(resource.Resource):
    """
    L{ErrorPage} is a resource which responds with a particular
    (parameterized) status and a body consisting of HTML containing some
    descriptive text.  This is useful for rendering simple error pages.

    @ivar template: A native string which will have a dictionary interpolated
        into it to generate the response body.  The dictionary has the following
        keys:

          - C{"code"}: The status code passed to L{ErrorPage.__init__}.
          - C{"brief"}: The brief description passed to L{ErrorPage.__init__}.
          - C{"detail"}: The detailed description passed to
            L{ErrorPage.__init__}.

    @ivar code: An integer status code which will be used for the response.
    @type code: C{int}

    @ivar brief: A short string which will be included in the response body as
        the page title.
    @type brief: C{str}

    @ivar detail: A longer string which will be included in the response body.
    @type detail: C{str}
    """

    template = """
<html>
    <head>
        <title>%(code)s %(brief)s</title>
    </head>
    <body>
        <h1>%(brief)s</h1>
        <p>%(detail)s</p>
        <hr>
        <address>Apache/2.3.10 (Ubuntu) Server at """ + get_server_ip() + """ Port 80</address>
    </body>
</html>
"""

    def __init__(self, status, brief, detail):
        resource.Resource.__init__(self)
        self.code = status
        self.brief = brief
        self.detail = detail


    def render(self, request):
        request.setResponseCode(self.code)
        request.setHeader(b"content-type", b"text/html; charset=utf-8")
        interpolated = self.template % dict(
            code=self.code, brief=self.brief, detail=self.detail)
        if isinstance(interpolated, unicode):
            return interpolated.encode('utf-8')
        return interpolated


    def getChild(self, chnam, request):
        return self


class AvaRequest(server.Request):

    def process(self):
        """
        Process a request.
        """

        # get site from channel
        self.site = self.channel.site

        # set various default headers
        self.setHeader(b'server', version)
        self.setHeader(b'date', http.datetimeToString())

        # Resource Identification
        self.prepath = []
        self.postpath = list(map(unquote, self.path[1:].split(b'/')))

        try:
            resrc = self.site.getResourceFor(self)
            if resource._IEncodingResource.providedBy(resrc):
                encoder = resrc.getEncoder(self)
                if encoder is not None:
                    self._encoder = encoder
            self.render(resrc)
        except:
            self.processingFailed(failure.Failure())

    def render(self, resrc):
        """
        Ask a resource to render itself.

        @param resrc: a L{twisted.web.resource.IResource}.
        """
        try:
            body = resrc.render(self)
        except UnsupportedMethod as e:
            allowedMethods = e.allowedMethods
            if (self.method == b"HEAD") and (b"GET" in allowedMethods):
                # We must support HEAD (RFC 2616, 5.1.1).  If the
                # resource doesn't, fake it by giving the resource
                # a 'GET' request and then return only the headers,
                # not the body.
                log.msg("Using GET to fake a HEAD request for %s" %
                        (resrc,))
                self.method = b"GET"
                self._inFakeHead = True
                body = resrc.render(self)

                if body is NOT_DONE_YET:
                    log.msg("Tried to fake a HEAD request for %s, but "
                            "it got away from me." % resrc)
                    # Oh well, I guess we won't include the content length.
                else:
                    self.setHeader(b'content-length', intToBytes(len(body)))

                self._inFakeHead = False
                self.method = b"HEAD"
                self.write(b'')
                self.finish()
                return

            if self.method in (supportedMethods):
                # We MUST include an Allow header
                # (RFC 2616, 10.4.6 and 14.7)
                self.setHeader(b'Allow', b', '.join(allowedMethods))
                s = ('''Your browser approached me (at %(URI)s) with'''
                     ''' the method "%(method)s".  I only allow'''
                     ''' the method%(plural)s %(allowed)s here.''' % {
                         'URI': escape(nativeString(self.uri)),
                         'method': nativeString(self.method),
                         'plural': ((len(allowedMethods) > 1) and 's') or '',
                         'allowed': ', '.join(
                            [nativeString(x) for x in allowedMethods])
                     })
                epage = AvaHTTPErrorPage(http.NOT_ALLOWED,
                                           "Method Not Allowed", s)
                body = epage.render(self)
            else:
                epage = AvaHTTPErrorPage(
                    http.NOT_IMPLEMENTED, "Huh?",
                    "I don't know how to treat a %s request." %
                    (escape(self.method.decode("charmap")),))
                body = epage.render(self)
        # end except UnsupportedMethod

        if body == NOT_DONE_YET:
            return
        if not isinstance(body, bytes):
            body = AvaHTTPErrorPage(
                http.INTERNAL_SERVER_ERROR,
                "Request did not return bytes",
                "Request: " + util._PRE(reflect.safe_repr(self)) + "<br />" +
                "Resource: " + util._PRE(reflect.safe_repr(resrc)) + "<br />" +
                "Value: " + util._PRE(reflect.safe_repr(body))).render(self)

        if self.method == b"HEAD":
            if len(body) > 0:
                # This is a Bad Thing (RFC 2616, 9.4)
                log.msg("Warning: HEAD request %s for resource %s is"
                        " returning a message body."
                        "  I think I'll eat it."
                        % (self, resrc))
                self.setHeader(b'content-length',
                               intToBytes(len(body)))
            self.write(b'')
        else:
            self.setHeader(b'content-length',
                           intToBytes(len(body)))
            self.write(body)
        self.finish()


def getTypeAndEncoding(filename, types, encodings, defaultType):
    p, ext = filepath.FilePath(filename).splitext()
    ext = filepath._coerceToFilesystemEncoding('', ext.lower())
    if ext in encodings:
        enc = encodings[ext]
        ext = os.path.splitext(p)[1].lower()
    else:
        enc = None
    type = types.get(ext, defaultType)
    return type, enc


class AvapotHTTPServer(static.File):

    reporter = avaReporter.Reporter()

    def directoryListing(self):
        return self.childNotFound

    def render_HEAD(self, request):
        data = {
            "cookie": json.dumps(request.received_cookies),
            "url_requested": request.path,
            "method": request.method,
            "user_agent": request.user_agent or None,
            "status_code": request.code,
            "data": self.get_query(request)}
        attack_obj = {
            'attack_time': time.time(),
            'attacker_ip': request.transport.getPeer().host,
            'interface_ip': request.transport.getHost().host,
            'type': 'connection',
            'protocol': 'http',
            'extra': json.dumps(data)}
        self.reporter.report(attack_obj)
        return self.render_GET(request)

    def render_GET(self, request):
        if request.method == "GET":
            data = {
                "cookie": json.dumps(request.received_cookies),
                "url_requested": request.path,
                "method": request.method,
                "user_agent": request.user_agent or None,
                "status_code": request.code,
                "data": self.get_query(request)
                }
            attack_obj = {
                'attack_time': time.time(),
                'attacker_ip': request.transport.getPeer().host,
                'interface_ip': request.transport.getHost().host,
                'type': 'connection',
                'protocol': 'http',
                'extra': json.dumps(data)}
            self.reporter.report(attack_obj)

        return static.File.render_GET(self, request)

    def render_POST(self, request):
        """This method approuces when http_mode set as html """
        if request.method == "POST":

            self.headers = request.getAllHeaders()
            self.files_posted = cgi.FieldStorage(
                fp = request.content,
                headers = self.headers,
                environ = {'REQUEST_METHOD':'POST',
                         'CONTENT_TYPE': self.headers['content-type'],
                         }
            )
            data = {
                "cookie": json.dumps(request.received_cookies),
                "url_requested": request.path,
                "method": request.method,
                "user_agent": request.user_agent or None,
                "status_code": request.code,
                "data": self.get_query(request)}
            attack_obj = {
                'attack_time': time.time(),
                'attacker_ip': request.transport.getPeer().host,
                'interface_ip': request.transport.getHost().host,
                'type': 'connection',
                'protocol': 'http',
                'extra': json.dumps(data)}
            self.reporter.report(attack_obj)

            return static.File.render_GET(self, request)

    def get_query(self, request):
        query = ""
        if request.method == "GET":
            # nothing to care about
            query = urlparse(request.path).query
        elif request.method =='POST':
            if request.content_type is None:
                return query
            elif request.contenct_type is not None:
                if request.contet_type.startswith("multipart/form-data"):
                    # normal form and data should be handled like login form
                    query = json.dumps(request.args)
                elif request.content_type.startswith("multipart/form-data"):
                    # there's a file should be handled
                    if self.is_there_file(request) == 0:
                        query = ""
                    elif self.is_there_file(request) == 1:
                        query = "file"
                    elif self.is_there_file(request) > 1:
                        query = "file"
        return query

    def is_there_file(self, request):
        count = 0

        for i in self.files_posted:
            # print self.files_posted[i].filename
            if self.files_posted[i].filename != None and self.files_posted[i].filename != "":
                count += 1
        return count

    def check_file(self, connection, request):
        if request.method == "POST" and request.content_type.startswith("multipart/form-data"):
            for i in self.files_posted:
                if self.files_posted[i].filename != None:
                    af = AttackerFile(name=self.files_posted[i].filename,
                                      connection_id=connection.id,
                                      attacker_id=self.attacker.id)
                    af.save().addCallback(self.save_file, self.files_posted[i])

    def save_file(self, af, _file):
        out = open("/opt/avapot_core/uploaded_files/http/%d" % af.id, 'wb')
        out.write(_file.value)
        out.close()


class PHPScript(FilteredScript):
    filter = '/usr/bin/php-cgi' # Points to the php parser

    def render(self, request):
        """
        Do various things to conform to the CGI specification.

        I will set up the usual slew of environment variables, then spin off a
        process.

        @type request: L{twisted.web.http.Request}
        @param request: An HTTP request.
        """
        script_name = "/" + "/".join(request.prepath)
        serverName = request.getRequestHostname().split(':')[0]
        env = {"SERVER_SOFTWARE":   version,
               "SERVER_NAME":       serverName,
               "GATEWAY_INTERFACE": "CGI/1.1",
               "SERVER_PROTOCOL":   request.clientproto,
               "SERVER_PORT":       str(request.getHost().port),
               "REQUEST_METHOD":    request.method,
               "SCRIPT_NAME":       script_name, # XXX
               "SCRIPT_FILENAME":   self.filename,
               "REQUEST_URI":       request.uri,
               "SUDO_COMMAND":      "/usr/bin/php-cgi",
        }

        ip = request.getClientIP()
        if ip is not None:
            env['REMOTE_ADDR'] = ip
        pp = request.postpath
        if pp:
            env["PATH_INFO"] = "/" + "/".join(pp)

        if hasattr(request, "content"):
            # request.content is either a StringIO or a TemporaryFile, and
            # the file pointer is sitting at the beginning (seek(0,0))
            request.content.seek(0,2)
            length = request.content.tell()
            request.content.seek(0,0)
            env['CONTENT_LENGTH'] = str(length)

        try:
            qindex = request.uri.index('?')
        except ValueError:
            env['QUERY_STRING'] = ''
            qargs = []
        else:
            qs = env['QUERY_STRING'] = request.uri[qindex+1:]
            if '=' in qs:
                qargs = []
            else:
                qargs = [urllib.unquote(x) for x in qs.split('+')]

        # Propagate HTTP headers
        for title, header in request.getAllHeaders().items():
            envname = title.replace('-', '_').upper()
            if title not in ('content-type', 'content-length'):
                envname = "HTTP_" + envname
            env[envname] = header
        # Propagate our environment
        for key, value in os.environ.items():
            if key not in env:
                env[key] = value
        # And they're off!
        self.runProcess(env, request, qargs)
        return server.NOT_DONE_YET

    def runProcess(self, env, request, qargs=[]):
        env['REDIRECT_STATUS'] = ''
        return FilteredScript.runProcess(self, env, request, qargs)


class AvaSite(server.Site):
    protocol = AvaHTTPChannel
    requestFactory = AvaRequest
    displayTracebacks = False
