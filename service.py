from utilz.daemon import Daemon
from http.server import *
import MySQLdb
# import psycopg2

class AvapotHTTPService(Daemon):
    def run(self):
        conn = MySQLdb.connect(user="avapot", passwd="123", db="honeypot")
        # conn = psycopg2.connect(host="127.0.0.1", database="honeypot", user="saboney", password="123")

        cur = conn.cursor()
        cur.execute("""SELECT http_mode FROM configuration""")
        config = cur.fetchone()
        http_mode = config[0]
        conn.close()
        resource = AvapotHTTPServer("/var/fakewww")
        if http_mode == "html":
            pass
        elif http_mode == "php" or http_mode == "perl":
            resource.processors = {".php": PHPScript}
            resource.indexNames = ['index.php']

        site = AvaSite(resource) # AvaSite : server.Site Child / Portocol : channel / RequestFactory : ...

        reactor.listenTCP(80, site)
        print "AvapotHTTP Server Started ..."
        reactor.run()