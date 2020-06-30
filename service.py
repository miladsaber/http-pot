from utilz.daemon import Daemon
from http.server import *
import MySQLdb
# import psycopg2

class MiladpotHTTPService(Daemon):
    def run(self):
        conn = MySQLdb.connect(user="Miladpot", passwd="123", db="honeypot")
        # conn = psycopg2.connect(host="127.0.0.1", database="honeypot", user="miladpot", password="123")

        cur = conn.cursor()
        cur.execute("""SELECT http_mode FROM configuration""")
        config = cur.fetchone()
        http_mode = config[0]
        conn.close()
        resource = MiladHTTPServer("/var/fakewww")
        if http_mode == "html":
            pass
        elif http_mode == "php" or http_mode == "perl":
            resource.processors = {".php": PHPScript}
            resource.indexNames = ['index.php']

        site = MiladSite(resource) # MiladSite : server.Site Child / Portocol : channel / RequestFactory : ...

        reactor.listenTCP(80, site)
        print "MiladpotHTTP Server Started ..."
        reactor.run()