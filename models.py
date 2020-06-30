from twisted.enterprise import adbapi
from twistar.registry import Registry
from twistar.dbobject import DBObject

class HttpAttacker(DBObject):
	TABLENAME = "http_attackers"

	# id = Column(Integer, primary_key=True)
	# ip = Column(String(32))
	# count = Column(Integer)
	# last_activity = Column(Integer)


class AttackerConnection(DBObject):
	TABLENAME = "http_attacker_connections"

	# id = Column(Integer, primary_key=True)
	# attacker_id = Column(Integer, ForeignKey("http_attackers.id"))
	# url_requested = Column(String(256))
	# method = Column(String(32))
	# status_code = Column(Integer)
	# cookie = Column(String(256))
	# user_agent = Column(String(256))
	# data = Column(String(256))
	# timestamp = Column(Integer)


class AttackerFile(DBObject):
	TABLENAME = "http_attacker_file"

	# id = Column(Integer, primary_key=True)
	# name = Column(String(64))
	# connection_id = Column(Integer, ForeignKey("http_attacker_connections.id"))


class Configuration(DBObject):
	TABLENAME = "configuration"

    # id = db.Column(db.Integer, primary_key=True)

    # # Honeypot Configuration
    # http = db.Column(db.Boolean, default=False)
    # https = db.Column(db.Boolean, default=False)
    # telnet = db.Column(db.Boolean, default=False)
    # ssh = db.Column(db.Boolean, default=False)
    # ftp = db.Column(db.Boolean, default=False)
    # smb = db.Column(db.Boolean, default=False)
    # database = db.Column(db.Boolean, default=False)

    # http_mode = db.Column(db.String(32), default="html")

    # last_update = db.Column(db.DateTime(), default=datetime.utcnow)


class NetworkConf(DBObject):
	TABLENAME = "network_config"
	
    # id = db.Column(db.Integer, primary_key=True)
    # name = db.Column(db.String(16), nullable=False)

    # sysport = db.Column(db.Integer)

    # is_management = db.Column(db.Boolean, default=False)

    # network_type = db.Column(db.String(32)) # example : static/ dhcp
    # address = db.Column(db.String(64))         # example : 192.168.1.200
    # netmask = db.Column(db.String(64))         # example : 255.255.255.0
    # gateway = db.Column(db.String(64))         # example : 192.168.1.1
    # dns_nameservers = db.Column(db.String(64)) # example : 192.168.1.1
    # alternate_dns = db.Column(db.String(64))
    # # network = db.Column(db.String)         # example : 192.168.1.0
    # # broadcast = db.Column(db.String)       # example : 192.168.1.255

    # proxy = db.Column(db.String(64))
    # proxy_port = db.Column(db.Integer)
    # sys_log_adrress = db.Column(db.String(64))
    # sys_log_port = db.Column(db.Integer)
    # snmp_address = db.Column(db.String(64))
    # snmp_port = db.Column(db.Integer)
    # community = db.Column(db.String(64))


# Registry.DBPOOL = adbapi.ConnectionPool('psycopg2', host="127.0.0.1", user="saboney", password="123", database="honeypot")
Registry.DBPOOL = adbapi.ConnectionPool('MySQLdb', host="localhost" ,user="avapot",port=13306 , passwd="123", db="honeypot", cp_reconnect=True)