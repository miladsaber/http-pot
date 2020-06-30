
import MySQLdb
# import psycopg2

def get_server_ip():
	conn = MySQLdb.connect(user="avapot", passwd="123", db="honeypot")
	# conn = psycopg2.connect(host="127.0.0.1", database="honeypot", user="saboney", password="123")

	cur = conn.cursor()
	cur.execute("""SELECT http_mode FROM configuration""")
	config = cur.fetchone()
	http_mode = config[0]
	cur.execute("""SELECT is_management, address FROM network_config""")
	for result in cur.fetchall():
	    if result[0] == True:
	        return result[1]