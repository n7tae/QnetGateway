#!/usr/bin/env python
import socket
import datetime
import csv
import configparser
import json
import requests
import subprocess
from time import sleep

# HTML to send to browser
html = """<!DOCTYPE html>
<html>
<head>
<title>QnetGateway D-Star Hotspot</title>
<meta http-equiv="refresh" content="30, url=http://{0}" >
</head>
<h2>QnetGateway D-Star Hotspot</h2>

<p>This status page shows the Callsign, Frequency, IP address and Connected Reflector for the QnetGateway D-Star Hotspot.</p>
<p><strong>Callsign:</strong> {1}<br>
<strong>Modem:</strong> {2}<br>
<strong>Frequency:</strong> {3}MHz<br>
<strong>IP Address:</strong> {4}<br>
<strong>External IP Address:</strong> {5}<br>
<strong>Reflector:</strong> {6}</p>
<form>
<strong>Note:</strong> Please enter a valid 7 character reflector code.</br>
<strong>Link Reflector: </strong> <input type="text" name="LINK"> <input type="submit" value="Link Reflector"></br>
</form>
<form>
<strong>Unlink Reflector: </strong> <button name="UNLINK" value="UL" type="submit">Unlink Reflector</button>
</form>
</html>
"""
data = []
def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# doesn't even have to be reachable
		s.connect(('10.255.255.255', 1))
		IP = s.getsockname()[0]
	except:
		IP = '127.0.0.1'
	finally:
		s.close()
	return IP

def get_data():
	global data
	data = []
	reflector = "Unlinked"
	with open('/usr/local/etc/rptr_status') as csvfile:
		readCSV = csv.reader(csvfile, delimiter=',')
		for row in readCSV:
			reflector = row[1] + row[2]
	data.append(cs)
	data.append(modem)
	data.append(freq)
	data.append(intip)
	data.append(extip)
	data.append(reflector)
	return data

def get_MMDVM():
	MMDVM_config = configparser.ConfigParser()
	MMDVM_config.read('/usr/local/etc/MMDVM.qn')
	rawfreq = MMDVM_config['Info']['txfrequency']
	freq = float(rawfreq)/1000000
	return freq

intip = get_ip()
extip = requests.get('https://ipapi.co/json/').json()['ip']

cfg = dict()
with open('/usr/local/etc/qn.cfg', 'r') as f:
	for line in f:
		if line.strip()[0] == "#":
			continue
		kv = line.strip().split("=")
		cfg[kv[0]] = kv[1].strip("'")

cs = cfg['ircddb_login']
for module in ( 'a', 'b', 'c' ):
	key = 'module_' + module
	if key in cfg:
		modem = cfg[key]
		if modem == 'mmdvmhost':
			freq = get_MMDVM()
		elif key + "_tx_frequency" in cfg:
			freq = cfg[key + "_tx_frequency"]
		elif key + "_frequency" in cfg:
			freq = cfg[key + "_frequency"]
		else:
			freq = 0.0
		break

#Setup Socket WebServer
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 80))
s.listen(5)
while True:
	conn, addr = s.accept()
	request = conn.recv(1024)
	request = str(request)
	UNLINK = request.find('/?UNLINK=UL')
	if UNLINK == 6:
		unlink = "/usr/local/bin/qnremote " + module + " " + cs + " U"
		subprocess.Popen(unlink.split())
		sleep(8)
	LINK = request.find('/?LINK=')
	if LINK == 6:
		refl = request[13:20].upper()
		link = "/usr/local/bin/qnremote " + module + " " + cs + " " + refl + "L"
		subprocess.Popen(link.split())
		sleep(8)

	data = get_data()
	response = html.format(data[3], data[0], data[1], data[2], data[3], data[4], data[5])
	conn.send(bytes(response, "UTF-8"))
	conn.close()
