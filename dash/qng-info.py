#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer
import datetime
import socket
import csv
import configparser

# HTML to send to browser
html = """<!DOCTYPE html>
<html>
<head>
<title>QnetGateway D-Star Hotspot</title>
<meta http-equiv="refresh" content="30" >
</head>
<h2>QnetGateway D-Star Hotspot</h2>

<p>This status page shows the Callsign, Frequency, IP address and Connected Reflector for the QnetGateway D-Star Hotspot.</p>
<p><strong>Callsign:</strong> {0}<br>
<strong>Frequency:</strong> {1}MHz<br>
<strong>IP Address:</strong> {2}<br>
<strong>Reflector:</strong> {3}</p>
</html>
"""

data = []
# HTTPRequestHandler class
class HS_HTTPServer_RequestHandler(BaseHTTPRequestHandler):

  # GET
  def do_GET(self):
        # Send response status code
        self.send_response(200)

        # Send headers
        self.send_header('Content-type','text/html')
        self.end_headers()

        # Send message back to client
        data = get_data()
        message = html.format(data[0], data[1], data[2], data[3])
        # Write content as utf-8 data
        self.wfile.write(bytes(message, "utf8"))
        return

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
    with open('/usr/local/etc/RPTR_STATUS.txt') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
          reflector = row[1] + row[2]
    config = configparser.ConfigParser()
    config.read('/usr/local/etc/MMDVM.qn')
    cs = config['General']['callsign']
    rawfreq = config['Info']['txfrequency']
    freq = float(rawfreq)/1000000
    data.append(cs)
    data.append(freq)
    data.append(str(get_ip()))
    data.append(reflector)
    return data

def run():
  print('starting server...')

  # Server settings
  server_address = ('', 80)
  httpd = HTTPServer(server_address, HS_HTTPServer_RequestHandler)
  print('running server...')
  httpd.serve_forever()


run()
