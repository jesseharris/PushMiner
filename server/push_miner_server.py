import base64
import BaseHTTPServer
import collections
import hashlib
import httplib
import json
import re
import socket
import struct
import sys
import threading
import time
import urlparse

class BitcoinJSONRPC(object):
    
    def __init__(self, protocol, host, port, path, username, password, timeout):
        self.id = 1
        self.auth_header = "Basic " + base64.b64encode(username + ':' + password)
        self.protocol = protocol
        self.host = host
        self.port = port
        self.path = path
        self.strict = False
        self.timeout = timeout
        self.server_headers = {}
        
    def rpc(self, method, params=None):
        if not params: params = []
        self.id += 1
        
        body = { 'version' : '1.1',
                'method' : method,
                'id' : self.id,
                'params' : params}
        
        headers = {'Authorization' : self.auth_header,
                   'Content-Type' : 'application/json'}
        
        # Make the callout
        conn = None
        if self.protocol.lower() == "https":
            conn = httplib.HTTPSConnection(self.host, self.port, None, None, self.strict, self.timeout)
        elif self.protocol.lower() == "http": 
            conn = httplib.HTTPConnection(self.host, self.port, self.strict, self.timeout)
        else:
            raise Exception("Unsupported Protocol")
        resp = None
        try:
            conn.request("POST", self.path, json.dumps(body), headers)
            resp = conn.getresponse()
        except:
            log.append('JSON-RPC', "Connection error")
            return None
        if resp is None:
            log.append('JSON-RPC', "No response")
            return None

        # Set longpolling
        self.server_headers = dict(resp.getheaders())
        
        # Interpret Response
        try:
            resp_body = resp.read()
        except socket.timeout:
            log.append('JSON-RPC', "Timeout reading from server")
            return None
        resp_obj = json.loads(resp_body)
        if resp_obj is None:
            log.append('JSON-RPC', "Unable to decode JSON body")
            return None
        if "error" in resp_obj and resp_obj['error'] != None:
            log.append('JSON-RPC', "error in response: " + str(resp_obj['error']))
            return None
        if "result" not in resp_obj:
            log.append('JSON-RPC', "No result in JSON")
            return None

        return resp_obj['result']
   
    def get_work(self):
        return self.rpc('getwork')
        # data = solution(nonce = 00075f1f)
        # expected from push miner: Result: {u'nonce': 483103, u'share_found': True, u'nonce_end': 4000000, u'nonce_start': 0}
        #return {u'data': u'000000016ca07287069928b90b978b6652f6f4ae0a48d4f8b5adc6b7000000a000000000685facea94d6583624e0a6ca50221fc5dc0c6253f4e7379aecfd9f2c6c3fee7a4fd4e6a41a0a98d600000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000',
        #        u'hash1': u'00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000',
        #        u'target': u'0000000000000000000000000000000000000000000000000000ffff00000000',
        #        u'midstate': u'9b63b766fdf3e840de7b7da8842c76c1d655418a28e22e0deb020d4bf9d06650'}

    def submit_work(self, params):
        resp = self.rpc('getwork', params)
        return resp

class Work(object):
    
    def __init__(self):
        self.response = None
        self.data = None
        self.nonce_start = 0
        self.nonce_uint_end = int("7FFFFFDF", 16)
        self.nonce_end = int("FFFFFFFF", 16)
        self.nonce_pool_start = self.nonce_start
        self.nonce_pool_end = self.nonce_end
        self.last_update = 0
        
    def reset_nonce_pool(self):
        self.nonce_pool_start = self.nonce_start
        self.nonce_pool_end = self.nonce_end
        
    def get_nonce_range(self, size, uint_support=True):
        # uint support means that the whole nonce range can be sent
        # therefor uint supported requests take range off the top instead
        # of the bottom
        if uint_support:
            start = self.nonce_pool_end - size + 1
            end = self.nonce_pool_end
            if (start >= self.nonce_pool_start):
                self.nonce_pool_end = start - 1
                return (start, end)
            else:
                start = self.nonce_pool_start
                self.nonce_pool_end = start
                return (start, end)
        else: # limited to bottom half of range
            start = self.nonce_pool_start
            end = self.nonce_pool_start + size - 1
            if (end <= self.nonce_uint_end):
                self.nonce_pool_start = end + 1
                return (start, end)
            else:
                end = self.nonce_uint_end
                self.nonce_pool_start = end
                return (start, end)
    
    def get_percentage_remaining(self):
        overall = float(self.nonce_pool_end - self.nonce_pool_start) / float(self.nonce_end - self.nonce_start)
        uint_end = self.nonce_pool_end  
        if uint_end > self.nonce_uint_end:
            uint_end = self.nonce_uint_end
        uint = float(uint_end - self.nonce_pool_start) / float(self.nonce_uint_end - self.nonce_start)
        return (overall, uint)
    
    def need_more(self):
        # if less than 40% nonce space remaining, return True
        overall, uint = self.get_percentage_remaining()
        if overall < .4 or uint <.4:
            return True
        return False
    
      
class GetWorker(threading.Thread):

    def __init__(self, rpc_conn, work, work_lock, longpoller=False):
        threading.Thread.__init__(self)
        self.daemon = True
        self.rpc_conn = rpc_conn
        self.work = work
        self.work_lock = work_lock
        self.longpoller = longpoller
        self.refresh = 60 # seconds - time between manditory getworks
        
    def run(self):
        while True:
            if self.longpoller or self.work.need_more() or (time.time() > self.work.last_update + self.refresh):
                response =  self.rpc_conn.get_work()
                self.work_lock.acquire()
                try:
                    self.response = response
                    self.work.data = response['data']
                    self.work.reset_nonce_pool()
                    self.work.last_update = time.time()
                except:
                    pass
                finally:
                    self.work_lock.release()
            time.sleep(.1)


class PushWorker(threading.Thread):
    def __init__(self, rpc_conn, work, work_lock, name, settings=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.rpc_conn = rpc_conn
        self.work = work
        self.work_lock = work_lock
        self.name = name
        # Settings from settings file
        self.nonce_range_size = settings['nonce_range_size']
        self.uint_support = settings['uint_support']
        self.protocol = settings['protocol']
        self.host = settings['host']
        self.port = settings['port']
        self.path = settings['path']
        self.timeout = settings['timeout']
        self.salt = settings['salt'] # salt must be hexasdecimal byte string
        # instance variables
        self.nonce_start = None
        self.nonce_end = None
        self.data = None
        # Statistics Gathering
        self.work_history = collections.deque([], 1000)
        self.share_history = collections.deque([])
        
    def run(self):
        while True:
            global statistics_lock
            # Do the work and time it
            time_start = time.time()
            result = self.do_work()
            time_end = time.time()
            
            if not result:
                statistics_lock.acquire()
                self.work_history.append({'hash_count': 0, 'time_start': time_start, 'time_end': time_end})
                statistics_lock.release()
                time.sleep(1) # connection error of some kind
                continue
            
            # update statistics tracking
            hash_count = result.get('nonce_end', 0) - result.get('nonce_start', 0)
            if hash_count < 0:
                hash_count = 0
            statistics_lock.acquire()
            self.work_history.append({'hash_count': hash_count, 'time_start': time_start, 'time_end': time_end})
            statistics_lock.release()
            
            
            # submit share if found
            share_found = result.get("share_found", False)
            if share_found:
                log.append(self.name, "Share Found!")
                params = self.prepare_submit(result.get('nonce', 0))
                resp = self.rpc_conn.submit_work(params)
                log.append(self.name, "Share Accepted: " + str(resp))
                statistics_lock.acquire()
                self.share_history.append({'valid': resp, 'time': time_end})
                statistics_lock.release()
            
        
    def do_work(self):
        """ Swap endianess on the data, grab nonce range, encode both, and send to pushminer
        target_hex is currently ignored and standard share is hard coded
        """
        # Lock into current work, get nonce range and data, then release lock
        self.work_lock.acquire()
        self.nonce_start, self.nonce_end = self.work.get_nonce_range(self.nonce_range_size)
        self.data = self.work.data
        self.work_lock.release()
        
        # Swap endian-ness of the data and convert to byte string
        little_endian_data_hex = self.endian_swap_32bit(self.data)
        block_header_byte_string = little_endian_data_hex.decode("hex")[:76] # remove nonce portion and padding
        
        # Generate Signature
        signature = hashlib.sha256(block_header_byte_string + self.salt.decode('hex')).hexdigest()
        
        # encode nonce_start, nonce_end, block_header, signature
        # currently only decimal uint for nonce_start and nonce_end, hex for block_header 
        block_header = block_header_byte_string.encode('hex')
        
        # Make the callout
        conn = None
        if self.protocol.lower() == "https":
            conn = httplib.HTTPSConnection(self.host,
                                           self.port,
                                           None,
                                           None,
                                           False,
                                           self.timeout)
        elif self.protocol.lower() == "http": 
            conn = httplib.HTTPConnection(self.host,
                                          self.port,
                                          False,
                                          self.timeout)
        else:
            raise Exception("Unsupported Protocol")
        args = "?nonce_start=%d&nonce_end=%d&block_header=%s&signature=%s" % (self.nonce_start, self.nonce_end, block_header, signature)
        path = self.path + args
        body = None
        headers = {} 
        resp = None
        try:
            conn.request("GET", path, body, headers)
            resp = conn.getresponse()
        except:
            log.append(self.name, "Connection error")
            return None
        if resp is None:
            log.append(self.name, "No response")
            return None
         
        # only decimal nonce responses accepted
        result = None
        try:
            # check for http responses other than 200 OK
            if not resp.status == 200:
                log.append(self.name, "Bad Server Response: %s %s" % (resp.status, resp.reason))
                return None
            # look for all json dictionarys and attempt to parse and check them
            # this allows for responses to be surrounded by HTML or XML
            resp_body = resp.read()
            for item in re.findall("{.*?}", resp_body): 
                try: 
                    possible_result = json.loads(item)
                    # has all the keys
                    if len(set(['share_found', 'nonce', 'nonce_start', 'nonce_end']).difference(possible_result.keys())) <= 0:
                        return possible_result
                except:
                    pass
            log.append(self.name, "Error parsing JSON from server")
            return None
        except socket.timeout:
            log.append(self.name, "Timeout reading from server")
            return None
        except:
            log.append(self.name, "Generic server response error")
            return None
        return result
                  
    def endian_swap_32bit(self, hex_string):
        """pass a hex string and it will convert from little endian 32 bit(4 bytes)(8 hex characters)to big endian

        Ex: undo_little_endian("A0B1C2D3") -> "D3C2B1A0"
        Ex: undo_little_endian("11223344AABBCCDD") -> "44332211DDCCBBAA"
        """
        return "".join(hex_string[i+6:i+8] + hex_string[i+4:i+6] + hex_string[i+2:i+4] + hex_string[i+0:i+2] for i in xrange(0, len(hex_string), 8))

    def prepare_submit(self, nonce):
        """ accepts a nonce and returns a ['hex_string'] containing the 128 bytes for a param in a getwork RPC request"""
        #only uint nonce currently supported
        # nonce_hex is big endian, just like the original data string
        nonce_hex = struct.pack(">I", long(nonce)).encode('hex')
        return [self.data[:152] + nonce_hex + self.data[160:256]]

class AdminWebserver(threading.Thread):

    class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            global log
            global statistics_lock
            global start_time
            # Favicon handler
            if self.path in ('/customfavicon.ico', '/favicon.ico'):
                self.send_response(200)
                self.send_header("Content-type", "image/x-icon")
                self.send_header("Cache-Control", "max-age=3600, must-revalidate")
                self.end_headers()
                self.wfile.write(("0000010001001010020000000000b000000016000000280000001000000020000000010" + 
                           "00100000000004000000000000000000000000200000000000000ff2f000000000000c6490000c64" +
                           "90000c6490000c6490000c6010000c6230000c67f0000c07f0000c03f0000c01f0000c71f0000c71" +
                           "f0000c71f0000c01f0000c03f0000c07f0000c6490000c6490000c6490000c6490000c6010000c62" +
                           "30000c67f0000c07f0000c03f0000c01f0000c71f0000c71f0000c71f0000c01f0000c03f0000c07" +
                           "f0000").decode('hex'))
                return
            # Gather statistics
            statistics_lock.acquire()
            worker_stats = {} # by name
            group_stats = {} # by name.split(':')[0]
            for worker in self.server.thread_list:
                worker_stat = {}
                worker_stat['hash_rate'], worker_stat['hash_rate_5min'] = self.get_hash_rates(worker)
                worker_stat['average_work_time'] = self.get_average_work_time(worker)
                worker_stat['shares'] = len(worker.share_history)
                worker_stat['shares_invalid'] = sum(not share['valid'] for share in worker.share_history)
                worker_stat['shares_24hour'], worker_stat['shares_invalid_24hour'] = self.get_shares_24hour(worker)
                worker_stats[worker.name] = worker_stat
                group_stat = group_stats.get(worker.name.split(':')[0], {})
                group_stat['name'] = worker.name.split(':')[0]
                group_stat['thread_count'] = group_stat.get('thread_count', 0) + 1
                group_stat['hash_rate'] = group_stat.get('hash_rate', 0) + worker_stat['hash_rate']
                group_stat['hash_rate_5min'] = group_stat.get('hash_rate_5min', 0) + worker_stat['hash_rate_5min']
                group_stat['shares'] = group_stat.get('shares', 0) + worker_stat['shares']
                group_stat['shares_invalid'] = group_stat.get('shares_invalid', 0) + worker_stat['shares_invalid']
                group_stat['shares_24hour'] = group_stat.get('shares_24hour', 0) + worker_stat['shares_24hour']
                group_stat['shares_invalid_24hour'] = group_stat.get('shares_invalid_24hour', 0) + worker_stat['shares_invalid_24hour']
                group_stats[worker.name.split(':')[0]] = group_stat
            overall_hash_rate = sum(stat['hash_rate'] for stat in worker_stats.itervalues())
            overall_hash_rate_5min = sum(stat['hash_rate_5min'] for stat in worker_stats.itervalues())
            overall_shares = sum(stat['shares'] for stat in worker_stats.itervalues())
            overall_shares_invalid = sum(stat['shares_invalid'] for stat in worker_stats.itervalues())
            overall_shares_24hour = sum(stat['shares_24hour'] for stat in worker_stats.itervalues())
            overall_shares_invalid_24hour = sum(stat['shares_invalid_24hour'] for stat in worker_stats.itervalues())
            uptime = int(time.time() - start_time)
            statistics_lock.release()
            # Start Response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<html><title>Server Status</title><head>")
            self.wfile.write("<link rel='icon' href='/customfavicon.ico' type='image/x-icon'><style>table, th, td{border: 1px solid black;}</style>")
            self.wfile.write("</head><body>")
            # Overall Info
            self.wfile.write("<h3>Overall Status</h3>")
            self.wfile.write("<table>")
            self.wfile.write("<tr><th>Uptime</th><th>Total Shares(invalid)</th><th>Shares in Last 24 Hours(invalid)</th><th>Overall 5min Average Hash Rate</th><th>Overall Current Hash Rate</th></tr>")
            self.wfile.write("<tr><td>%d hours %d minutes %d seconds</td>" % tuple(list(divmod(uptime, 3600))[:1] + list(divmod(divmod(uptime, 3600)[1], 60))))
            self.wfile.write("<td>%d(%d)</td>" % (overall_shares, overall_shares_invalid))
            self.wfile.write("<td>%d(%d)</td>" % (overall_shares_24hour, overall_shares_invalid_24hour))
            self.wfile.write("<td>%.3f Mhash/sec</td>" % (overall_hash_rate_5min / 1000))
            self.wfile.write("<td>%.3f Mhash/sec</td></tr></table>" % (overall_hash_rate / 1000))
            # Group Info
            self.wfile.write("<h3>Group Status</h3>")
            self.wfile.write("<table>")
            self.wfile.write("<tr><th>Name</th><th>Number of Threads</th><th>Total Shares(invalid)</th><th>Shares in Last 24 Hours(invalid)</th><th>5min Average Hash Rate(Khash/sec)</th><th>Current Hash Rate(Khash/sec)</th></tr>")
            for group_stat in group_stats.itervalues():
                self.wfile.write("<tr><td>%s</td><td>%d</td><td>%d(%d)</td><td>%d(%d)</td><td>%.3f</td><td>%.3f</td></tr>" % (group_stat['name'], group_stat['thread_count'], group_stat['shares'], group_stat['shares_invalid'], group_stat['shares_24hour'], group_stat['shares_invalid_24hour'], group_stat['hash_rate_5min'], group_stat['hash_rate']))
            self.wfile.write("</table>")
            # Thread Info
            self.wfile.write("<h3>Thread Status</h3>")
            self.wfile.write("<table>")
            self.wfile.write("<tr><th>Id</th><th>Name</th><th>Alive</th><th>Total Shares(invalid)</th><th>Shares in Last 24 Hours(invalid)</th><th>Average Work Time(sec)</th><th>5min Average Hash Rate(Khash/sec)</th><th>Current Hash Rate(Khash/sec)</th></tr>")
            for worker in self.server.thread_list:
                hash_rate = worker_stats[worker.name]['hash_rate'] 
                hash_rate_5min = worker_stats[worker.name]['hash_rate_5min']
                average_work_time = worker_stats[worker.name]['average_work_time']
                shares = worker_stats[worker.name]['shares']
                shares_invalid = worker_stats[worker.name]['shares_invalid']
                shares_24hour = worker_stats[worker.name]['shares_24hour']
                shares_invalid_24hour = worker_stats[worker.name]['shares_invalid_24hour']
                self.wfile.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d(%d)</td><td>%d(%d)</td><td>%.2f</td><td>%.3f</td><td>%.3f</td></tr>" % (worker.id, worker.name, worker.is_alive(), shares, shares_invalid, shares_24hour, shares_invalid_24hour, average_work_time, hash_rate_5min, hash_rate))
            self.wfile.write("</table>")
            # Event Logs
            self.wfile.write("<h3>Event Log</h3>")
            self.wfile.write("<table>")
            self.wfile.write("<tr><th>Time</th><th>Name</th><th>Message</th></tr>")
            log.lock.acquire()
            for event in reversed(log.events):  
                self.wfile.write("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (event['time'], event['name'], event['message']))
            log.lock.release()
            self.wfile.write("</table>")
            self.wfile.write("</body></html>")            
            return

        def get_shares_24hour(self, worker):
            if len(worker.share_history) > 0:
                now = time.time()
                shares = []
                for share in worker.share_history:
                    if share.get('time') > now - (24 * 60 * 60): # 24hours
                        shares.append(share)
                return len(shares), sum(not shr['valid'] for shr in shares)
            return 0, 0
        
        def get_average_work_time(self, worker):
            # this average is for the last 5 min
            average_work_time = 0 # in seconds
            if len(worker.work_history) > 0:
                # Calculate 5 minute average
                now = time.time()
                time_diffs = []
                for work in worker.work_history:
                    if work.get('time_start') > now - 300: # 5min
                        time_diffs.append(work.get('time_end') - work.get('time_start'))
                if len(time_diffs) > 1:
                    average_work_time = float(sum(time_diffs)) / len(time_diffs)
            return average_work_time

        def get_hash_rates(self, worker):
            hash_rate = 0 # in KHash
            hash_rate_5min = 0 # in KHash
            if len(worker.work_history) > 0:
                # Calculate Last Hash Rate
                hash_rate = (worker.work_history[-1].get('hash_count', 0) / 1000.0) / (worker.work_history[-1].get('time_end') - worker.work_history[-1].get('time_start'))
                # Calculate 5 minute average
                now = time.time()
                times = []
                hash_count_5min = 0
                for work in worker.work_history:
                    if work.get('time_start') > now - 300: # 5min
                        times.append(work.get('time_start'))
                        times.append(work.get('time_end'))
                        hash_count_5min += work.get('hash_count', 0)
                if len(times) > 1:
                    hash_rate_5min = (hash_count_5min / 1000.0) / (max(times) - min(times)) 
            return hash_rate, hash_rate_5min

    def __init__(self, thread_list, host, port):
        threading.Thread.__init__(self)
        self.thread_list = thread_list
        self.host = host
        self.port = port
        self.daemon = True

    def run(self):
        httpd = BaseHTTPServer.HTTPServer((self.host, self.port), self.Handler)
        httpd.thread_list = self.thread_list
        httpd.serve_forever()

class SimpleEventLog(object):
    
    def __init__(self):
        self.lock = threading.Lock()
        self.events = collections.deque([], 1000)
    
    def append(self, name, message):
        self.lock.acquire()
        self.events.append({'name': name,
                            'message': message,
                            'time' : time.asctime()})
        self.lock.release()
    
def main():

    time.clock()

    #Initialize globals
    global log
    global statistics_lock
    global start_time
    log = SimpleEventLog()
    statistics_lock = threading.Lock()
    start_time = time.time()
    
    # Parse Command Line options
    settings_filename = None
    try:
        settings_filename = sys.argv[1]
    except:
        print "Error parsing command line options. Example usage: %s settings.py" % sys.argv[0]
        return

    # Load Settings File
    settings = {}
    try: 
        execfile(settings_filename, {}, settings)
    except:
        print "Error running settings script"
        return

    # JSON-RPC Server Connection Data and other general config items
    protocol = None
    host = None
    port = None
    path = None
    username = None
    password = None
    timeout = None
    timeout_longpoll = None
    try:
        general = settings['general']
        protocol = general['protocol']
        host = general['host']
        port = general['port']
        path = general['path']
        username = general['username']
        password = general['password']
        timeout = general['timeout']
        longpoll_timeout = general['longpoll_timeout']
        admin_host = general['admin_host']
        admin_port = general['admin_port']
    except KeyError:
        print "Settings File Error(after load)"
        return
    
    log.append('main', "Starting application.")
    
    # Threading Variables for Push Work Threads
    work_lock = threading.Lock()
    work = Work()
    thread_list = []
    
    # Main GetWorker connection
    rpc_conn = BitcoinJSONRPC(protocol, host, port, path, username, password, timeout)

    # Get mining extension headers and populate initial Work
    response = rpc_conn.get_work()
    while not response:
        response = rpc_conn.get_work()
        print "Initial getwork failed, retrying in 5 seconds"
        time.sleep(5)
    work.response = response
    work.data = response['data']
    work.last_update = time.time()
    
    # Start longpolling thread if enabled on server
    longpolling = rpc_conn.server_headers.get('x-long-polling', None)
    rpc_conn_lp = None
    if longpolling:
        parse_result = urlparse.urlparse(longpolling)
        if not parse_result.scheme or not parse_result.hostname or not parse_result.port:
            rpc_conn_lp = BitcoinJSONRPC(protocol, host, port, parse_result.path, username, password, longpoll_timeout)
        else:
            rpc_conn_lp = BitcoinJSONRPC(parse_result.scheme, parse_result.hostname, parse_result.port, parse_result.path, username, password, longpoll_timeout)
        w = GetWorker(rpc_conn_lp, work, work_lock, longpoller=True)
        w.start()
         
    # Start get worker thread, this only refills work if nonce range gets low
    w = GetWorker(rpc_conn, work, work_lock)
    w.start()
    
    # Start push worker threads
    id = 0
    for worker in settings['workers']:
        for i in xrange(worker['thread_count']):
            try:
                push_thread = PushWorker(rpc_conn, work, work_lock, worker['name'] + ':' + str(i), worker)
            except:
                print "Error initializing a push worker thread: %s:%d  check settings file" % (worker.get('name', 'name not set'), i)
                continue
            push_thread.id = id
            id += 1
            push_thread.start()
            thread_list.append(push_thread)
            
    # Start Admin server thread
    w = AdminWebserver(thread_list, admin_host, admin_port)
    w.start()
    
    # Try to capture Ctrl-C and exit if caught
    try:
        while True:
            time.sleep(.1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()