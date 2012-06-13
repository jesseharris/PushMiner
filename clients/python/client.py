import BaseHTTPServer
import hashlib
import struct
import json

PORT = 8000

class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        # Declare local variables
        block_header = None
        nonce_start = None
        nonce_end = None
        
        # Parse the args in the URL into a dict and assign local variables
        try:
            args = dict(item.split('=')[0:2] for item in self.path.split('?')[1].split('&'))
            block_header = str(args['block_header'])
            nonce_start = int(args['nonce_start'])
            nonce_end = int(args['nonce_end'])
        except:
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write("Internal Server Error")
            return
        
        
        # pre-hash the block header(76 bytes)
        pre_hash = hashlib.sha256()
        pre_hash.update(block_header.decode('hex'))
        
        result = {"share_found": False, "nonce": -1, "nonce_start": nonce_start, "nonce_end": nonce_end}
        nonce = nonce_start
        while nonce <= nonce_end:
            
            # hash the block header(76 bytes) + nonce(4 bytes)
            hash = pre_hash.copy()
            hash.update(struct.pack("<I", nonce)) # little endian
            digest = hashlib.sha256(hash.digest()).digest()
            # create a share?
            if digest[-4:] == '\0\0\0\0': # check last 4 bytes
                print "success!!"
                result["share_found"] = True
                result["nonce"] = nonce
                break
            nonce += 1
        
        # Standard Response Template
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(json.dumps(result))
        
        
httpd = BaseHTTPServer.HTTPServer(('', 8000), Handler)
httpd.serve_forever()
    