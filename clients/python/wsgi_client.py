import hashlib
import struct
import json

def push_miner(environ, start_response):
    # Declare local variables
    block_header = None
    nonce_start = None
    nonce_end = None

    # Parse the args in the URL into a dict and assign local variables
    try:
        args = dict(item.split('=')[0:2] for item in environ.get('QUERY_STRING', '').split('&'))
        block_header = str(args['block_header'])
        nonce_start = int(args['nonce_start'])
        nonce_end = int(args['nonce_end'])
    except:
        status = '500 Internal Server Error'
        headers = [('Content-type', 'text/plain')]
        start_response(status, headers)
        return ["Internal Server Error"]


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
    status = '200 OK'
    headers = [('Content-type', 'text/plain')]
    start_response(status, headers)
    return [json.dumps(result)]

if __name__ == '__main__':
    import wsgiref.simple_server as simple_server
    httpd = simple_server.make_server('', 8000, push_miner)
    httpd.serve_forever()