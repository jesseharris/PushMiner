""" Push Miner Test Tool

Example Usage: python push_miner_test.py http://localhost:8000

This will run a series of tests. Change the salt in this file to match the salt of the client.
The first two tests work for clients with uint support.
The third test work for any client(uint support not required).
The final test is a performance test.
"""

import hashlib
import json
import sys
import time
import urllib2

salt = "c2c565a8c7dc220ed7d9ff2f34b40dae7864ef0b8189557f0d3b7360ef34e1cd"

#Block: 125552
#Double SHA-256 Hash:  1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000
sample = "01000000"  # Version
sample+= "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000"  # Hash of previous block
sample+= "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b"  # Merkle Root
sample+= "c7f5d74d"  # Timestamp
sample+= "f2b9441a"  # Bits
#sample+= "42a14695"  # Nonce   2504433986   little endian 32-bit uint
# Straight hash result(big endian)   00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d

#Block: 125553
#Double SHA-256 Hash:  85afcb448a3fcde31dc78babd352d9dbde6fcb566777ea33051c000000000000
sample2 = "01000000"  # Version
sample2+= "1dbd981fe6985776b644b173a4d0385ddc1aa2a829688d1e0000000000000000"  # Hash of previous block
sample2+= "b371c14921b20c2895ed76545c116e0ad70167c5c4952ca201f5d544a26efb53"  # Merkle Root
sample2+= "b4f6d74d"  # Timestamp
sample2+= "f2b9441a"  # Bits
#sample2+= "0258061b"  # Nonce   2165053959   little endian 32-bit uint
# Straight hash result(big endian)   0000000000001c0533ea776756cb6fdedbd952d3ab8bc71de3cd3f8a44cbaf85

#Block: 125661
#Double SHA-256 Hash:  2087fad97bc67d87007151c62cdb272071178c69c7c732097c3d000000000000
sample3 = "01000000"  # Version
sample3+= "e24a0439d23ebde141ac3113c0672386ad0a04c07f1b3aaf551a000000000000"  # Hash of previous block
sample3+= "bb284940c75074e1dd75c8237fb5d937a7c080a89237700562bac4c76183b764"  # Merkle Root
sample3+= "9246d84d"  # Timestamp
sample3+= "f2b9441a"  # Bits
#sample3+= "071a0c81"  # Nonce   453400578   little endian 32-bit uint
# Straight hash result(big endian)   0000000000003d7c0932c7c7698c17712027db2cc6517100877dc67bd9fa8720


try:
    sys.argv[1]
except:
    print "Example Usage: push_miner_test.py http://localhost:8000"
    sys.exit()

# Ask for 20 hashes, should end on the 7th one
response = urllib2.urlopen(sys.argv[1] + "?nonce_start=2504433980&nonce_end=2504433999&block_header=" + sample + "&signature=" +  hashlib.sha256(sample.decode('hex') + salt.decode('hex')).hexdigest())
print
print "Actual Response:   " + response.read().strip()
print "Expected Response: " + """{ "share_found" : true, "nonce" : 2504433986, "nonce_start" : 2504433980, "nonce_end" : 2504433999 }"""


# Ask for 20 hashes, should end on the 10th one
response = urllib2.urlopen(sys.argv[1] + "?nonce_start=2165053950&nonce_end=2165053969&block_header=" + sample2 + "&signature=" +  hashlib.sha256(sample2.decode('hex') + salt.decode('hex')).hexdigest())
print
print "Actual Response:   " + response.read().strip()
print "Expected Response: " + """{ "share_found" : true, "nonce" : 2165053959, "nonce_start" : 2165053950, "nonce_end" : 2165053969 }"""

# Ask for 10 hashes, should end on the 9th one
response = urllib2.urlopen(sys.argv[1] + "?nonce_start=453400570&nonce_end=453400579&block_header=" + sample3 + "&signature=" +  hashlib.sha256(sample3.decode('hex') + salt.decode('hex')).hexdigest())
print
print "Actual Response:   " + response.read().strip()
print "Expected Response: " + """{ "share_found" : true, "nonce" : 453400578, "nonce_start" : 453400570, "nonce_end" : 453400579 }"""


start_time = time.time()
response = urllib2.urlopen(sys.argv[1] + "?nonce_start=0&nonce_end=1000000&block_header=" + sample + "&signature=" +  hashlib.sha256(sample.decode('hex') + salt.decode('hex')).hexdigest())
time_delta = time.time() - start_time
print 
print "Actual Response:   " + response.read().strip()
print "Expected Response: " + """{ "share_found" : false, "nonce" : -1, "nonce_start" : 0, "nonce_end" : 1000000 }"""
print 
print "Speed: %d hashes @ %.2f Khash/sec" % (1000000, ((1000000 / 1000.0) / (time_delta)))
