""" Settings File for Push Miner Server

The bottom section of this file contains default settings. Do not modify these settings directly.
Override the settings as shown in the examples included.
"""


### Create a dictionary to override the defaults ###
general = {'host' : 'pool.somedomain.com',
           'port' : 8333,
           'username' : 'USERNAME',
           'password' : 'PASSWORD',           
    }    
    
### Create  a list of dictionaries that override the defaults ###
workers = [
    {
        'name' : 'LocalHost',
        'thread_count' : 2,
        'nonce_range_size' : 200000,
        'host' : 'localhost',
        'port' : 8000,
    },
#    {
#        'name' : 'Other PC',
#        'thread_count' : 4,
#        'nonce_range_size' : 400000,
#        'protocol' : 'http',
#        'host' : '192.168.1.123',
#        'path' : '/pushminer',
#    },
#    {
#        'name' : 'MyServer',
#        'thread_count' : 10,
#        'nonce_range_size' : 900000,
#        'host' : 'somedomain.com',
#        'protocol' : 'https',
#        'port' : 443,
#        'salt' : 'f973d61ab6f14ea76dbfedb01f47babe8e760ec9e6b1465e6159c3ada6b4f9b7'
#    },
]


### DO NOT MODIFY ###
general_default = {'protocol' : 'http', 
                  'host' : 'localhost',
                  'port' : 8332,
                  'path' : '/',
                  'username' : 'OVERRIDEME',
                  'password' : 'OVERRIDEME',
                  'timeout' : 30,
                  'longpoll_timeout' : 6000,
                  'admin_host' : '',
                  'admin_port' : 8080,                    
    }

### DO NOT MODIFY ###
workers_default = {'name' : 'Default',
                   'thread_count' : 1,
                   'nonce_range_size' : 500000,
                   'uint_support' : False,
                   'protocol' : 'http',
                   'host' : 'localhost',
                   'port' : 80,
                   'path' : '/',        
                   'timeout' : 60,
                   'salt' : 'c2c565a8c7dc220ed7d9ff2f34b40dae7864ef0b8189557f0d3b7360ef34e1cd'
    }

### DO NOT MODIFY ###
for key in general_default.iterkeys():
    if not general.has_key(key):
        general[key] = general_default[key]
for worker in workers:
    for key in workers_default.iterkeys():
        if not worker.has_key(key):
            worker[key] = workers_default[key]