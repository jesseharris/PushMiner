PushMiner Quick Start
=====================

Install and Configuration
-------------------------

PushMiner Server was developed against Python 2.7.2 and it is required to run the server. To get started quickly, edit the settings.py file
with the standard bitcoin worker information(pool URL, username, passsword). Then run the following command:

    # python push_miner_server.py settings.py
    
In another shell run the python WSGI client:
    
    # python application

This will start the client on port 8000 and start the server with an admin page on port 8080.
Open <http://localhost:8080> in a browser and it will show the current status of the server.

Salts
----------

It is *highly* recommended that the default salts in the example clients are changed before being installed and used.
The salts are sign the work requests as an authentication mechanism.
Leaving the default salts will allow anyone to hijack your clients to due their work.
