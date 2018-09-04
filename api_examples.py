#   Created by Anton Solovey, Falcongaze 2018 (c), a.solovey@falcongaze.ru

import client
import pprint
import json

#   Some const and variables
ST_IP = "localhost"
ST_PORT = "9090"
CLIENT_HOST = "fg-note-08.fg.local"   # "10.10.200.2"

auth = client.Auth()   #   Create an instance of class
search = client.Search()
upload = client.Upload()

pp = pprint.PrettyPrinter(indent=3)

#   First, we have to register out custom service on SecureTower server
secret_key = auth.server_register(ST_IP, ST_PORT, CLIENT_HOST)
print("\n Secret key: ", secret_key)

#   Second, we have to get the token
oauth_token = auth.get_oauth_token(ST_IP, ST_PORT, CLIENT_HOST, secret_key)
print("\n Your token is: ", oauth_token, "\n")

pp.pprint("Collections list: " + json.dumps(search.get_collections(ST_IP, ST_PORT, oauth_token)))
pp.pprint("Collection data: " + search.collection_request(ST_IP, ST_PORT, oauth_token, 'ftp'))

#   Then we can make a requests with the token

#   Let's make some other requests

