#   Created by Anton Solovey, Falcongaze 2018 (c), a.solovey@falcongaze.ru

import json
import requests
import pprint
from requests.auth import HTTPBasicAuth

#   Here we define some default constants

CLIENT_ID = "custom_service"
pp = pprint.PrettyPrinter(indent=3)

class Auth():
    def server_register(self, st_ip, st_port, client_host):      # User service register function

        register_url =  "http://" + st_ip + ":" + st_port + "/api/v1/oauth2/register"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'client_id': CLIENT_ID, 'client_host': client_host}
        request = requests.post(register_url, headers=headers, data=payload)

        #   Check for HTTP 200 - if it's okay then return secret key
        if request.status_code == 200:
            json_data = json.loads(request.content)
            return(json_data['secret_key'])
        elif request.status_code == 409:
            print("Client already registered on this host")
            #   TODO: Use current token
        else:
            print("Error: ", str(request.status_code), json.loads(request.content))

    def get_oauth_token(self, st_ip, st_port, client_host, secret_key):

        token_url =  "http://" + st_ip + ":" + st_port + "/api/v1/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'grant_type': 'client_credentials', 'client_host': client_host}
        BASE64_CRED = HTTPBasicAuth(CLIENT_ID, secret_key)
        #   TODO:   check if token already exists then use that token
        request = requests.post(token_url, auth=BASE64_CRED, data=payload, headers=headers)

        if request.status_code == 200:    #   Check for HTTP 200 - if it's okay then return JWT token
            json_data = json.loads(request.content)
            if json_data['access_token'] != None:
                return(json_data['access_token'])
            else:
                print("Something went wrong, the token is null")    # TODO: avoid the sutiation when token is None or Null or correctly handle the error (Try, Raise, whatever)
        else:
            print("Error while getting token: ", str(request.status_code), json.loads(request.content))
            #print(self.api_error_handler(request.status_code, request.content))
    
    def check_token(self, st_ip, st_port, token):

        check_token_url =  "http://" + st_ip + ":" + st_port + "/oauth/check_token"
        headers = {'Content-Type': "application/x-www-form-urlencoded",
                   'Authorization': "Bearer " + token,
                  }
        request = requests.post(check_token_url, headers=headers)

        if request.status_code == 200:
            return "AUTHORIZED"
        elif request.status_code == 401:
            if json.loads(request.content) == "UserTokenInvalid = 13":
                raise ValueError("Token Invalid")
            elif json.loads(request.content) == "UserTokenExpired = 14":
                raise ValueError("Token has been expired")
            elif json.loads(request.content) == "UserTokenInvalidSignature = 15":
                raise ValueError("Token signature is invalid")
            else:
                return "UNAUTHORIZED"
        else:
            return "UNKNOWN ERROR"

class Service:

    def request(self, st_ip, st_port, token, resource, http_method='GET', http_payload=None, offset=None, limit=None):
        #   Abstract class
        #   TODO:   support offset and limit args
        url = "http://" + st_ip + ":" + st_port + "/api/v1/" + resource
        headers = {'Content-Type': "application/x-www-form-urlencoded",
                   'Authorization': "Bearer " + token,
                  }

        if http_method == "GET":
            request = requests.get(url, headers=headers)
        elif http_method == "POST" and http_payload is not None:
            request = requests.post(url, headers=headers, data=http_payload)
        else:
            raise Exception("HTTP method is not allowed or implemented or http body is empty")

        if request.status_code == 200:
            '''for item in request:
                print(item)'''
            #pp.pprint(json.loads(request.content))
            return(json.loads(request.content))
        else:
            print("Error: ", str(request.status_code), json.loads(request.content))

class Search(Service):

    def get_collections(self, st_ip, st_port, token):
        resource = "data/collections"
        return self.request(st_ip, st_port, token, resource)

    def collection_request(self, st_ip, st_port, token, collection):
        resource = "data/collections/" + collection
        return self.request(st_ip, st_port, token, resource)

    def get_documents(self, st_ip, st_port, token, collection, offset=0, limit=0):
        if offset != 0 and limit != 0:
            resource = "data/collections/" + collection + "/documents?" + "offset=" + offset +'\&limit=' + limit
        elif offset != 0 and limit == 0:
            resource = "data/collections/" + collection + "/documents?" + "offset=" + offset
        elif offset == 0 and limit != 0:
            resource = "data/collections/" + collection + "/documents" +'?limit=' + limit
        else:
            resource = "data/collections/" + collection + "/documents"
        return self.request(st_ip, st_port, token, resource)

    def document_request(self, st_ip, st_port, token, collection, document_id):
        resource =  "data/collections/" + collection + "/documents/" + document_id
        return self.request(st_ip, st_port, token, resource)
    
    def get_document_content(self, st_ip, st_port, token, collection, document_id, mode="original"):
        resource = "/data/collections/" + collection + "/documents/" + document_id + "/contents/" + mode    #   mode = [original|extracted|converted|highlighted]
        return self.request(st_ip, st_port, token, resource)
    
    def dfp_search(self, st_ip, st_port, token, dfp_id, query, threshold_value=50):
        if threshold_value is not int:
            raise ValueError("Threshold value must be a string!")
        else:
            resource = "/dfp/" + dfp_id + "/search?query=" + query + "&threshold=" + threshold_value
        return self.request(st_ip, st_port, token, resource)

class Statistics(Service):
    pass
    #   TODO:   search statistics API - 
    #   https://stdoc.pg.local/pages/viewpage.action?pageId=29458994
    #   https://stdoc.pg.local/pages/viewpage.action?pageId=29459006

class Licensing(Service):
    pass
    #   TODO:   Licence API - https://stdoc.pg.local/pages/viewpage.action?pageId=13241709

class DFP(Service):
    pass
    #   TODO:   DFP API - https://stdoc.pg.local/pages/viewpage.action?pageId=16778175

class Stamps(Service):
    pass
    #   TODO:   Stamps API - https://stdoc.pg.local/pages/viewpage.action?pageId=20021897

class Configure(Service):
    pass
    #   TODO:   Configure API - https://stdoc.pg.local/pages/viewpage.action?pageId=4128865

class Extras(Service):
    pass
    #   TODO:   Services - https://stdoc.pg.local/pages/viewpage.action?pageId=4128877
    
    def get_domains(self, st_ip, st_port, token):
        resource = "/data/system/domains"
        return self.request(st_ip, st_port, token, resource)

    def get_machines(self, st_ip, st_port, token):
        resource = "/data/system/machines"
        return self.request(st_ip, st_port, token, resource)
    
    def get_users(self, st_ip, st_port, token):
        resource = "/data/system/users"
        return self.request(st_ip, st_port, token, resource)


class Categorizer(Service):
    pass
    #   TODO:   Site categorizer API - https://stdoc.pg.local/pages/viewpage.action?pageId=16778493
class Upload():
    def upload(self, st_ip, st_port, token, collection, http_payload):
        upload_url = "http://" + st_ip + ":" + st_port + "/api/v1/upload/" + collection
        headers = {'Content-Type': 'application/octet-stream',  #   OR {'Content-Type': 'application/x-protobuf'}
                   'Authorization': "Bearer " + token,
                  }
        request = requests.post(upload_url, headers=headers, data=http_payload.SerializeToString())

class Api:

    def __init__(self):

        self.RESOURCES = {

            #   BASE
            "api": "/api/v1",
            #   SERVICE
            "collections": "/data/collections",

            #   SEARCH

            #   AUTH
            "check_token": "/oauth/check_token",

            #   STATICTICS
            "current_search_queries": "/search_requests/current",
            "current_fulltext_queries": "/search_requests/current/ft",
            "current_dict_queries": "/search_requests/current/dict",
            "current_dfp_queries": "/search_requests/current/dfp",
            
            #   OTHER
            "upload": "/upload/",   # + name of collection
            "consoles_versions": "/services/update",
            "client_console_version": "/services/update/client_console",
            "admin_console_version": "/services/update/admin_console",

        }

        self.COLLECTIONS = {

            "smtp": "smtp",
            "pop3": "pop3",
            "imap": "imap",
            "mapi": "mapi",
            "ftp": "ftp",
            "httpurls": "httpurls",
            "httpreq": "httpreq",
            "mailproc": "mailproc",
            "printer": "printer",
            "desktop": "desktop",
            "clipboard": "clipboard",
            "screenshots": "screenshots",
            "browsers": "browsers",
            "keylogger": "keylogger",
            "devices": "devices",
            "sharedfiles": "sharedfiles",
            "cddvd": "cddvd",
            "usbfiles": "usbfiles",
            "cloudfiles": "cloudfiles",
            "wsindexer": "wsindexer",
            "webmsg": "webmsg",
            "conversations": "conversations",  

        }

        self.HTTP_ERRORS = {

            "304": "Not Modified",
            "400": "Bad request",
            "401": "Not authorized",
            "403": "Fordidden",
            "501": "Not implemented",
            "503": "Service unavailable", 

        }   #   Just FYI

        self.ST_INT_API_ERRORS = {
            "5": "NotAuthenticated. There is no header with bearer token or Basic not sucsessful.",
            "7": "AccessForbidden. There is no appropriate right on your token.",
            "11": "Invalid upload rule. Database not exits OR rotation group not exists.",
            "13": "UserTokenInvalid. Token type is not supported.",
            "14": "UserTokenExpired. Token has been expired.",
            "15": "UserTokenInvalidSignature. Token digital signature is not valid.",
        }
    
    def error_handler(self, http_error_code, int_error_code):
        # pass    #   TODO:   make API HTTP error codes and internal error codes handler

        if http_error_code == 401 and int_error_code == 5:
            print(self.ST_INT_API_ERRORS("5"))
        elif http_error_code == 401 and int_error_code == 13:
            print(self.ST_INT_API_ERRORS("13"))
        elif http_error_code == 401 and int_error_code == 14:
            return(self.ST_INT_API_ERRORS("14"))
        elif http_error_code == 401 and int_error_code == 15:
            return(self.ST_INT_API_ERRORS("15"))
        elif http_error_code == 403 and int_error_code == 7:
            return(self.ST_INT_API_ERRORS("7"))
        #   Otherwise print an error
        else:
            if ((http_error_code not in self.HTTP_ERRORS) and (int_error_code not in self.ST_INT_API_ERRORS)):
                print("Unknown error: ", str(http_error_code), json.loads(int_error_code))