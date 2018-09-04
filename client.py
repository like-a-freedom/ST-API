#   Created by Anton Solovey, Falcongaze 2018 (c), a.solovey@falcongaze.ru

import time, random
import hashlib
import json
import requests
import pprint
from etc import UploadDataProtocol_pb2 as pb
from etc.UploadDataProtocol_pb2 import MessageHeader, MessageDataConversationMessage, MessageDataPOP3, MessageSystemInfo, MessageProcessInfo
#from UploadDataProtocol_pb2 import *
from requests.auth import HTTPBasicAuth

#   Here we define some default constants

CLIENT_ID = "custom_service"
pp = pprint.PrettyPrinter(indent=3)


class Auth():
    # User service register function
    def server_register(self, st_ip, st_port, client_host):

        register_url = "http://" + st_ip + ":" + st_port + "/api/v1/oauth2/register"
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
            print("Error: ", str(request.status_code),
                  json.loads(request.content))

    def server_unregister(self, st_ip, st_port, token):

        unregister_url = "http://" + st_ip + ":" + st_port + "/api/v1/oauth2/unregister"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        request = requests.post(unregister_url, headers=headers)

        #   Check for HTTP 200 - if it's okay then return secret key
        if request.status_code == 200:
            json_data = json.loads(request.content)
            return(json_data)
        else:
            print("Error: ", str(request.status_code),
                  json.loads(request.content))

    def get_oauth_token(self, st_ip, st_port, client_host, secret_key):

        token_url = "http://" + st_ip + ":" + st_port + "/api/v1/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'grant_type': 'client_credentials',
                   'client_host': client_host}
        BASE64_CRED = HTTPBasicAuth(CLIENT_ID, secret_key)
        #   TODO:   check if token already exists then use that token
        request = requests.post(
            token_url, auth=BASE64_CRED, data=payload, headers=headers)

        if request.status_code == 200:  # Check for HTTP 200 - if it's okay then return JWT token
            json_data = json.loads(request.content)
            if json_data['access_token'] != None:
                return(json_data['access_token'])
            else:
                # TODO: avoid the sutiation when token is None or Null or correctly handle the error (Try, Raise, whatever)
                print("Something went wrong, the token is null")
        else:
            print("Error while getting token: ", str(
                request.status_code), json.loads(request.content))
            #print(self.api_error_handler(request.status_code, request.content))

    def check_token(self, st_ip, st_port, token):

        check_token_url = "http://" + st_ip + ":" + st_port + "/oauth/check_token"
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
            raise Exception(
                "HTTP method is not allowed or implemented or http body is empty")

        if request.status_code == 200:
            '''for item in request:
                print(item)'''
            # pp.pprint(json.loads(request.content))
            return(json.loads(request.content))
        else:
            print("Error: ", str(request.status_code),
                  json.loads(request.content))


class Search(Service):

    def get_collections(self, st_ip, st_port, token):
        resource = "data/collections"
        return self.request(st_ip, st_port, token, resource)

    def collection_request(self, st_ip, st_port, token, collection):
        resource = "data/collections/" + collection
        return self.request(st_ip, st_port, token, resource)

    def get_documents(self, st_ip, st_port, token, collection, offset=0, limit=0):
        if offset != 0 and limit != 0:
            resource = "data/collections/" + collection + \
                "/documents?" + "offset=" + offset + r'\&limit=' + limit
        elif offset != 0 and limit == 0:
            resource = "data/collections/" + collection + "/documents?" + "offset=" + offset
        elif offset == 0 and limit != 0:
            resource = "data/collections/" + collection + "/documents" + '?limit=' + limit
        else:
            resource = "data/collections/" + collection + "/documents"
        return self.request(st_ip, st_port, token, resource)

    def document_request(self, st_ip, st_port, token, collection, document_id):
        resource = "data/collections/" + collection + "/documents/" + document_id
        return self.request(st_ip, st_port, token, resource)

    def get_document_content(self, st_ip, st_port, token, collection, document_id, mode="original"):
        resource = "/data/collections/" + collection + "/documents/" + document_id + \
            "/contents/" + \
            mode  # mode = [original|extracted|converted|highlighted]
        return self.request(st_ip, st_port, token, resource)

    def dfp_search(self, st_ip, st_port, token, dfp_id, query, threshold_value=50):
        if threshold_value is not int:
            raise ValueError("Threshold value must be a string!")
        else:
            resource = "/dfp/" + dfp_id + "/search?query=" + \
                query + "&threshold=" + threshold_value
        return self.request(st_ip, st_port, token, resource)


class Statistics(Service):
    pass
    #   TODO:   search statistics API -
    #   https://stdoc.pg.local/pages/viewpage.action?pageId=29458994
    #   https://stdoc.pg.local/pages/viewpage.action?pageId=29459006


class Licensing(Service):

    #   TODO:   Licence API - https://stdoc.pg.local/pages/viewpage.action?pageId=13241709

    def get_licences_list(self, st_ip, st_port, token):
        resource = "license/licenses"
        return self.request(st_ip, st_port, token, resource)
    
    def get_licence(self, st_ip, st_port, token, licence_id):
        pass
    
    def add_licence(self, st_ip, st_port, token):
        pass
        #TODO: PUT request
    
    def delete_licence(self, st_ip, st_port, token, licence_id):
        pass
        #TODO: DELETE request
    
    '''def update_licence(self, st_ip, st_port, token, licence_id, type = "software", serial_number = "None"):
        resource = "license/licenses/" + licence_id
        body = json.dumps(#TODO: make json body)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)'''

    def licence_statistics(self, st_ip, st_port, token):
        resource = "license/stats"
        return self.request(st_ip, st_port, token, resource)
    
    def licence_users_statistics(self, st_ip, st_port, token, licence_id = "trial"):
        pass



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

    #   /services resource

    def supported_dbms_providers(self, st_ip, st_port, token):
        resource = "/services/dbms"
        return self.request(st_ip, st_port, token, resource)

    def enum_db_in_dbms(self, st_ip, st_port, token, connection_string):
        #   SQLite is not supports that method. PostreSQL connection string must contains "postgres" db
        resource = "/services/dbms/:dbms/databases?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def check_dbms_connection(self, st_ip, st_port, token, connection_string):
        resource = "/services/dbms/:dbms/connect?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def check_dbms_connection_and_get_db_scheme(self, st_ip, st_port, token, connection_string):
        resource = "/services/dbms/:dbms/schema_version?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def make_sql_request(self, st_ip, st_port, token, connection_string, sql):
        resource = "/services/dbms/:dbms/sql?timeout=10"
        ''' Another JSON generating method
        mydict - {
            connection_string,
            sql,
        }
        body = json.dumps(mydict)
        '''
        body = json.dumps([connection_string, sql])  # Not tested ;)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def get_db_tables(self, st_ip, st_port, token, connection_string):
        resource = "/services/dbms/:dbms/tables?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def get_db_columns_list(self, st_ip, st_port, token, connection_string):
        resource = "/services/dbms/:dbms/columns?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def create_sqlite_db_file(self, st_ip, st_port, token, connection_string):
        #   Note that connection string must be as full path to the file on disk
        resource = "/services/dbms/sqlite/create_database_file?timeout=10"
        body = json.dumps(connection_string)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def get_filesystem_tree(self, st_ip, st_port, token, root_folder):
        resource = "/services/fs[?path=" + root_folder + "]"
        return self.request(st_ip, st_port, token, resource)

    def create_directory(self, st_ip, st_port, token, folder_path):
        resource = "/services/fs?path=" + folder_path
        return self.request(st_ip, st_port, token, resource, http_method="POST")

#   Indexer service

    def get_indexer_filesystem_tree(self, st_ip, st_port, token, root_folder):
        resource = "/services/indexer_fs?address=" + st_ip + \
            ":" + st_port + "[&path=" + root_folder + "]"
        return self.request(st_ip, st_port, token, resource)

    def create_indexer_directory(self, st_ip, st_port, token, folder_path):
        resource = "services/indexer_fs?address=" + "&path=" + folder_path
        body = json.dumps(folder_path)
        return self.request(st_ip, st_port, token, resource, http_method="POST", http_payload=body)

    def get_indexer_file_content(self, st_ip, st_port, token, size=100, offset=20):
        resource = "services/indexer_fs/file?address=" + "&path=file_path[&offset=" + offset + "][&size=" + size + "]"
        return self.request(st_ip, st_port, token, resource)

    def check_indexer_connections(self, st_ip, st_port, token):
        resource = "/services/connect/index_server?address=" + st_ip + ":" + st_port
        return self.request(st_ip, st_port, token, resource)
        #   Return JSON with bool - true or false

    def check_search_server_connections(self, st_ip, st_port, token):
        resource = "/services/connect/search_server?address=" + st_ip + ":" + st_port
        return self.request(st_ip, st_port, token, resource)
        #   Return JSON with bool - true or false

    #   /system resource

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

    #   TODO: Protobuf generated and upload to SecureTower storage server. Please keep in mind that SecureTower uses protobuf version 2!

    def upload(self, st_ip, st_port, token, collection, http_payload):
        upload_url = "http://" + st_ip + ":" + st_port + "/api/v1/upload/" + collection
        headers = {'Content-Type': 'application/octet-stream',  # OR {'Content-Type': 'application/x-protobuf'}
                   'Connection': 'keep-alive',
                   'Authorization': "Bearer " + token,
                   }
        request = requests.post(
            upload_url, headers=headers, data=http_payload.SerializeToString())

    #   Method below is for test purpose only
    def test_conv_msg_upload(self, st_ip, st_port, token):
        upload_url = upload_url = "http://" + st_ip + \
            ":" + st_port + "/api/v1/upload/conversations"
        

        #   Filling MessageHeader structure
        msg_header = MessageHeader()
        msg_header.version = 1
        msg_header.type = 29

        #   Filling MessageSystemInfo structure
        msg_sys_info = MessageSystemInfo()
        msg_sys_info.address = "192.168.1.1"
        msg_sys_info.mname = "workstation"
        msg_sys_info.mdnsname = "worstation.domain.local"
        msg_sys_info.msid = "S-1237128937-123123-123123"
        msg_sys_info.mdomainsid = "S-1237128937-123210000003-12903833"
        msg_sys_info.dname = "domain"
        msg_sys_info.ddnsname = "domain.local"
        msg_sys_info.dsid = "S-1237128937"
        msg_sys_info.usid = "S-1237128937-123210000003-12321311"
        msg_sys_info.uname = r"domain\user"
        msg_sys_info.udispname = "Sample User"
        msg_sys_info.udsid = "S-1237128937"
        msg_sys_info.udname = "domain"
        msg_sys_info.uddnsname = "domain.local"
        msg_sys_info.dtime_tzbias = -180
        msg_sys_info.mfqdn = "CN=PG1032,OU=Desktops,DC=pg,DC=local"
        msg_sys_info.ufqdn = "CN=Sample User,OU=Moscow,OU=Company,DC=domain,DC=local"

        #   Filling MessageProcessInfo structure
        msg_proc_info = MessageProcessInfo()
        msg_proc_info.process_name = "none"
        msg_proc_info.process_filepath = "none"
        msg_proc_info.process_version = "none"
        msg_proc_info.process_product_name = "none"
        msg_proc_info.process_company_name = "falcongaze"
        msg_proc_info.process_description = "none"

        #   Filling MessageDataConversationMessage structure
        msg = MessageDataConversationMessage()
        msg.dtime_utc = int(131790780000000000)
        msg.dtime_msg_utc = int(131790780000000000) #int(time.time())   # unixtime
        msg.messenger_name = "API-Uploaded-message"
        msg.messenger_type = "Custom-type"
        msg.conversation_hash = hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()
        msg.message_id = "msg_id_12345"
        msg.local_user = "123456789"
        msg.sender_user = "987654321"
        msg.chat_users = "None"
        msg.message_body = "Test message body"


        payload = msg_header.SerializeToString() + msg.SerializeToString() + msg_sys_info.SerializeToString() + msg_proc_info.SerializeToString()

        headers = {'Content-Type': 'application/octet-stream',  # OR {'Content-Type': 'application/x-protobuf'}
                   'Authorization': "Bearer " + token,
                   'Content-length': str(len(payload))
                   }
        
        #   Debug output
        print("Serialized data: ", payload)
        print("Content-lenght: ", len(payload))

        # request = requests.post(upload_url, headers=headers, data=payload)
        request = requests.post(upload_url, data=payload, headers=headers)

        if request.status_code == 200:
            print("Data uploaded!")
        else:
            print("Error: ", str(request.status_code), json.loads(request.content))

        # return self.request(st_ip, st_port, token, resource, http_method = "POST", http_payload = body)


    def test_pop3_msg_upload(self, st_ip, st_port, token):
        
        upload_url = upload_url = "http://" + st_ip + \
            ":" + st_port + "/api/v1/upload/pop3"
        
        '''
        Helpful protobuf articles:
        https://stackoverflow.com/questions/32836315/python-protocol-buffer-field-options
        https://www.indelible.org/ink/protobuf-polymorphism/
        http://qaru.site/questions/547402/c-protobuf-how-to-iterate-through-fields-of-message
        http://qaru.site/questions/4213463/protobuf-python-error-cannot-assign-to-extension-because-it-is-a-repeated-or-composite-type
        https://github.com/archit47/Protobuf-over-Http/blob/master/Protobuf-Message-Sender/src/app/protobuf/Employee_pb2.py
        '''

        #   Filling MessageHeader structure
        msg_header = pb.MessageHeader()
        msg_header.version = 1
        msg_header.type = 2

        # msg_header.content.Extensions[UploadDataProtocol_pb2.MessageDataConversationMessage].messenger_name = "Custom type"
        # UploadDataProtocol_pb2.MessageHeader.descriptor.GetOptions().Extensions[UploadDataProtocol_pb2.MessageDataConversationMessage]
        # msg_header.Extensions[pb.MessageDataPOP3].host_address = 2


        #   Filling MessageSystemInfo structure
        msg_sys_info = pb.MessageSystemInfo()
        msg_sys_info.address = "192.168.1.1"
        msg_sys_info.mname = "workstation"
        msg_sys_info.mdnsname = "workstation.domain.local"
        msg_sys_info.msid = "S-1237128937-123123-123123"
        msg_sys_info.mdomainsid = "S-1237128937-123210000003-12903833"
        msg_sys_info.dname = "domain"
        msg_sys_info.ddnsname = "domain.local"
        msg_sys_info.dsid = "S-1237128937"
        msg_sys_info.usid = "S-1237128937-123210000003-12321311"
        msg_sys_info.uname = r"domain\user"
        msg_sys_info.udispname = "Sample User"
        msg_sys_info.udsid = "S-1237128937"
        msg_sys_info.udname = "domain"
        msg_sys_info.uddnsname = "domain.local"
        msg_sys_info.dtime_tzbias = -180
        msg_sys_info.mfqdn = "CN=PG1032,OU=Desktops,DC=pg,DC=local"
        msg_sys_info.ufqdn = "CN=Sample User,OU=Moscow,OU=Company,DC=domain,DC=local"

        #   Filling MessageProcessInfo structure
        msg_proc_info = pb.MessageProcessInfo()
        msg_proc_info.process_name = "none"
        msg_proc_info.process_filepath = "none"
        msg_proc_info.process_version = "none"
        msg_proc_info.process_product_name = "none"
        msg_proc_info.process_company_name = "falcongaze"
        msg_proc_info.process_description = "none"

        #   Filling MessageDataPOP3Message structure
        msg = pb.MessageDataPOP3()
        msg.host_address = "192.168.1.10"
        msg.host_port = 110
        msg.dtime_utc = int(131790780000000000)
        msg.user_name = "Sample-user"
        msg.user_pass = "Sample-pass"
        s = "Message-body"
        msg.msg = s.encode('utf-8')

        #   --- Debug section ---
        #   Check that all required fields are initialized... or not
        print("\n Are required fields are initialized? ", \
                "\n Header: ", msg_header.IsInitialized(), \
                "\n Body: ", msg.IsInitialized(), \
                "\n System info: ", msg_sys_info.IsInitialized(), \
                "\n Process info: ", msg_proc_info.IsInitialized())
                
        print("\n Message size, bytes:", \
                "\n Header: ", msg_header.ByteSize(), \
                "\n Body: ", msg.ByteSize(), \
                "\n System info: ", msg_sys_info.ByteSize(), \
                "\n Process info: ", msg_proc_info.ByteSize(), \
                "\n Total bytes: ", msg_header.ByteSize() + msg.ByteSize() + msg_sys_info.ByteSize() + msg_proc_info.ByteSize())
        #   --- End of debug section ---


        payload = msg_header.SerializeToString() + msg.SerializeToString() + msg_sys_info.SerializeToString() + msg_proc_info.SerializeToString()
        payload_2 = '_b'+('\x08\x01\x10\x02\x12\x0c192.168.1.10\x18n \x80\xb0\xc9\x94\xc2\xe0\x8d\xea\x012\x0bSample-user:\x0bSample-passB\x0cMessage-body\n\x0b192.168.1.1\x12\x0bworkstation\x1a\x18workstation.domain.local"\x1aS-1237128937-123123-123123*"S-1237128937-123210000003-129038332\x06domain:\x0cdomain.localB\x0cS-1237128937J"S-1237128937-123210000003-12321311R\x0bdomain\\userZ\x0bSample Userb\x0cS-1237128937j\x06domainr\x0cdomain.localx\xcc\xfe\xff\xff\xff\xff\xff\xff\xff\x01\x82\x01$CN=PG1032,OU=Desktops,DC=pg,DC=local\x8a\x016CN=Sample User,OU=Moscow,OU=Company,DC=domain,DC=local\n\x04none\x12\x04none\x1a\x04none"\x04none*\nfalcongaze2\x04none')

        headers = {'Content-Type': 'application/octet-stream',  # OR {'Content-Type': 'application/x-protobuf'}
                   'Authorization': "Bearer " + token,
                   'Content-length': str(len(payload_2))
                   }
        
        #   --- Debug section ---
        print("\n Serialized data: \n", payload_2)
        print("\n Content-lenght: ", len(payload_2))
        #   --- End of debug section

        # request = requests.post(upload_url, headers=headers, data=payload)
        request = requests.post(upload_url, data=payload_2, headers=headers)

        if request.status_code == 200:
            print("\n Data uploaded!")
        else:
            print("\n Error: ", str(request.status_code), json.loads(request.content))

    def test_pop3_msg_upload_2(self, st_ip, st_port, token):
        
        upload_url = upload_url = "http://" + st_ip + \
            ":" + st_port + "/api/v1/upload/pop3"

        msg = pb

        header = pb.MessageHeader()
        header.version = 1
        header.type = 2

        #   Filling MessageHeader structure
        pb.MessageHeader().version = 1
        pb.MessageHeader().type = 2
        
        # msg_header.Extensions[UploadDataProtocol_pb2.MessageDataPOP3.host_address] = "192.168.1.10"

        #msg_header.content.Extensions[UploadDataProtocol_pb2.MessageDataConversationMessage].messenger_name = "Custom type"
        #UploadDataProtocol_pb2.MessageHeader.descriptor.GetOptions().Extensions[UploadDataProtocol_pb2.MessageDataConversationMessage]


        #   Filling MessageSystemInfo structure
        pb.MessageSystemInfo().address = "192.168.1.1" 
        pb.MessageSystemInfo().mname = "workstation"
        pb.MessageSystemInfo().mdnsname = "worstation.domain.local"
        pb.MessageSystemInfo().msid = "S-1237128937-123123-123123"
        pb.MessageSystemInfo().mdomainsid = "S-1237128937-123210000003-12903833"
        pb.MessageSystemInfo().dname = "domain"
        pb.MessageSystemInfo().ddnsname = "domain.local"
        pb.MessageSystemInfo().dsid = "S-1237128937"
        pb.MessageSystemInfo().usid = "S-1237128937-123210000003-12321311"
        pb.MessageSystemInfo().uname = r"domain\user"
        pb.MessageSystemInfo().udispname = "Sample User"
        pb.MessageSystemInfo().udsid = "S-1237128937"
        pb.MessageSystemInfo().udname = "domain"
        pb.MessageSystemInfo().uddnsname = "domain.local"
        pb.MessageSystemInfo().dtime_tzbias = -180
        pb.MessageSystemInfo().mfqdn = "CN=PG1032,OU=Desktops,DC=pg,DC=local"
        pb.MessageSystemInfo().ufqdn = "CN=Sample User,OU=Moscow,OU=Company,DC=domain,DC=local"

        #   Filling MessageProcessInfo structure
        pb.MessageProcessInfo().process_name = "none"
        pb.MessageProcessInfo().process_filepath = "none"
        pb.MessageProcessInfo().process_version = "none"
        pb.MessageProcessInfo().process_product_name = "none"
        pb.MessageProcessInfo().process_company_name = "falcongaze"
        pb.MessageProcessInfo().process_description = "none"

        #   Filling MessageDataPOP3Message structure
        pb.MessageDataPOP3().host_address = "192.168.1.10"
        pb.MessageDataPOP3().host_port = 110
        pb.MessageDataPOP3().dtime_utc = int(131790780000000000)
        pb.MessageDataPOP3().user_name = "Sample-user"
        pb.MessageDataPOP3().user_pass = "Sample-pass"
        s = "Message-body"
        pb.MessageDataPOP3().msg = s.encode('utf-8')


        payload = pb.MessageHeader().SerializeToString()

        headers = {'Content-Type': 'application/octet-stream',  # OR {'Content-Type': 'application/x-protobuf'}
                   'Authorization': "Bearer " + token,
                   'Content-length': str(len(payload))
                   }
        
        #   --- Debug section ---
        print("Serialized data: ", payload)
        print("Content-lenght: ", len(payload))
        #   --- End of debug section ---

        request = requests.post(upload_url, data=payload, headers=headers)

        if request.status_code == 200:
            print("Data uploaded!")
        else:
            print("Error: ", str(request.status_code), json.loads(request.content))


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

        }  # Just FYI

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
                print("Unknown error: ", str(http_error_code),
                      json.loads(int_error_code))
