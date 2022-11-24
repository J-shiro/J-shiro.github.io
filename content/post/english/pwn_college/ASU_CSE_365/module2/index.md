---
title: "PwnCollege_Note2"
description: the 2nd module of ASU CSE 365, talking web
date: 2022-11-17
image: pwncollege.png
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - Pwn.college
    - ForeignCourse


---

# Talking Web

-----------**ASU CSE 365**: Introduction to Cybersecurity

## Talking Web: Introduction

static http request: 

- `GET /cat.gif HTTP/1.0`—>
- `HTTP/1.0 200 OK`  <—

dynamic http request: 

- `GET /time?tz=UTC HTTP/1.0` —>

- ```web-idl
  HTTP/1.0 200 OK
  Content-Type: text/plain
  Content-Length: 19
  
  2022-01-19 03:14:07 //<——
  ```

## Talking Web: The Internet

TCP/IP

![](img/pwn_college/lesson/TCPIP.png)

- Link Layer(Physically link computers)
- Internet Layer(Find the right computer:IP、ICMP、ARP)
- Transport Layer(Find the right program:UDP、TCP)
- Application Layer(Talk with the program:HTTP、FTP、SMTP、SSH)

## Talking Web: RFC 1945



## babyhttp

**the challenge python shell**

```python
#!/opt/pwn.college/python
import random
import pathlib
import shutil
import hashlib
import psutil
from flask import Flask, request, make_response, redirect, session

app = Flask(__name__)#app is an instance of a flask that accepts requests from a web server, the parameter is the __name__(env parameter)-->py file_name/function_name
flag = open("/flag").read()
config = (pathlib.Path(__file__).parent / ".config").read_text()
#__file__:the current file path; /:add ; read_text():read the text file to string
challenge_name, client_name = config.split()#client_name:used command

def value(n): #Generates a n-character hexadecimal number
    return "".join(random.choice("0123456789abcdef") for _ in range(n)) #_:temp parameter

def validate(name, value, correct):
    assertion_message = f"Incorrect {name}: value `{value}`, should be `{correct}`\n" #f-string
    assert value == correct, assertion_message
    #assert expression (if false:output)

......#only analyse some of the whole code

if __name__ == "__main__":
    app.secret_key = flag#SECRET_KEY major role is to provide a value for all kinds of HASH
    app.run("127.0.0.1", 80)
```

level1: **curl**-----> (CommandLine Uniform Resource Locator):   The network request tool used under the terminal

```shell
USAGE: curl [options...] <url>
-v: output details
```

execute the file and click into the web: 

```shell
Incorrect client: value `/usr/lib/code-server/lib/node`, should be `/usr/bin/curl`
so open a new terminal: `curl 127.0.0.1:80` get the flag
```

level2: **nc**----->Used to send and to monitor any TCP and UDP data, so we can simulate any client or server

```shell
nc 127.0.0.1 80
#Simulate the HTTP request
GET / HTTP/1.1	#input
host: localhost	#127.0.0.1 either
-l:listeng		-p:port
```

level3: **python**

```shell
python
>>import requests
>>response = requests.get(url='http://127.0.0.1:80')
>>print(response) #<Response [200]>
>>print(response.content) #get the flag
```

level4: **curl**

```shell
curl 127.0.0.1:80 
#Incorrect host: value `127.0.0.1`, should be `xxx`
curl 127.0.0.1:80 -H 'Host:xxx' #get the flag
#-H :Request custom IP address and specify HOST only for the 'HTTP'
```

level5: **nc**

just change the `host: localhost` to the `host: xxx` so that we can get the flag.

level6: **python**

```shell
python
>>import requests
>>headers={"host":"xxx"}
>>res=requests.get("http://127.0.0.1:80",headers=headers)
>>print(response.text) #get the flag
```

level7: **curl**--->hint: path

```shell
curl -v 127.0.0.1/xxx #get the shell:it's not explicit so I even didn't understand the meaning of 'path'
```

level8: **nc**

just change the `GET / HTTP/1.1` to the `GET /xxx HTTP/1.1` so that we can get the flag.

level9: **python**

change the `http://127.0.0.1:80` to `http://127.0.0.1/xxx` and get the flag

level10: **curl**--->hint:path_encoded

```shell
curl -v 127.0.0.1/xx%20xx%20xx # /xx xx xx the blank will be the %20 in the url
```

level11: **nc**

```shell
GET /xx%20xx%20xx HTTP/1.1 #get the flag
```

level12: **python**

```python
res=requests.get("http://127.0.0.1/xx%20xx%20xx")
```

level13: **curl**--->hint: arg

```shell
curl -v 127.0.0.1:80?a=xxx
curl -v 127.0.0.1:80/?a=xxx
```

level14: **nc**

```shell
GET /?a=xxx HTTP/1.1 
```

level15: **python**

```python
res=requests.get("http://127.0.0.1:80?a=xxx")
```

level16: **curl**--->hint:arg_multi

First, there're some special character escape encodings in urls: `&:%26` `#:%23`. Change these character

```shell
curl -v 127.0.0.1:80?a=xxx&b=xxx  #same as'curl -v 127.0.0.1:80?a=xxx
#need to transfer meaning
curl -v 127.0.0.1:80?a=xxx\&b=xxx	#get flag
```

another solution:

```shell
curl -X GET -G --data-urlencode "a=xxx" --data-urlencode "b=xx#xx xx&xx" -i http://127.0.0.1:80
#in double quote the '&# ' don't need to change
#-X:--request <command> Specify request command to use
#-G:--get	Put the post data in the URL and use GET
#--data-urlencode:HTTP POST data url encoded
#-i:--include Include protocol response headers in the output
```

level17: **nc**

```shell
nc 127.0.0.1 80
GET /?a=xxx&b=xxx HTTP/1.1 #didn't use HTTP/1.1 can also get the flag
```

level18: **python**

```python
payload={'a':'xxx','b':'xx xx&xx#xx'}
res=requests.get("http://127.0.0.1",params=payload)
```

level19: **curl**--->form, The form property returns a form reference that contains a URL field.

```shell
#POST
curl 127.0.0.1 -d "a=xxx"
#-d:--data <data>   HTTP POST data
```
