---
title: "Talking Web"
description: ASU CSE 365, talking web(finish)
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

①Hyper Transfer Protocol: HTTP is an application-level protocol 

②Request-Line = <span style="background: #86cce8">Method SP Request-URI SP HTTP-Version CRLF</span>

SP: space, CRLF: \n

- Method: "GET"	|	"HEAD"	|	"POST"

③Status-Line = <span style="background: #86cce8">HTTP-Version SP Status-Code SP Reason-Phrase CRLF</span>

**Status-Code Definition**

1xx: **Informational**-Not used, but reserved for futrue use

2xx: **Success**-The action was successfully received, understood, and accepted

3xx: **Redirection**-Further action must be taken in order to complete the request

4xx: **Client Error**-The request contains bad syntax or can't be fulfilled

5xx: **Server Error**-The server failed to fulfill an apparently valid request

![](img/pwn_college/lesson/StatusCode.png)

④ GET

> GET /greet HTTP/1.0
>
> Host: hello.example.com

> HTTP/1.0 200 OK
>
> Content-Type: text/html; charset=UTF-8
>
> Content-Length: 39
>
> 
>
> `<html><body>Hello, World!</body></html>`

⑤ HEAD

> HEAD /greet HTTP/1.0
>
> Host: hello.example.com

> HTTP/1.0 200 OK
>
> Content-Type: text/html; charset=UTF-8
>
> Content-Length: 39

⑥ POST

> POST /greet HTTP/1.0
>
> Host: hello.example.com
>
> Content-Length: 11
>
> Content-Type: application/x-www-form-urlencoded
>
> 
>
> name=Connor

> HTTP/1.0 200 OK
>
> Content-Length: 0

## Talking Web: URLs and Encoding

① URL: `<scheme>://<host>:<port>/<path>?<query>#<fragment>`

scheme: Protocol used to access resource

host: Host that holds resource

port: Port for program servicing resource

path: Identifies the specific resource

query: Information that the resource can use

fragment: Client information about the resource

②URL encoding

SP=%20	#=%23	/=%2F	?=%3F	A=%41

![](img/pwn_college/lesson/URLenCode.png)

③ Content-Type: Form

application/x-www-form-urlencoded	name=xx

application/json	{"name":"xx"}

## Talking Web: State

① HTTP is a stateless protocol

**solution:** use HTTP Headers for maintaning state

1. The server sets a cookie in a response with the header: Set-Cookie
2. The client includes the cookie in future requests with the header: Cookie

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

level20: **nc**

```shell
vim a.txt
#POST / HTTP/1.1
#Content-Length: 34 #this counts must be equal to the arguments
#Content-Type: application/x-www-form-urlencoded #Form data is encoded as name/value pairs. This is the standard encoding format
#
#a=xxx
cat a.txt | nc 127.0.0.1 80 # get the flag
```

level21: **python**

```python
para={'a':'xx'}
res=requests.post("http://127.0.0.1",data=para)
```

level22: **curl**--->hint: form_multi

```shell
curl http://127.0.0.1:80 -d "a=xx" -d "b=xx" #get the flag
#found that '#' and ' ' don't need to change to %23 and %20, but '&' must change
```

level23: **nc**

```shell
POST / HTTP/1.1
Content-Length: 74
Content-Type: application/x-www-form-urlencoded

a=xxx&b=xxx
```

level24: **python**

```python
para={'a':'xx','b':'xx'} #the '&, ,#' all don't need to change
```

level25: **curl**--->hint: json

```shell
curl 127.0.0.1 -H "Content-Type: application/json" -d '{"a":"xxx"}'
```

level26: **nc**

```shell
POST / HTTP/1.1
Content-Length: 57
Content-Type: application/json

{"a":"xxx"}
```

level27: **python**

```python
import json,requests
data={"a":"xx"}
headers={'Content-Type':'application/json'}
res=requests.post("http://127.0.0.1",headers=headers,data=json.dumps(data))
print(res.text)
```

level28: **curl**--->hint: json_multi

having trouble here!

```shell
# the first try
curl 127.0.0.1 -H "Content-Type: application/json" -d '{"a":"8484e2a3838f64b6943f66c57d0d52a2","b":"{'\'c\'': '\'99aa4d7f\'', '\'d\'': ['\'7eb4984c\'', '\'c2c37973\ eb81af72\&b1ffc820\#f4fb51c1\'']}"}'

hacker@babyhttp_level28:/challenge$ curl 127.0.0.1 -H "Content-Type: application/json" -d '{"a":"8484e2a3838f64b6943f66c57d0d52a2","b":"{'\'c\'': '\'99aa4d7f\'', '\'d\'': ['\'7eb4984c\'', '\'c2c37973\ eb81af72&b1ffc820\#f4fb51c1\'']}"}'
Incorrect json b: value {'c': '99aa4d7f', 'd': ['7eb4984c', 'c2c37973 eb81af72&b1ffc820#f4fb51c1']}, should be {'c': '99aa4d7f', 'd': ['7eb4984c', 'c2c37973 eb81af72&b1ffc820#f4fb51c1']}
#question: it is string instead of json, so we need to remove the quotes around the values of b
```

```shell
# after many tries, get the solution
hacker@babyhttp_level28:/challenge$ curl 127.0.0.1 -H "Content-Type: application/json" -d '{"a":"8484e2a3838f64b6943f66c57d0d52a2","b":{"c":"99aa4d7f","d":["7eb4984c","c2c37973 eb81af72&b1ffc820#f4fb51c1"]}}'
pwn.college{xxx} #get the flag
#and remove the blackslash because it is not neccessory.
#and can't interchange the quotes!
```

level29: **nc**

```shell
#test.txt
POST / HTTP/1.1
Content-Length: 123
Content-Type: application/json

{
"a":"xx",
"b":{"c": "xxx", "d": ["xx", "x xx&xxx#xxxx"]}
}
cat test.txt | nc 127.0.0.1 80
```

level30: **python**

```python
data={"a":"xx","b":{'c': 'x', 'd': ['xx', 'x xx&xxx#xxx']}} #just change this line
```

level31: **curl**--->hint: redirect

```shell
curl 127.0.0.1:80
curl 127.0.0.1:80/xxx #1
curl -L 127.0.0.1:80  #2	
#-L:-location-->follow redirects
#--max-redirs options :redirect counts,-l:Always follow the redirect
```

level32: **nc**

```shell
nc -v 127.0.0.1 80
GET /xxx HTTP/1.1
#xxx from the "Location:xxx" of the response headers
```

level33: **python**

```python
res=requests.get("http://127.0.0.1",allow_redirects=True)
```

level34: **curl**--->hint: cookie

```shell
curl 127.0.0.1 -b "anything"
#<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
curl 127.0.0.1 -L
#curl: (47) Maximum (50) redirects followed
curl 127.0.0.1 -L -b "anything"	#get flag
```

level35: **nc**

```shell
nc -v 127.0.0.1 80
GET / HTTP/1.1
Cookie: cookie=xxx
```

level36: **python**

```python
headers={"cookie":"anything"}#I found that the cookie is no need
```

level37: **curl**--->hint: state

```shell
curl -L -b "xx" 127.0.0.1
```

level38: **nc**

```shell
nc 127.0.0.1 80
GET / HTTP/1.1
Cookie: session=xxx
```

level39: **python**

```python
res=requests.get("http://127.0.0.1")
```

