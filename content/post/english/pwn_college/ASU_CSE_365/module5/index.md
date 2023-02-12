---
title: "PwnCollege_Note5"
description: the 5th module of ASU CSE 365, intercepting communication
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
- Protocol: declare what the follow-on contents protocol is
- Header Checksum: doing some sort of mathematical operation on the header, we can see if data was corrupted



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

