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

