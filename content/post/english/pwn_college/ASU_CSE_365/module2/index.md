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

