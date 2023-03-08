---
title: "PwnCollege_Note7"
description: ASU CSE 365, sandboxing
date: 2023-03-07
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

# Sandboxing

-----------**ASU CSE 365**: System Security

## Sandboxing: Introduction

untrusted code/data should live in a process with almost 0 permissions

- spawn "privileged" parent process
- spawn "sandboxed" child processes
- when a child needs to perform a privileged action, it asks the parent

![](index.assets/image-20230307172617141.png)

## babyjail

level1: **Escape a basic chroot sandbox!**
