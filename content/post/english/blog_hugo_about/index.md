---
title: "HUGO_blog"
description: 
date: 2022-10-24
image: 86.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - blog
---

## git

Use the following statement to upload the local file to GitHub.

```shell
hugo server -D
hugo -F --cleanDestinationDir
git add .
git commit -m "xxxx"
git push -u origin master
```

some more commands.

```shell
git remote -v #view the remote library
git branch	#view the branch
git checkout main	#change the default branch
```

**init：**

```shell
echo "# Algorithm-design-and-analysis" >> README.md
git init
git remote add origin sshcopy
git branch -M main
git add README.md
git commit -m "xx"
git push -u origin main
```

**standardization:**

```shell
git checkout -b project_name/my_name/add_function
fork:
git add xxx
git commit -m "[XXX] add xxx
add xxx
issue:#xxxx
"#the supplementation of commit information
#git commit --amend 
git push -f
```

## Problems encountered 

**error1: Updates were rejected because the remote contains work that you do not have locally. This is usually caused by another repository pushing to the same ref. You may want to  first integrate the remote changes (e.g., 'git pull ...') before pushing again.**

**solution:**

```shell
git pull origin master --allow-unrelated-histories
# I created a README.md but the local didn't have it.
```

**error2: warning: in the working copy of '.vscode/tasks.json', LF will be replaced by CRLF the next time Git touches it**

Line breaks in Windows are different from line breaks in Unix, and Git converts them automatically.

**solution: Disable automatic conversion**

```shell
git config --global core.autocrlf false
```



## add picture

Add images to the markdown: the images need to be placed in path: `/static/img`. Then, use the following statement in the markdown.(Typora)

```
![](/img/xxx.jpg)
```

