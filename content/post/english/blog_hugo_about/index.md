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

# git

Use the following statement to upload the local file to GitHub.

```shell
hugo server -D
hugo -F --cleanDestinationDir
git add .
git commit -m "xxxx"
git push -u origin master
```



```shell
git remote -v //查看远程库
git branch	//查看分支
git checkout main	//切换分支
```



# add picture

Add images to the markdown: the images need to be placed in path: `/static/img`. Then, use the following statement in the markdown.(Typora)

```
![](/img/xxx.jpg)
```

