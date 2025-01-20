---
title: "GIT笔记"
description: 
date: 2025-1-14
image: /img/note.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - notes

typora-root-url: ..\..\..\..\..\static

---

## 命令

从 git 服务器拉取代码

```bash
git clone xxx.git
```

配置开发者用户和邮箱，代码每次提交包含配置

```bash
git config user.name xxx
git config user.email xx@xx.com
```

查看文件变动状态

```bash
git status
```

添加文件变动到暂存区

```bash
git add xxfile
git add . # 添加所有文件

git add -i # 进入交互式
# patch: 显示文件当前内容与本地版本库差异，决定是否添加修改到暂存区
# update: 列出工作区 修改 或 删除 的文件列表
# diff: 比较暂存区文件和本地版本库的差异
```

提交文件变动到版本库

```bash
git commit -m "description"

# --amend 只添加 修改 和 删除 的文件到本地版本库
```

重命名文件并添加变动到暂存区

```bash
git mv src.md dest.md -f # -f 强制
```

从工作区和暂存区移除文件并添加变动到暂存区

```bash
git rm xx.md
```

将本地的代码改动推送到服务器

```bash
git push origin branch_name # orgin: git 服务器地址
```

服务器最新代码拉取到本地

```bash
git pull origin brach_name
```

版本提交记录

```bash
git log # J下翻, K上翻, Q退出
```

标记里程碑

```bash
git tag publish/0.0.1
git push origin publish/0.0.1
```

分支命令

```bash
git branch xxx # 创建
git branch -m old_name new_name # 重命名
git branch -a # 查看本地版本库和远程版本库上的分支列表
git branch -r # 远程版本库的分支列表
git branch -d xxx # 删除
git branch -vv # 查看带有最后提交id、最近提交原因等信息的本地版本库分支列表
```

切换分支

```bash
# 切换到某分支 -b 创建并切换
git checkout xxx 
# 创建一个全新的，完全没有历史记录的新分支，必须commit操作后才真正成为一个分支
git checkout --orphan new_branch 
# 比较两个分支间的差异内容，并提供交互式的界面来选择进一步的操作
git checkout -p other_branch
```

合并其它分支到当前分支

```bash
# 默认合并，分支中的各个节点都加入到master中
git merge
# 将待合并分支上的 commit 合并成一个新的 commit 放入当前分支，适用于待合并分支的提交记录不需要保留的情况
git merge --squash
# 执行正常合并，在 Master分支上生成一个新节点
git merge --no-ff
# 没有冲突的情况下合并，git自动生成提交原因
git merge --no-edit
```

栈：保存当前修改或删除的工作进度

```bash
git stash # 将未提交文件保存到Git栈中
git stash list # 查看栈中保存的列表
git stash show stash@{0} # 显示一条记录
git stash drop stash@{0} # 移除一条记录
git stash pop # 检出最新一条记录移除
git stash apply stash@{0} # 检出一条记录
git stash brach new # 检出最近一次记录并创建一个新分支
git stash clear # 清空栈里所有记录

git stash create # 为当前修改或删除文件创建自定义栈，返回一个ID
git stash store ID # 栈真正创建一个记录，文件并未从工作区移除
```

**.gitignore**中存储需要被忽略而不推送到服务器的文件

![image-20250115214715037](/img/git.zh-cn.assets/image-20250115214715037.png)
