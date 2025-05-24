# GIT


## 命令

先 commit 一次后才会真正创建 master 分支

从 git 服务器拉取完整仓库代码

```bash
git clone xxx.git
```

配置开发者用户和邮箱，代码每次提交包含配置

```bash
git config user.name xxx
git config user.email xx@xx.com

cat .git/config # 查看配置

git config --list # 获取所有 git 配置

# 配置代理
git config --global http.proxy 127.0.0.1:7890
git config --global https.proxy 127.0.0.1:7890

# 查看代理
git config --global --get http.proxy
git config --global --get https.proxy

# 取消
git config --global --unset http.proxy
git config --global --unset https.proxy
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

此时`.git/objects`中加入`xx/yyyyyyyyy`，可通过`git cat-file -p xxyyyyyyyyy`查看添加的文件内容

列出将要被提交的文件

```bash
git commit -n
```

提交文件变动到版本库，若为其他分支会获取一个url用于pull request

```bash
git commit -m "description" # 会创建新的tree、blob、commit object
# 可以直接换行
# --amend 只添加 修改 和 删除 的文件到本地版本库，修改最近一次commit信息，修改后commit id变化

feat/fix/...: xxxx

- xxxx
- xxxx
```



查看commit添加的内容

```bash
git ls-files -s
git show --raw # 最近提交的commit文件
```

撤消上一次commit的内容

```bash
git reset --soft HEAD^
git reset --soft HEAD~1 # 撤回到上一次还没提交
```

删除暂存区的内容

```bash
git rm --cached -r file
```

修改最近3个commit

```bash
git rebase -i HEAD~3
```

查看悬空的commit

```bash
git fsck --lost-found
```

删除不需要的object，且打包压缩object减少仓库体积

```bash
# 先设置reflog防止无操作后数据丢失
git reflog expire --expire=now --all
git gc prune=now # 修剪多久前对象，默认2周前
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
git push -u origin branch_name # 无该分支 -u 来创建
```

删除远程分支

```bash
git push origin -d remote_branch
```

将本地分支推送到对应远程分支

```bash
git push origin dev_tmp:dev_tmp
```

服务器最新代码拉取到本地并与本地代码合并，等价于`git fetch + git merge`

```bash
git pull origin brach_name # main or master
git pull --rebase # 等价于 git fetch + git rebase
```

合并他人代码

```bash
git fetch # 显示哪些分支发生更改
git merge orgin/xxx_branch # 云端他人分支合并到自己分支
git stash # 处理冲突 将当前工作目录更改丢到一边，使得工作目录保持干净
git merge orgin/xxx_branch
git stash pop # 将刚丢到一边的更改捡回来
```

远程分支存在本地分支没有的代码，本地分支存在远程分支没有的代码

```bash
git pull --no-rebase origin branch_name
// 处理冲突
git add xxx
git rm xxx

git commit xxx
git push origin branch_name:branch_name
```

当`git reset HEAD~3`使得远程分支高于本地分支多个版本，而需要远程分支强制回滚到本地某个分支(不建议使用)

```bash
git push --force-with-lease origin branch_name
```



版本提交记录

```bash
git log # J下翻, K上翻, Q退出
```

标记里程碑

```bash
git tag publish/0.0.1
git tag -a # 创建附注标签
git push origin publish/0.0.1
```

分支命令

```bash
git branch # 查看分支
git branch xxx # 创建
git branch -m old_name new_name # 重命名
git branch -a # 查看本地版本库和远程版本库上的分支列表
git branch -r # 远程版本库的分支列表
git branch -d xxx # 删除
git branch -vv # 查看带有最后提交id、最近提交原因等信息的本地版本库分支列表
git branch --set-upstream-to=origin/my_test # 将本地分支关联到远程分支
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

# fast-forward：线性不创建新merge结点，命令`--ff-only`
# three-way merge：三方合并产生新merge结点，命令`--no-ff`
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

gitlab 配置

```bash
# gitlab ssh key
ssh-keygen -t rsa -C "email.com" # 查看 id_rsa.pub 复制到 gitlab ssh-key 中
# 即可 git clone
```

比较工作区、暂存区、本地版本库间文件差异

<img src="/img/git.zh-cn.assets/image-20250122215003787.png" alt="图片无法加载" />

```bash
git diff --stat
```

远程仓库

```bash
git remote -v # 列出已存在的远程分支
git remote add origin https://github.com/xx/xx.github.com.git # 添加一个新远程仓库
```

将远程版本库的最新更新取回到本地版本库，不会执行merge操作，会修改refs/remote内分支信息

```bash
git fetch origin xx/0.0.1
```

ssh免密配置访问

```bash
ssh-keygen -t ed25519 -C "email@example.com"
# 秘钥公钥在~/.ssh/id_ed25519及id_ed25519.pub中
```

**.gitignore**中存储需要被忽略而不推送到服务器的文件

<img src="/img/git.zh-cn.assets/image-20250115214715037.png" alt="图片无法加载" />

某分支下专门写注释学习

```bash
git worktree add ../project-a a
```

## object

- commit：存储提交信息，一个 commit 对应唯一版本的代码，可找到 tree ID
- tree：存储文件目录信息，可获取不同 blob ID
- blob：存储文件内容
- tag

## Refs

Refs中存储对应的commit ID

`refs/heads` 前缀表示分支，`refs/tags` 前缀表示标签

## 研发

**github**

- 一个主干分支，基于Pull Request往主干分支提交代码
- owner外用户Fork创建自己仓库进行开发

## Vscode

记录与 git 对应命令

- Changes 里文件 "+" 放到 Staged Changes : `git add .`
- `√ + message` : `git commit -m "message"`

