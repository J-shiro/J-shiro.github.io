---
title: "Fuzzing笔记"
description: 
date: 2024-10-09
image: /img/note.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - notes
    - fuzzing

typora-root-url: ..\..\..\..\..\static
---

## 工具

### AFL++

**编译**获取可被测试的程序

```Bash
export AFL_USE_ASAN=1
afl-gcc -fsanitize=address -o test test.c
```

`afl-as`会执行函数`add_instrumentation()`进行插桩，最后执行`as`做汇编，产生的`test`文件是插桩版本

```Bash
objdump -M intel -d test | grep __afl
```

可查看许多`__afl`前缀的函数

**模糊测试**

```Bash
afl-fuzz -i seed-dir -o out-dir -m none ./test
# -i 测试用例 -o 结果 -f 指定文件读取输入 -t 超时
# -m 内存限制 -d 突变阶段跳过最初处理 -n 对无插桩目标进行fuzz
```

可在`crashes`目录中查看成功测试
