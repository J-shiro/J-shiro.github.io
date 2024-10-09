---
title: "区块链笔记"
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
    - blockchain

typora-root-url: ..\..\..\..\..\static
---

## 基础知识

比特币

以太坊

智能合约：保证承诺不被违背

去中心化网络

Web3

**交易**

`Transaction Fee`：付给处理此次交易的矿工的费用

`Gas Price`：交易中每个执行单元的费用

**运作机制****`https://andersbrownworth.com/blockchain/hash`**

- 使用**Keccak256**哈希算法
- 矿工(miner)：将不断试错找到一个`Nonce`来使得`Block`、`Nonce`以及`Data`进行哈希后以`0000`开头
- **ECDSA算法**根据**私钥**创建**公钥**，私钥创建签名**，**公钥验证签名
- **账户地址**由公钥衍生出来
