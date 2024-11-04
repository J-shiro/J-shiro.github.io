---
title: "LangChain笔记"
description: 
date: 2024-11-01
image: /img/ai_note.jpg
math: 
license: 
hidden: false
comments: true
draft: false
categories:
    - notes
    - AI

typora-root-url: ..\..\..\..\..\static
---

- 字节青训营学习

## 基本知识

- LangChain是一个基于大语言模型（LLMs）用于构建端到端语言模型应用的框架

- 组件：模型（Models）、提示模板（Prompts）、数据检索（Indexes）、记忆（Memory）、链（Chains）、代理（Agents）

**安装**

```bash
pip install langchain
pip install openai
pip install langchain-openai
# 手动下载tar解压后 python setup.py install
```

**初始化**

```python
# coding=utf-8
import os
import httpx
from openai import OpenAI

os.environ["OPENAI_API_KEY"] = 'openai_api_key'
# 解决httpx中ssl问题
proxy_url = "http://127.0.0.1:7890"
httpx_client = httpx.Client(proxies={"http://": proxy_url, "https://": proxy_url})
openai_client = OpenAI(http_client=httpx_client)
```

**Text模型**

```python
response = openai_client.completions.create(
    model="gpt-3.5-turbo-instruct",
    temperature=0.5,
    max_tokens=100,
    prompt=user_prompt
)
print(response.choices[0].text.strip())
```

**Chat模型**

```python
response = openai_client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[
        {"role": "system", "content": "You are a helpful assistant designed to output JSON. And Answer with chinese."},
        {"role": "user", "content": "input_the_prompt_content"}
    ],
    temperature=0.8,
    max_tokens=20,
)
print(response.choices[0].message.content)
```

**LangChain调用**

```python
# text模型
from langchain_openai import OpenAI
llm = OpenAI(model="gpt-xxx",temperature=0.8,max_tokens=60, http_client=httpx_client)
response = llm.invoke("xxx")
print(response)

# chat模型
from langchain.schema import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
chat = ChatOpenAI(model="gpt-xxx", temperature=0.8, max_tokens=600, http_client=httpx_client)

messages = [
    SystemMessage(content="你是一个很棒的智能助手"),
    HumanMessage(content="帮助我xx"),
]
response = chat.invoke(messages)
print(response)
```

## 模型I/O

过程：Format输入提示，Predict调用模型，Parse输出解析

###  提示模板

```python
from langchain.prompts import PromptTemplate

template = """对于 {price} 元的 {something} XXXX? """ # 原始模板f-string
prompt = PromptTemplate.from_template(template) # LangChain提示模板
input = prompt.format(something=["XX"], price="50")
```

### 语言模型

```python
# 可初始化不同的语言模型
model.invoke(input)
```

### 输出解析

言语转换为结构化的数据结构

```python
from langchain.output_parsers import StructuredOutputParser, ResponseSchema

prompt_template = """xxxxxx{format_instructions}"""
# 接收响应模式
response_schemas = [
    ResponseSchema(name="description", description="描述xxx信息"),
    ResponseSchema(name="reason", description="为何xxx"),
]
# 创建输出解析器
output_parser = StructuredOutputParser.from_response_schemas(response_schemas)

# 获取输出的格式说明
format_instructions = output_parser.get_format_instructions()
prompt = PromptTemplate.from_template(
    prompt_template, partial_variables={"format_instructions": format_instructions}
)

parsed_output = output_parser.parse(output.content)# output为LLM返回
parsed_output["xxx"] = 'xxx' #也可直接赋值加入内容
# {'description': 'xxxx', 'reason': 'xxxxx', 'xxx': 'xxx'}
```

## 提示工程

**提示框架**，LangChain中提供String（StringPromptTemplate）和Chat（BaseChatPromptTemplate）两种基本类型模板

- 指令instruction：告诉模型任务做啥，怎么做
- 上下文context：额外知识来源
- 提示输入prompt input：具体问题变量
- 输出指示器output indicator：标记要生成的文本的开始

```python
# PromptTemplate 提示模板类的构造函数
prompt = PromptTemplate(
    input_variables=["test2", "test1"], 
    template="你是xxx, 对于{arg1}的{arg2}, xxx?"
)
print(prompt.format(test2="xx", test1="xx"))

# ChatPromptTemplate

```

