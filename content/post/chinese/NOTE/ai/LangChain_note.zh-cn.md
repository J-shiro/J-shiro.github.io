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

**Llama模型**

```python
# HuggingFace 调用Llama
from transformers import AutoTokenizer, AutoModelForCausalLM

# 分词器
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-chat-hf")

# device_map 将预训练模型自动加载到可用的硬件设备上
model = AutoModelForCausalLM.from_pretrained(
          "meta-llama/Llama-2-7b-chat-hf", 
          device_map = 'auto')  

# 分词器将提示转化为模型可以理解的格式并将其移动到GPU上, pt返回PyTorch张量
prompt = "xxx?"
inputs = tokenizer(prompt, return_tensors="pt").to("cuda")

outputs = model.generate(inputs["input_ids"], max_new_tokens=2000)
# 令牌解码成文本
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
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

**Pydantic（JSON）解析器**

## 提示工程

**提示框架**，LangChain中提供String（StringPromptTemplate）和Chat（BaseChatPromptTemplate）两种基本类型模板

- 指令instruction：告诉模型任务做啥，怎么做
- 上下文context：额外知识来源
- 提示输入prompt input：具体问题变量
- 输出指示器output indicator：标记要生成的文本的开始

### 提示模版类型

**① PromptTemplate**

```python
from langchain import PromptTemplate
# 常用String提示模版
template = """xx{product}xxx"""
prompt = PromptTemplate.from_template(template)
print(prompt.format(product="input_something"))

# 提示模板类的构造函数
prompt = PromptTemplate(
    input_variables=["test1", "test2"], 
    template="你是xxx, 对于{test1}的{test2}, xxx?"
)
print(prompt.format(test1="xx", test2="xx"))
```

**② ChatPromptTemplate**

```python
# 常用Chat提示模板, 组合各种角色消息模板

# 模板的构建
system_template = "xx{product}xx"
system_message_prompt = SystemMessagePromptTemplate.from_template(system_template)

human_template = "xxx{product_detail}。"
human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)

prompt_template = ChatPromptTemplate.from_messages(
    [system_message_prompt, human_message_prompt]
)

# 格式化提示消息生成提示
prompt = prompt_template.format_prompt(
    product="xxx", product_detail="xxx"
).to_messages()
```

**③ FewShotPromptTemplate**

- 少样本提示模板，模仿示例写出新文案

- Few-Shot(少样本)、One-Shot(单样本)、 Zero-Shot(零样本)：让机器学习模型在极少量甚至无示例情况下学习到新概念或类别

```python
# 创建示例样本
samples = [
	{
		"key1": "xx",
		"key2": "yy"
	},
	{
		"key1": "zz",
		"key2": "qq"
	}
]

# 创建提示模板
template="键1: {key1}\n 键2: {key2}"
prompt_sample = PromptTemplate(input_variables=["key1", "key2"], template = template)

# 创建FewShotPromptTemplate对象
prompt = FewShotPromptTemplate(
	examples = samples,
    example_prompt=prompt_sample,
    suffix="{key1}{key2}",
    input_variables=["key1", "key2"]
)
```

### CoT

- 思维链，Chain of Thought，用于引导模型推理
- Few-Shot CoT提示中提供CoT示例，Zero-Shot CoT让模型一步一步思考

```python
cot_template = """将包含一些对话推导示例"""
system_prompt_cot = SystemMessagePromptTemplate.from_template(cot_template)
```

### TOT

- 思维树，Tree of Thoughts
- 为任务定义具体思维步骤及每个步骤候选项数量

![image-20241106201642021](/img/LangChain_note.zh-cn.assets/image-20241106201642021.png)

