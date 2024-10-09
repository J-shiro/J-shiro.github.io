---
title: "AI笔记"
description: 
date: 2024-10-09
image: /img/note.jpg
math: "true"
license: 
hidden: true
comments: true
draft: false
categories:
    - notes

typora-root-url: ..\..\..\..\..\static
---

## 基础

**灰度图**

一般为3个数相乘，前两个数是长宽，单位为像素，最后一个数是指RGB通道数，灰度图为1，相乘的结果作为维数，输入值将平展为一列向量

**均方误差**

mean_squared_error: MSE

**专业术语**

- 输入变量/特征 **x**
- 输出变量/目标变量 **y**
- 训练示例总数 **m**
- 训练示例 **(x, y)**
- 第 i 个训练示例$(x^{(i)}, y^{(i)})$
- 输出的估计值 $\hat y$
- 函数/模型 **f**
- 系数，权重，变量
- 满足指标，优化指标
- 人类水平代表贝叶斯最优误差
- F-范数：矩阵每个数平方和开根号

**模型训练步骤**

1. 给定x,w,b明确输出函数
2. 确定损失和代价函数
3. 训练数据最小化代价函数

## 模型评估

多元特征时，不好绘制多维图像，使用一些系统方法评估模型

构造数据：数据增强（旋转，扭曲）、数据合成（人工生成）

**迁移学习——针对数据集小**

- 预训练，获取大模型：神经网络先分类1000份得到前N-1层的参数
- 微调，小模型调参：使用这些参数，迁移到另一个神经网络，用梯度下降优化求第N层的参数或将前N-1层参数作为初始值继续变化，最后一层1000个神经元替换为其他如10个神经元，用于分类10份
- 两模型输入类型需相同

**多任务学习**

一个神经网络模型中分类每张图都包含多个标签

**端到端深度学习（end-to-end）**

大量数据包括各种子数据，不经过中间过程

### **预处理**

将数据集分为训练集（训练模型）和测试集（评估模型），需要具有相同分布

- 回归模型：计算训练集与测试集的**代价函数中的平方误差项，比较测试集大小**
- 分类模型：计算训练集与测试集的**代价函数中的平均损失函数项，主要看测试集和训练集中误分类的分值，即预测的y和实际y不相等的个数**

**标准化：**需要先将数据规格化，即减去平均值并除以标准差，得到[-1, 1]的范围，并且打乱数据

### **交叉验证**

**cross validate**

分为：训练集60%、测试集20%、交叉验证集20%，**大数据集时：可分为98%、1%、1%**

1. 练模型：N个模型使用训练集得到N组参数
2. 挑模型：使用交叉验证集求每个模型的平方误差$J_{cv}$比较
3. 测模型：最终使用测试集求平方误差评估泛化误差(Generalization Error)

- 针对**训练集**进行交叉验证：将训练集分成 **K [n1,n2,...,nK]** 份，进行 **K** 次实验
- 第 **i** 次实验中，取 **ni** 作为**训练集中的验证集**，其余为**训练集中的训练集**
-  **K** 次实验最终取平均

![img](/img/ai_note.zh-cn.assets/-172845431716996.assets)

### 偏差方差

高偏差：不拟合，$J_{cv}$高，$J_{train}$高，相差不大

高方差：过拟合，$J_{cv}$高，$J_{train}$低，后者远小于前者

与多项式程度的关系

![img](/img/ai_note.zh-cn.assets/-17284543171621.assets)

正则化参数$\lambda$影响偏差、方差

![img](/img/ai_note.zh-cn.assets/-17284543171622.assets)

**表现基准**

需要加入**人类基准表现**，来判断模型的训练误差$J_{train}$和交叉验证误差$J_{cv}$

**学习曲线判断偏/方差**

高偏差下，增加训练集不会有助于模型（例如：使用线性模型拟合二次函数，再多点都不利于拟合）

![img](/img/ai_note.zh-cn.assets/-17284543171623.assets)

高方差下，增加训练集有助于模型（例如：模型过拟合匹配了四次函数，数据增多使模型逐渐接近四次函数模型）

![img](/img/ai_note.zh-cn.assets/-17284543171624.assets)

- 更多训练集：解决高方差
- 更少特征：解决高方差
- 更多特征：解决高偏差
- 增加多项式特征：解决高偏差
- 增加正则化：解决高偏差
- 减少正则化：解决高方差
- 更大神经网络：解决高偏差

### 混淆矩阵

处理倾斜数据集，使用不同误差度量，而非分类误差

**Confusion Matrix**

|                          | 相关(Relevant)，正类                           | 无关(NonRelevant)，负类                      |
| ------------------------ | ---------------------------------------------- | -------------------------------------------- |
| 被检索到(Retrieved)      | **TP** (true positives)检索到正确的值          | **FP** (false positives)检索到错误的值：存伪 |
| 未被检索到(Not Retrieved | **FN** (false negatives)未检测到正确的值：去真 | **TN** (true negatives)未检测到错误的值      |

两个指标：区分只报单一类别的模型

**精准度：**$precision=\frac{TP}{TP+FP(total\,predicted\,positive)}$：预测病人得某病，大概率病人确实有该病

**召回率：**$recall=\frac{TP}{TP+FN(total\,actual\,positive)}$：病人有该病，大概率模型能够识别出来确有该病

当$f_{w,b}(x)\gt$threshold阈值，预测为1：

![img](/img/ai_note.zh-cn.assets/-17284543171625.assets)

不使用平均值$\frac{Precision+Recall}{2}$，因为P很低但R很高的情况如：只播报不得病也可能获得高平均值，而通过调和平均值，给**低值**更**多权重**，结合为一个综合指标：**F1 score**

$F_1=\frac{2}{\frac{1}{precision}+\frac{1}{recall}}=\frac{TP}{TP+\frac{FN+FP}{2}}$

### ROC曲线

Receiver Operating Characteristic，该曲线是二元分类中的常用评估方法，通过计算各种阈值的 **true positive rate(TPR)** 和 **false positive rate(FPR)** 进行绘制

- y轴：TPR = TP / (TP + FN) (Recall)
- x轴：FPR = FP / (FP + TN)

一个好的分类器尽可能**朝左上方**远离虚线

![img](/img/ai_note.zh-cn.assets/-17284543171626.assets)

比较分类器的方法：测量曲线下面积（**AUC**），完美的AUC为**1**，纯随机分类器的AUD为**0.5**

## 编程基础

### python

```Python
print(f"{x:.2f}") # x 小数点后2位

[::3, ::2] # 每3行一跳，每2列一跳
```

### Numpy

广播机制：shape 不相等时会复制调整使运算通过

```Python
np.array([[1, 2]])   # 1*2矩阵
np.array([[1], [2]]) # 2*1矩阵
# n 个中括号即 n 维矩阵

a = np.random.randn(5, 1) # 随机生成 5*1 矩阵

tensor_type.numpy() # array([[xx]], dtype=float32 将Tensor类型转换为np数组

np.matmul(a, b) # 矩阵乘法 或 a @ b
np.exp(V) # V中每个元素i: 求e^i
np.log(V)
np.abs(V) # 绝对值
np.maximum(V, 0)
np.sum(A)
A.sum(axis=0) # 垂直方向求和 axis=1 水平求和
AT = A.T # 矩阵转置
# [2, ] [2, 1] 区别
[1 2] # 秩为1的数组
[[1]
 [2]] # 2*1的矩阵
```

### TensorFlow

### Pyplot

```Python
plt.hist(x) # 直方图
```

## 机器学习

### 类别

- 有监督学习：给定输入输出对训练，最终可通过输入预测输出【回归（拟合）、分类（边界）】
- 无监督学习：将未标记的数据自动分配到不同组【聚类、异常检测、推荐系统、降维】
- 强化学习
- 深度学习

### 优化方法

**梯度下降**

（Gradient Descent，**GD**）

根据梯度下降，多参数下可能获得代价函数的多个局部极小值，迭代次数自定义，沿梯度方向将增加损失函数值

$\begin{cases}w_j = w_j-\alpha \frac{\partial}{\partial w}J(w,b)\\ b=b-\alpha\frac{\partial}{\partial b}J(w,b) \end{cases}$，$\alpha$为学习率，后面一项为 J 关于 w 和 b 的导数，同时更新 w 和 b

**动量梯度下降——加速梯度下降**

计算 dw 和 db 的滑动平均值 v ，更新权重时使得梯度下降更平滑

![img](/img/ai_note.zh-cn.assets/-17284543171627.assets)

**RMSprop算法——加速**

均方根传递（Root Mean Square prop），当梯度下降震荡时，减少某 w 参数方向的震荡

$S_{dW}=\beta_2 S_{dW} + (1-\beta_2)dW^2\\ W=W-\alpha \frac{dW}{\sqrt{S_{dW}}+\varepsilon}$

**Adam算法**

（Adaptive Moment estimation）自适应矩估计结合RMSprop和动量，对每个参数($w_i, b$)使用不同的学习率

默认：$\beta_1:0.9,\quad \beta_2: 0.999\quad \varepsilon: 10^{-8}$， $\alpha$ 需要调整

1. 动量：$V_{dW}=\beta_1 V_{dW}+(1-\beta_1)d_W\quad V_{db}=\beta_1 V_{db}+(1-\beta_1)d_b$
2. RMSprop：$S_{dW}=\beta_2 S_{dW} + (1-\beta_2)dW^2\quad S_{db}=\beta_2 S_{db} + (1-\beta_2)db^2$
3. 偏差修正： $V_{dW}^{correct}=\frac{V_{dW}}{1-\beta_1^t}\quad V_{db}^{correct}=\frac{V_{db}}{1-\beta_1^t}\quad S_{dW}^{correct}=\frac{S_{dW}}{1-\beta_2^t}\quad S_{dW}^{correct}=\frac{S_{dW}}{1-\beta_2^t}$
4. 更新参数：$W=W-\alpha\frac{V_{dW}^{correct}}{\sqrt{S_{dW}^{correct}}+\varepsilon}\quad b=b-\alpha\frac{V_{db}^{correct}}{\sqrt{S_{db}^{correct}}+\varepsilon}$

使用等高图绘制代价函数，由梯度下降从start到minimum，若每次参数移动方向基本一致，Adam将**提高学习率**，加快速度

![img](/img/ai_note.zh-cn.assets/-17284543171628.assets)

当梯度下降呈现下图形式，参数不断来回振荡，Adam将减少学习率，加快速度

![img](/img/ai_note.zh-cn.assets/-17284543171639.assets)

```Python
model.complile(optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3)) # 默认初始学习率 0.001
```

**机器学习策略**

**正交化**

### 回归模型

#### 线性回归

解决回归问题，预测一个连续型的因变量

线性回归模型：$f(x)=wx+b$【w: weight权重, b: bias偏置】

**代价函数**

Cost function，或**平方误差**成本(Squared error cost)函数：$J(w, b)=\frac{1}{2m}\cdot\sum_{i-1}^{m}(\hat y^{(i)} - y^{(i)})^2=\frac{1}{2m}\cdot\sum_{i-1}^{m}(f_{w,b}(x^{(i)}) - y^{(i)})^2$，找 w 和 b 使得$J(w,b)$最小，

**步长/学习率**

范围 [0, 1]，对结果产生影响，从小选择

![img](/img/ai_note.zh-cn.assets/-172845431716310.assets)

步长过小：收敛慢，花费时间长

步长过大：抖动幅度大，无法收敛或发散

**学习率衰减**

- mini-batch会产生噪声，使得最终无法收敛，所以尝试使学习率慢慢减少，则步长也慢慢减少，使得学习率开始高，后期低
- $\alpha=\frac{1}{1+d*t}\alpha_0$，d 为衰减率，t 为迭代数
- $\alpha=0.95^{t}\alpha_0\quad or \quad =\frac{k}{\sqrt{t}}\alpha_0$

**过拟合**

degree值过高可能会出现**过拟合**，表明模型过于贴合训练集，方差大

解决过拟合：可以增加训练集数；使用更少特征；正则化

**L1 正则化**为$\frac{\lambda}{2m}\sum_{j=1}^n|w_j|$

**L2 正则化**

用于解决**过拟合**，令模型选择更合适的$\theta$值，对**权重参数**用$\lambda$进行惩罚，减小参数大小，让权重参数尽可能平滑

若有 n 个参数 w ，对每个参数都进行惩罚，**线性回归模型**的代价函数变为：

$J(w, b)=\frac{1}{2m}\sum^m_{i=1}(f_{w,b}(x^{(i)})-y^{(i)})^2+\frac{\lambda}{2m}\sum^n_{j=1}w_j^2$，$\lambda\gt0$是正则化参数，第二项为正则化项

![img](/img/ai_note.zh-cn.assets/-172845431716311.assets)

```Python
Dense(units=2, kernel_regularizer=L2(0.01)) # 正则化 lambda=0.01
```

**提早停止（Early stopping）**

作图：随迭代次数 训练误差(递减) 或成本函数 及 交叉验证误差(先减后增)，在表现最好时提前停止，解决过拟合

#### 多元线性回归

多特征回归，即多 **x** 情况，若是存在$x_1,x_2$，则将会回归为一个平面

$x_j^{(i)}$表示：第 **i** 个测试示例中 特征 **j** 的值

**模型描述**

$Y=x_1\theta_1+x_2\theta_2$，已知大量 样本标签$Y$  |  特征$x_1,x_2$  |  权重参数$\theta_1,\theta_2$

拟合平面：$h_\theta(x)=\theta_0+\theta_1x_1+\theta_2x_2$，（$\theta_0$是偏置值，微调平面位置）

补充一列$x_0=1$整合成矩阵形式——多元线性回归：$h_{\theta}(x)=\sum_{i=0}^n\theta_ix_i=\theta^Tx$

**误差项**

误差$\varepsilon$是真实值和预测值间的差异，对于每个样本，真实值=预测值+误差：$y^{(i)}=\theta^Tx^{(i)}+\varepsilon^{(i)}$

**独立同分布**

误差$\varepsilon^{(i)}$是**独立同分布**的，服从均值为0方差为$\theta^2$的**高斯分布/正态分布**

即$p(\varepsilon^{(i)})=\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(\varepsilon^{(i)}-0)^2}{2\sigma^2})$

**似然函数**

消去误差$\varepsilon$得到概率：$p(y^{(i)}|x^{(i)};\theta)=\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(y^{(i)}-\theta^Tx^{(i)})^2}{2\sigma^2})$

- 似然函数：多样本累乘，什么样的参数跟数据组合后恰好为真实值

$L(\theta)=\prod_{i=1}^mp(y^{(i)}|x^{(i)};\theta)$，

- 对数似然，将累乘法转换为加法

$logL(\theta)$

- 化简

$\sum_{i=1}^mlog\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(y^{(i)}-\theta^Tx^{(i)})^2}{2\sigma^2})\\=mlog\frac{1}{\sqrt{2\pi}\sigma}-\frac{1}{\sigma^2}\cdot\frac{1}{2}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$

- 目标：让似然函数越大越好，则使后面项（设为$J(\theta$）越小

$J(\theta)=\frac{1}{2}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$（最小二乘法）

- 求对$\theta$的偏导等于0

$\theta=(X^TX)^{-1}X^Ty$，此处X为行/列向量

**使用梯度下降进行优化迭代**

目标函数：$J(\theta,m)=\frac{1}{2m}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$，求偏导得到梯度方向，下降：向梯度反方向走，是指mini-batch 的大小，一般为2的幂数

- **批量梯度下降BGD**：【易求得最优解，考虑所有样本，速度慢】
  - $\frac{\partial J(\theta)}{\partial\theta_j}=-\frac{1}{m}\sum_{i=1}^m(y^i-h_{\theta}(x^i))x_j^i\quad\quad\quad\theta_j'=\theta_j+\frac{1}{m}\sum_{i=1}^m(y^i-h_{\theta}(x^i))x_j^i$
  - 矩阵表示：$\frac{\partial J(\theta)}{\partial\theta_j}=\frac{2}{m}X^T\cdot(X\cdot\theta-y)$
- **随机梯度下降SGD**：【每次随机找一个样本，迭代快，但不一定朝收敛方向，会在最小值周围徘徊】
  - $\theta_j'=\theta_j+(y^i-h_{\theta}(x^i))x_j^i$
- **小批量梯度下降MBGD(Mini-batch)**：【每次更新选择小部分数据（如10个样本），实用，应对极大数据集】
  - $\theta_j':=\theta_j-\alpha\frac{1}{10}\sum_{k=i}^{i+9}(h_{\theta}(x^{(k)})-y^{(k)})x_j^{(k)}$，$\alpha$为学习率/步长
  - 趋向于全局最小值，每步并非往最好方向，但计算成本低

**特征放缩**

将范围差异较大的不同特征范围调整到大致范围

1. 基础归一化：除以最大值缩小值
2. 均值归一化：**(var - 均值μ)** **/ (max_value - min_value) 转换为范围[-1, 1]** 
3. Z分数归一化(Z-score normalization)：**(var - 均值μ) / 标准差σ 转换为范围[-1, 1]**

#### 多项式回归

- 通过修改**多项式特征**程度的大小，即不同的维度，来拟合不同的数据，拟合曲线
- 如：当有二维样本 a 和 b ，程度degree为2时的多项式特征将为$[1, a, b, a^2, b^2, ab]$，最终拟合后得到各个多项式特征变量前的参数，$y=\theta\cdot 1+\theta_1\cdot a+\theta_2\cdot b+\theta_3\cdot a^2+\theta_4\cdot b^2+\theta_5\cdot ab$

**样本数量对结果影响**

- 训练集大小极小时，测试集均方差高，训练集均方差低
- 随训练集大小增大，两均方差之差减小

![img](/img/ai_note.zh-cn.assets/-172845431716312.assets)

#### 岭回归

- $J(\theta)=MSE(\theta)+\alpha \frac{1}{2}\sum_{i=1}^n\theta_i^2$
- 后一项中对每一个$\theta$量进行平方和计算并相加，以上图为例，1和2计算的结果分别为1和1/4，选择更小的值（即更加平稳的$\theta$），即$\theta_2$进行正则化处理
- 其中$\alpha$用于确定左右式的比重谁大，并且用于调整正则化程度

#### Lasso回归

- $J(\theta)=MSE(\theta)+\alpha \sum_{i=1}^n|\theta_i|$
- 后一项中对每一个$\theta$量绝对值计算并相加

### 分类算法

**有监督**问题

#### 逻辑回归

logistic regression, 经典二元分类算法，逻辑回归的决策边界可以是**非线性**的，预测一个离散型的因变量

**Sigmoid函数：**

- $g(z)=\frac{1}{1+e^{-z}}=P(y=1|x)=\hat y$，**z** 可取任意实数，值域[0, 1]
- 线性回归中得到的预测值，可以映射到Sigmoid函数中完成**值**到**概率**的转换——分类

![img](/img/ai_note.zh-cn.assets/-172845431716313.assets)

**预测函数：**$h_{\theta}(x)=g(\theta^Tx)=\frac{1}{1+e^{-\theta^Tx}}$，其中$z=\theta^Tx=\sum_{i=1}^n\theta_ix_i=\theta_0+\theta_1x_1+\cdots+\theta_nx_n$

**注：**$P(y=1|x;\theta)$**中**$\theta$**表示其为影响该概率的参数**

二分类任务：$\begin{cases}P(y=1|x;\theta)=h_{\theta}(x) \\P(y=0|x;\theta)=1-h_{\theta}(x)\end{cases}$，整合：$P(y|x;\theta)=(h_{\theta}(x))^y(1-h_{\theta}(x))^{1-y}$

对于概率，设定一个阈值a，二分类：**概率大于等于a时，分类为1，当概率小于a时，分类为0**

**决策边界**

- 决策边界是将图形中的所有像素点代入分类器进行划分，假设划分为了0和1两种，则基于等高线划分为0高度和1高度，则可以绘制出决策边界
- 当得到参数$\theta$后，则可以代入到边界绘制函数中，将所有像素点进行预测画出决策边界（使用plt.contour函数）

a为阈值，由$\frac{1}{1+e^{-\theta^Tx}}=a$简化为$\frac{1-a}{a}=e^{-\theta^Tx}$

特殊时，当a=0.5时，上式为$e^{-\theta^Tx}=1=e^0$，即$z=-\theta^Tx=0$，此时为一个决策边界，二维下为直线，多维下为曲线，即等高线

**非线性决策边界**

使用多项式程度（polynomial_degree）来对特征值进行非线性变化

用**多项式线性回归**的式子替代**sigmoid函数**中的 **z** 后通过 **z = 1** 得出决策边界

**代价函数**

平方误差代价函数不适合逻辑回归，会导致梯度下降时有多个局部最低点

定义**损失函数**

$$L(f_{w,b}(x^{(i)}), y^{(i)})=\begin{cases}-log(f_{w,b}(x^{(i)}))\quad y^{(i)}=1\\-log(1-f_{w,b}(x^{(i)}))\quad y^{(i)}=0\end{cases}$$，其中f(x)是sigmoid函数，所以取值[0, 1]

![img](/img/ai_note.zh-cn.assets/-172845431716314.assets)

预测值接近1时，损失最低，越接近0，损失越高

![img](/img/ai_note.zh-cn.assets/-172845431716315.assets)

预测值接近1时，损失越高，越接近0，损失最低

损失函数合并为：$L(f_{w,b}(x^{(i)}), y^{(i)})=-y^{(i)}log(f_{w,b}(x^{(i)}))-(1-y^{(i)})log(1-f_{w,b}(x^{(i)})$

即此时**代价函数**为：$J(w,b)=\frac{1}{m}\sum^m_{i=1}L(f_{w,b}(x^{(i)}), y^{(i)})\\ =-\frac{1}{m}\sum^m_{i=1}[y^{(i)}log(f_{w,b}(x^{(i)}))+(1-y^{(i)})log(1-f_{w,b}(x^{(i)}))]$，**二元分类**

- **似然函数：**$L(\theta)=\prod_{i=1}^mP(y_i|x_i;\theta)=\prod_{i=1}^m(h_{\theta}(x_i))^{y_i}(1-h_{\theta}(x_i))^{1-y_i}$
- **对数似然：**$l(\theta)=logL(\theta)=\sum_{i=1}^m(y_ilogh_{\theta}(x_i)+(1-y_i)log(1-h_{\theta}(x_i)))$
- **梯度上升求最大值**，引入$J(\theta)=-\frac{1}{m}l(\theta$**转换**为**梯度下降任务**
- **求偏导：**$\frac{\partial}{\partial\theta_j}J(\theta)=\cdots=-\frac{1}{m}\sum_{i=1}^m(y_i-g(\theta^Tx_i))x_i^j$
- **参数更新：**$\theta_j':=\theta_j-\alpha\frac{1}{m}\sum_{i=1}^m(h_{\theta}(x_i)-y_i)x_i^j$

**正则化将代价函数变为：**$J(w,b)-\frac{1}{m}\sum^m_{i=1}[y^{(i)}log(f_{w,b}(x^{(i)}))+(1-y^{(i)})log(1-f_{w,b}(x^{(i)}))]+\frac{\lambda}{2m}\sum^n_{j=1}w_j^2$

**多分类逻辑回归**

思路：将多分类转换为**多次二分类**，每次分为2类筛选出其中1类，n分类即进行n次二分类，以概率值进行分类

分类问题的**损失函数：**

损失值可以通过作图观察到随着迭代次数增加，逐渐减小趋于稳定

- 根据$l(\theta)=logL(\theta)=\sum_{i=1}^m(y_ilogh_{\theta}(x_i)+(1-y_i)log(1-h_{\theta}(x_i)))$计算
- 需要借助$f(x)=|logx|$来计算，离1越远损失越大

#### Softmax回归

**多类别分类(multi class classification)**——Logistic回归的推广

**Softmax计算概率：**

$\hat P_k=\sigma(s(x))_k=\frac{exp(s_k(x))}{\sum_{j=1}^Kexp(s_j(x))}$，将不同组的得分值 **s** 进行指数化来使得差异更大

假设**四**个输出：$z_1=w_1\cdot x + b_1\\z_2=w_2\cdot x + b_2\\z_3=w_3\cdot x + b_3\\z_4=w_4\cdot x + b_4$，$a_i=\frac{e^{z_i}}{e^{z_1}+e^{z_2}+e^{z_3}+e^{z_4}}=P(y=i|x)$

**损失函数**

$loss(a_1, \cdots, a_N, y)=\begin{cases}-\log{a_1}\quad if\,y=1\\-\log{a_2}\quad if\,y=2\\\quad\vdots\\-\log{a_N}\quad if\,y=N\end{cases}$，使用-log函数来使得概率越接近 **1 ，**损失函数值越小

**损失函数（交叉熵）：**$J(\theta)=-\frac{1}{m}\sum_{i=1}^m\sum_{k=1}^Ky_k^{(i)}log(\hat p_k^{(i)})$

运用到神经网络：输出层将需要 N 个神经元，以分为 N 个类别，Softmax激活功能使得$a_i$与$z_1 \cdots z_N$所有值相关，区别于logistic回归：$a_i$只与$z_i$有关

**多标签分类(multi label classification)**——输入单图像，判断是否有行人，是否有车，是否有公交，向量[1 0 1]

![img](/img/ai_note.zh-cn.assets/-172845431716316.assets)

#### KNN算法

K-近邻算法：非参数、有监督的分类回归算法，K为奇数

**解决：**给定一个测试数据，若离它最近的**K**个训练数据大多都属于某一类别，则认为该测试数据也属于该类别

**计算流程：**

1. 计算已知类别数据集中点与当前点距离，并排序
2. 选取与当前点距离最小的K个点
3. 确定前K个点所在类别的出现概率
4. 返回出现频率最高的类别作为当前点预测分类

**分析：**

- 无需训练集，计算复杂度与训练集文档数目成正比O(n)
- K值选择、距离度量、分类决策规则是三个基本要素
- 当对图像进行分类时导致以背景为主导了，而主体才应该为主要成分

### 决策树

![img](/img/ai_note.zh-cn.assets/-172845431716317.assets)

- 可以用于**分类**和**回归**，**有监督算法**
- **根结点**（第一个选择点）到**叶子结点**（最终决策结果）
- 训练阶段构造树，测试阶段跟随树走一遍，适用于电子表格/结构化数据，不适用于非结构化数据：图像、音频、文本

**选择决策结点的先后顺序，使用熵的原理，最大化纯度**

**熵**

测量纯度，衡量标准，随机变量不确定性的度量

**公式：各个的概率都要算，i个种类，**$H(X)=-\sum p_i\cdot \log_{2} p_i,\,\,\,i=1,2,\cdots,n$，**log函数使得概率pi越靠近1，值越小**

![img](/img/ai_note.zh-cn.assets/-172845431716318.assets)

当概率为1或0时纯度最高，熵最小

**信息增益原理：**特征值X使得类Y的不确定性减少的程度，熵减

以分类猫狗为例，信息增益：$H(p_1^{root})-(w^{left}H(p_1^{left})+w^{right}H(p_1^{right}))$

```Python
P表示该节点中猫数量占该节点动物数量概率
W表示该节点动物数量占最初节点动物数量概率
```

1. 计算根结点类别的熵值$H'$
2. 计算**所有特征值熵值**：$H(i)=\sum p_j\cdot H(X)$，$p_j$为特征值取各个值时的概率，熵值为特征值各个取值的熵
3. 获得信息增益：$a=H'-H(i)$，取最大值作为第一个决策点
4. 继续计算剩下的熵值依次选取决策点

**离散特征值**：输入样本矩阵中不同类可用0/1编码代替特征

**连续特征值**：离散化，如何取分界点，使用贪婪算法对连续值进行切割二分，然后计算信息增益，选最大值

**GINI系数**

$Gini(p)=\sum^K_{k=1}p_k(1-p_k)=1-\sum_{k=1}^Kp_k^2$，选取GINI系数最小的来构建优先决策节点

![img](/img/ai_note.zh-cn.assets/-172845431716319.assets)

**回归树**

决策树推广为回归算法——预测值：使用最终构建好的叶子结点中训练集数据的平均值预测

选择决策点：

- 将信息增益公式中计算**熵值**更换为计算**决策分裂完的子集中预测数据值的平均方差**
- **根结点最初熵值**换为**原始数据的总方差**

**剪枝策略**

- 决策树**过拟合风险**很**大**
- **预剪枝**：边建立决策树边剪枝，限制深度、叶子结点数、叶子结点样本数、信息增益量等
- **后剪枝**：建立完决策树后剪枝，通过一定衡量标准：$C_{\alpha}(T)=C(T)+\alpha\cdot|T_{leaf}|$，叶子结点个数$T_{leaf}$，C函数：Gini值乘数量
  - 分别计算分裂前和分裂后的损失值，若剪完后损失值减小则进行剪枝

#### ID3

- 信息增益
- ID3倾向于选择取值较多的属性作为节点

**过程：**

输入：训练数据集D，特征集A，阈值$\epsilon$

输出：决策树T

**（1）**若 D 中所有实例都属于同一个类 $C_k$ ，则 T 为单节点树，将 $C_k$ 作为该节点的类标记，返回 T

**（2）**若 A=∅ ，则 T 为单节点树，并将 D 中的实例数最大的类 $C_k$ 作为该节点的类标记，返回 T

**（3）**否则，**计算特征 A 对数据集 D 的信息增益，选择信息增益最大的特征** $A_g$

**（4）**如果 $A_g$ 的信息增益小于阈值 $\epsilon$ ，则置 T 为单节点树，并将 D 中实例数最大的类 $C_k$ 作为该节点的类标记，返回 T【剪枝】

**（5）否则，对** $A_g$ **的每一可能值** $a_i$ **依** $A_g=a_i$ **将 D 划分为若干非空子集** $D_i$ **，将** $D_i$ **中实例数最大的类作为标记，构建子节点**，由节点及其子节点构成树 T ，返回 T

![img](/img/ai_note.zh-cn.assets/-172845431716320.assets)

**（6）**对第 i 个子节点，以 $D_i$ 为训练集，以 $A-\{A_g\}$ 为特征集，递归调用 (1)~(5) ，得到子树 T ，返回 T

#### C4.5

- 举例：当有一行特征为ID编号，从0~K，将会导致ID的熵为0，而ID并不与结果相关，即信息增益不适合解决特征中及其稀疏的情况
- 解决ID3问题，考虑自身熵，使用**信息增益率=信息增益/属性熵**
- 当属性有很多值时，虽然信息增益变大，但相应属性熵也会变大，所以信息增益率计算不会很大

#### CART

使用**GINI系数**作为衡量标准

#### 集成学习

**分类**

- **Bagging：并联，**训练多个分类器取平均，$f(x)=\frac{1}{M}\sum_{m=1}^Mf_m(x)$

![img](/img/ai_note.zh-cn.assets/-172845431716321.assets)

- **Boosting：串联，**从弱学习器开始加强，通过**加权**来训练，大部分情况下，**经过 boosting 得到的结果偏差（bias）更小，**$F_m(x)=F_{m-1}(x)+argmin_h\sum_{i=1}^nL(y_i,F_{m-1}(x_i)+h(x_i))$

![img](/img/ai_note.zh-cn.assets/-172845431716422.assets)

- **Stacking：堆叠，**聚合多个分类或回归模型（KNN, SVM, RF），第一阶段得出各自结果，第二阶段用前一阶段结果训练

![img](/img/ai_note.zh-cn.assets/-172845431716423.assets)

#### 随机森林

- RF，由于决策树对数据轻微变化敏感
- 属于Bagging模型
- 随机：
  - **数据随机采样：**原始数据中进行放回抽样（取得值可能重复），构造新的训练集
  - **特征选择随机：**每个节点，选择随机子集k(<n, or $k=\sqrt n$)个特征
  - **分别训练多个相同参数的模型，预测时将所有模型结果再进行集成**
- 森林：多个决策树并行放一起

![img](/img/ai_note.zh-cn.assets/-172845431716424.assets)

能处理高维，可解释性强，并行化速度快，能给出哪些特征值重要

**投票策略**

- 软投票：各自分类器的概率值进行加权平均，要求各个分类器都有概率值
- 硬投票：直接用类别值，少数服从多数

**OOB策略**

**Out of Bag**，在随机抽取的样本中，剩余的样本可以作为验证集进行验证

**XGBoost**

- eXtreme Gradient Boosting，极端梯度提升，属于boosting模型
- 在下一轮时，随机抽样更大概率选择前一轮预测出错的样本，每个样本都有权重

```Python
from xgboost import XGBClassifier, XGBRegressor # 分类，回归

model = XGBClassifier() # XGBRegressor()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
```

**AdaBoost**

- 属于boosting模型
- 每一轮训练都提升那些错误率小的基础模型权重，同时减小错误率高的模型权重
- 每一轮改变训练数据的权值或概率分布，通过提高那些在前一轮被弱分类器分错样例的权值，减小前一轮分对样例的权值

**Gradient Boosting**

- 串行地生成多个弱学习器，每个弱学习器的目标是拟合先前累加模型的损失函数的负梯度
- 使加上该弱学习器后的累积模型损失往负梯度的方向减少
- 且用不同的权重将基学习器进行线性组合，使表现优秀的学习器得到重用

**提前停止策略**

在验证误差不再提升后，提前结束训练而不是一直等待验证误差到最小值

### 聚类算法

**无监督**问题：不存在标签，将相似的东西分到一组

#### K-MEANS

**概念**

- 需指明簇的个数**K**
- 质心：均值，向量各维取平均
- 距离：用**欧几里得距离**和**余弦相似度**（先标准化）
- **优化目标**：$min\sum_{i=1}^K\sum_{x\in C_i}dist(c_i,x)^2$
- **代价函数/失真函数：**$J(c^{(1)},\cdots,c^{(m)},\mu_1,\cdots,\mu_K)=\frac{1}{m}\sum_{i=1}^m||x^{(i)}-\mu_{c^{(i)}}||^2$
- 应用举例：x轴身高，y轴体重，离散点类似线性增加，可用于分类小中大三个簇，K越多，分类越细

**工作过程**

![img](/img/ai_note.zh-cn.assets/-172845431716425.assets)

- 优势：简单，快速，适合常规数据集
- 劣势：难确定K，复杂度与样本呈线性关系，难发现形状复杂的簇，初始化不当会导致陷入局部最优值

Elbow method-肘法：x轴K的值，y轴代价函数值，看图像是否有斜率突变的情况

![img](/img/ai_note.zh-cn.assets/-172845431716426.assets)

**评估指标**

**Inertia指标**

- 定义：**每个样本到质心的距离**
- 可用于**取合适K值（簇的个数）**
- 随K增大，Inertia指标一定下降，找指标下降过程中**拐点处**的K值【此处拐点指前后的变化率浮动大】
- 仅供选择，不一定最准确

**轮廓系数**

- **簇内不相似度**$a_i$：样本i到同簇其他样本的平均距离
- **簇间不相似度**$b_i$：计算样本i到其他簇Cj的所有样本的平均距离$b_{ij}$，$b_i=min\{b_{i1},b_{i2},\cdots,b_{ik}\}$

想让$a_i$越小，$b_i$越大，则有：

$s(i)=\frac{b(i)-a(i)}{max\{a(i),b(i)\}}=\begin{cases}1-\frac{a(i)}{b(i)},\quad a(i)\lt b(i)\\\\0,\,\,\,\,\quad\quad\quad a(i)=b(i)\\\\\frac{b(i)}{a(i)}-1,\quad a(i)\gt b(i)\end{cases}$

**结论：**

- $s_i$接近1，说明样本i聚类合理
- $s_i$接近-1，说明样本i更应该分类到其他簇
- $s_i$近似0，说明样本i在2个簇边界上

#### DBSCAN

（Density-Based Spatial Clustering of Applications with Noise）

**基本概念**

- **核心点**：某个点的**密度**达到算法设定的阈值 —— r邻域内点的数量≥ 阈值 **minPts**
- $\epsilon$-邻域的距离阈值：设定的半径 **r**
- **直接密度可达：若点 p 在点 q 的 r邻域内，且 q 是核心点，则 p-q 直接密度可达**
- 密度可达：一个点的序列$q_0,q_1,\cdots,q_l$，对任意$q_i-q_{i-1}$是直接密度可达的，则称从$q_0$到$q_k$密度可达，“传播”
- **边界点**：每一个类的非核心点
- **噪声点**：不属于任何一个类簇的点，从任何一个核心点出发都密度不可达
- K-距离：给定数据集$P=\{p(i);\,i=0,1,\cdots,n\}$，p(i)到P中其他点的距离并且从小到大排序，分别为d(k)，k=1,2,3,....，称为K-距离

![img](/img/ai_note.zh-cn.assets/-172845431716427.assets)

**工作流程**

输入：**数据集**$D$、**指定半径**$\epsilon$、**密度阈值**$MinPts$

1. 所有对象标记 unvisited
2. 随机选择一个对象p，标记为visited
3. 若 p 的$\epsilon$-邻域至少有 MinPts 个对象[a, b, c, d...]：创建新簇 C，p 加入 C 中
4. 令 N 为 p 的$\epsilon$-邻域中的对象集合，遍历[a, b, c, d...]中每个点 p' 【不断扩张的过程】：
   1. 若 p' 为unvisited，标记为visited；
   2. 若 p' 的$\epsilon$-邻域至少有 MinPts 个对象，将这些对象加入N
   3. 若 p' 不是任何簇的成员，加入 C 中
5. 输出C**（若不满足3条件，则为噪声点）**
6. 接着继续找标记为unvisited的对象，重复3-5
7. 直到没有标记为unvisited的对象

**参数选择：**

- 选择半径$\epsilon$：根据K-距离找突变的点
- 选择 MinPrs：K-距离中的 k 值，一般取小一点

优点：擅长找离群点，可分任意形状

劣势：高维数据困难，参数难以选择，效率低

### 异常检测

- Anomaly Detection，非线性检测，无监督学习
- 数据集：$\{x^{(1)},x^{(2)},\cdots,x^{(m)}\}$，每个$x_i$有 m 个特征$x=[x_1,x_2,\cdots,x_n]$，检测$x_{test}$，以二维即2个特征为例，x轴为x1，y轴为x2，可作图观察点分布

**密度估计**：越内部概率越高，越外圈概率越低，计算$x_{test}$概率

![img](/img/ai_note.zh-cn.assets/-172845431716428.assets)

**高斯/正态分布**

$p(x)=\frac{1}{\sqrt{2\pi}\sigma}e^{\frac{-(x-\mu)^2}{2\sigma^2}}$，轴线与$\mu$有关，宽度与$\sigma$有关

![img](/img/ai_note.zh-cn.assets/-172845431716429.assets)

**算法实现**

1. 选择n个特征的$x_i$
2. 通过数据集计算：$\mu_j=\frac{1}{m}\sum_{i=1}^mx_j^{(i)}$和$\sigma_j^2=\frac{1}{m}\sum(x_j^{(i)}-\mu_j)^2$
3. 给定待测试 x ，计算$p(x)=\prod_{j=1}^np(x_j;\mu_j,\sigma^2_j)=\prod_{j=1}^n\frac{1}{\sqrt{2\pi}\sigma_j}e^{\frac{-(x_j-\mu_j)^2}{2\sigma_j^2}}$，$p(x)\lt \varepsilon$则异常e

**评估方法**

加入标签0正常1异常，分为训练集、交叉验证集、测试集，训练集只测试正常数据；交叉验证集加入少许异常数据预测01，混淆矩阵评估来调整参数及$\varepsilon$；测试集也有少许异常数据测试来公平判断系统

与有监督的区别：异常检测中的异常不断变化可能与训练集中不一致，有监督学习区别的垃圾邮件大多与训练集中相似

**特征选择**

- 非高斯特征可通过计算转化为高斯性质：$log(x+c)$，$x^{\frac{1}{c}}$，特征图的x轴为索引，y轴为特征的值
- 添加特征可以使用原有特征的比率来使得更容易进行异常检测

### 推荐系统

a-d四个人对m1-m5电影评分数据

| Movie | a    | b    | c    | d    | x1(浪漫电影) | x2(动作电影) |
| ----- | ---- | ---- | ---- | ---- | ------------ | ------------ |
| m1    | 5    | 5    | 0    | 0    | 0.9          | 0            |
| m2    | 5    | ?    | ?    | 0    | 1.0          | 0.01         |
| m3    | ?    | 4    | 0    | ?    | 0.99         | 0            |
| m4    | 0    | 0    | 5    | 4    | 0.1          | 1.0          |
| m5    | 0    | 0    | 5    | ?    | 0            | 0.9          |

- $n_u$人数，$n_m$电影数，$r(i,j)=1/0$用户 j 是否给电影 i 打分，$y^{(i,j)}$用户 j 对 i 的打分值，$w^{(j)},b^{(j)}$用户 j 的参数，$x^{(i)}$电影 i 的特征向量
- 对 a(j) 预测第 3(i) 个电影：假设已得出了 w 和 b $w^{(j)}\cdot x^{(i)}+b^{(j)}=[5\quad 0]\cdot \begin{bmatrix}0.99\\0\end{bmatrix}+0=4.95$

**成本函数**

对单个用户 j

![img](/img/ai_note.zh-cn.assets/-172845431716430.assets)

对所有用户

![img](/img/ai_note.zh-cn.assets/-172845431716431.assets)

假设已知参数w和b，x1和x2特征值未知，可以通过成本函数推测特征值

![img](/img/ai_note.zh-cn.assets/-172845431716432.assets)

![img](/img/ai_note.zh-cn.assets/-172845431716433.assets)

#### **协同过滤**

- Collaborative filtering，基于部分用户已打分情况推荐相似电影
- **多个用户合作评价同一部电影，可以猜测什么是适合该电影的功能，以及猜测尚未评价同一部电影的用户如何评价**

上述成本函数结合：

![img](/img/ai_note.zh-cn.assets/-172845431716434.assets)

**梯度下降**变化

- $w_i^{(j)}=w_i^{(j)}-\alpha\frac{\partial}{\partial w_i^{(j)}}J(w,b,x)$
- $b^{(j)}=b^{(j)}-\alpha\frac{\partial}{\partial b^{(j)}}J(w,b,x)$
- $x_k^{(i)}=x_k^{(i)}-\alpha\frac{\partial}{\partial x_k^{(i)}}J(w,b,x)$，x也为参数

协同过滤算法可以通过逻辑回归运用到二进制标签应用

**均值归一化**

将评分都减去均值$\mu$，获取新的评分矩阵

对于用户 j，对于电影 i 预测：$w^{(j)}\cdot x^{(i)}+b^{(j)}+\mu_i$，对于新用户，此时参数均为0，则预测的值为均值而不是0，更合理

线性回归的梯度下降 使用自动求导( **Auto Diff** )实现

```Python
w = tf.Variable(3) # 优化参数变量 w 初始化为3

for iter in range(iterations):
    with tf.GradientTape() as tape:
        # 计算成本函数，tf将操作序列保存在tape中
    [dJdw] = tape.gradient(costJ, [w]) # tf自动计算导数
    w.assign_add(-alpha * dJdw) # tf 需要函数更新
```

**TensorFlow实现**

```Python
optimizer = keras.optimizers.Adam(learning_rate=0.1)
for iter in range(iterations):
    with tf.GradientTape() as tape:
        cost = cofiCostFuncV(X, W, b, Ynorm, R, num_users, num_movies, lambda)
        # 参数：训练数据, 参数, 参数, 均值归一化后的目标值, 是否对电影评分的二进制标签数据, 用户数量, 电影数量, 正则化参数
    grads = tape.gradient(cost, [X, W, b])
    optimizer.apply_gradients(zip(grads, [X,W,b]))
```

寻找**相关项：寻找**$x^{(k)}$相似于$x^{(i)}$，求$\sum_{l=1}^n(x_l^{(k)}-x_l^{(i)})^2$

**限制**：冷启动问题——新项很少用户点评

#### 内容过滤

- Content-based Filtering，基于用户和项的特征寻找合适匹配推荐
- 用户 j 特征$X_u^{(j)}$，电影 i 特征$X_m^{(i)}$，两个向量包含的**评分数字**可能不同，看是否 i 和 j 能匹配
- 预测 j 对 i 的评分由 wx+b 更改为 $V_u^{(j)}\cdot V_m^{(i)}$，分别从$X_u^{(j)}$和$X_m^{(i)}$计算得来，且包含评分数字相同

**神经网络架构**

![img](/img/ai_note.zh-cn.assets/-172845431716435.assets)

$g(V_u^{(j)}\cdot V_m^{(i)})$预测用户 j 对电影 i 即$y^{(i,j)}=1$的概率

- 32位向量$v_u^{(j)}$描述用户 j 的特征$x_u^{(j)}$
- 32位向量$v_m^{(i)}$描述电影 i 的特征$x_m^{(i)}$

**成本函数**

![img](/img/ai_note.zh-cn.assets/-172845431716536.assets)

推荐类似 i 的电影：$small\,\,||V_m^{(k)}-V_m^{(i)}||^2$

大数据集高效推荐：检索（Retrieval），排名（Ranking）

**检索：**生成大量合理项目候选并去除重复项

**排名：**将候选使用上述神经网络框架预测分数并排名

```Python
# 已构建了user_NN, item_NN
input_user = tf.keras.layers.Input(shape=(num_user_features)) # 定义输入层
vu = user_NN(input_user)
vu = tf.linalg.l2_normalize(vu, axis=1) # L2范数标准化 同理得到vm

output = tf.keras.layers.Dot(axes=1)([vu, vm]) # 点积层，计算输入向量点积
model = Model([input_user, input_item], output) # 定义keras模型
cost = tf.keras.losses.MeanSquaredError()
```

### SVM算法

- Support Vector Machine, **支持向量机**算法，**有监督**算法，解决经典二分类问题
- 解决：选取最好的决策边界；特征数据本身难分
- 选出离边界点最远的

![img](/img/ai_note.zh-cn.assets/-172845431716537.assets)

**公式推导**

计算**距离**：

![img](/img/ai_note.zh-cn.assets/-172845431716538.assets)

**数据标签**定义：

- 数据集：$(X_1,Y_1),(X_2,Y_2),\cdots,(X_n,Y_n)$
  - Y为样本类别，X为正例Y=+1；X为负例Y=-1
- **决策方程：**$y(x)=w^T\Phi(x)+b$，$\Phi(x)$对数据做了变换
  - $\begin{cases}y(x_i)\gt 0\Leftrightarrow y_i=+1\\y(x_i)\lt 0\Leftrightarrow y_i=-1\end{cases}\quad\Rightarrow\quad y_i\cdot y(x_i)\gt 0$

**优化目标：**

1. **点到直线的距离**化简**：**$\frac{y_i\cdot(w^T\cdot \Phi(x_i)+b)}{||w||}$
2. 目标：找到一条线（w和b），使得离该线最近的点能够最远，$\mathop{arg\,max}\limits_{w,b} \{\frac{1}{||w||}\mathop{min}\limits_{i}[y_i\cdot(w^T\cdot\Phi(x_i)+b]\}$
3. 对式子放缩变换，使得$y_i\cdot(w^T\cdot \Phi(x_i)+b)\ge 1$【约束条件】，则对上式中，由于其中的min函数中的项大于等于1，则只需要考虑**目标函数** $\mathop{arg\,max}\limits_{w,b} \frac{1}{||w||}$
4. 将**求解最大值**转换为**求解最小值**：$max_{w,b}\frac{1}{||w||} \quad\Longrightarrow \quad min_{w,b}\frac{1}{2}w^2$，并用**拉格朗日乘子法**求解
5. 其中拉格朗日乘子法：待约束的优化问题：
   1. $\mathop{min}\limits_xf_0(x)$
   2. $subject\quad to\quad f_i(x)\le 0,\,i=1,\cdots,m;\quad h_i(x)=0,\,i=1,\cdots,q$
   3. 原式转换：$min\,\,L(x,\lambda,v)=f_0(x)+\sum_{i=1}^m\lambda_if_i(x)+\sum_{i=1}^qv_ih_i(x)$
6. 式子化为：$L(w,b,\alpha)=\frac{1}{2}||w||^2-\sum_{i=1}^n\alpha_i(y_i(w^T\cdot \Phi(x_i)+b)-1)$
7. 对w、b求导：
   1. $\frac{\partial L}{\partial w}=0\Rightarrow w=\sum_{i=1}^n\alpha_iy_i\Phi(x_n)$代入L函数
   2. $\frac{\partial L}{\partial b}=0\Rightarrow 0=\sum_{i=1}^n\alpha_iy_i$代入L函数得：
   3. $L(w,b,\alpha)=\sum_{i=1}^n\alpha_i-\frac{1}{2}\sum_{i=1,j=1}^n\alpha_i\alpha_jy_iy_j\Phi^T(x_i)\Phi(x_j)$
8. 对$\alpha$求极大值转换为求极小值：$\mathop{min}\limits_{\alpha}\frac{1}{2}\sum_{i=1}^n\sum_{j=1}^n\alpha_i\alpha_jy_iy_j(\Phi(x_i)\cdot\Phi(x_j))-\sum_{i=1}^n\alpha_i$，条件：$\sum_{i=1}^n\alpha_iy_i=0$和$\alpha_i\ge 0$
9. 实例将x和y代入获得关于$\alpha_i$的等式，然后对各个$\alpha_i$求偏导为0得到$\alpha_i$的值代入可求得w,b，$w=\sum_{i=1}^n\alpha_iy_i\Phi(x_n)$，$b=y_i-\sum_{i=1}^na_iy_i(x_ix_j)$

**调整参数**

**软间隔——soft-margin**

有时候数据中存在噪音点，对其进行考虑时会对决策线产生影响，需要要求放松一点，引入松弛因子$\xi_i$有：$y_i(w\cdot x_i+b)\ge 1-\xi_i$

则新的目标函数：$min\frac{1}{2}||w||^2+C\sum_{i=1}^n\xi_i$，使得函数越小

- **C** 很大时，意味分类严格；很小时，意味有更大错误容忍

**核函数**

即$\Phi(x$，将低维中决策边界可能复杂过饱和的情况变换为高维中更简单决策边界的情况

![img](/img/ai_note.zh-cn.assets/-172845431716539.assets)

高斯核函数：$K(X,Y)=exp\{-\frac{||X-Y||^2}{2\sigma^2}\}$

![img](/img/ai_note.zh-cn.assets/-172845431716540.assets)

### 朴素贝叶斯

贝叶斯公式：$P(A|B)=\frac{P(B|A)P(A)}{P(B)}$

#### 邮件过滤

- 判定邮件D是否为垃圾邮件，h+表示垃圾邮件，h-表示正常邮件

$\begin{cases}P(h+|D)=\frac{P(h+)P(D|h+)}{P(D)}\\P(h-|D)=\frac{P(h-)P(D|h-)}{P(D)}\end{cases}$，P(h+)和P(h-)为先验概率

- D由N个单词组成，所以有$P(D|h+)=P(d_1,d_2,\cdots,d_n|h+)=P(d_1|h+)\cdot P(d_2|d_1,h+)\cdot P(d_3|d_2,d_1,h+)\cdots$
- 朴素贝叶斯假设特征之间是独立的，则化简为$P(d_1|h+)\cdot P(d_2|h+)\cdot P(d_3|h+)\cdots$，则只要统计$d_i$这个单词在垃圾邮件中出现的概率即可

### 数据降维

#### PCA算法

## 强化学习

**奖励函数（reward function）**

奖励(reward)：R，通过奖励好行为和惩罚坏行为使自动学习，核心要素：(s_start, action, reward(s_start), s_change)

**回报 （return）**

折扣因子(discount factor)$\gamma=0.9$：奖励随动作增加减少

$return=R_1 \cdot (\gamma) + R_2 \cdot (\gamma)^2 + \cdots + R_n\cdot (\gamma)^n$

**策略函数(policy)**

强化学习需要找到策略函数：$\pi(s)=a$来最大化回报

![img](/img/ai_note.zh-cn.assets/-172845431716541.assets)

**马尔科夫决策过程**：Markov Decision Process(MDP)

未来只取决于现在状态

**状态-动作价值函数（State-action value function, Q function or optimal Q function or Q\*）**

$\max_a Q(s, a)$得到从状态 s 经过动作 a 后最佳表现的回报

**贝尔曼方程(Bellman Equation)**

- s：当前状态，R(s)：当前状态的奖励，a：当前动作，s'：a动作后的状态，a'：s'状态时采取的动作
- $Q(s,a)=R(s)+\gamma \max_{a'}Q(s',a')=R_1+\gamma R_2 +\gamma^2 R_3 +\cdots= R_1+\gamma[R_2+\gamma R_3 +\cdots]$

**随机环境（Stochastic Environment）**

当出现随机情况，即下一个状态可能未实现，则更关注的是最大化多次运动下的**期望回报**

- $Expected\,\,Return = Average(R_1+\gamma R_2+\gamma^2 R_3 +\cdots)=E[R_1+\gamma R_2+\gamma^2 R_3 +\cdots]$
- $Q(s,a)=R(s)+\gamma E[\max_{a'}Q(s',a')]$

**连续状态空间**

每个状态不是离散的，通过向量表示：$s=[x\,\,y\,\,\theta\,\,x'\,\,y'\,\,\theta']$可分别表示位置，方向，速度，角度等

**深度强化学习-学习状态值函数**

使用神经网络去预测Q函数，选择最大化 Q(s,a) 的动作 a 

![img](/img/ai_note.zh-cn.assets/-172845431716542.assets)

**ε-贪婪策略**

- **0.95概率选择最大化 Q(s,a) 的动作 a：exploitation**
- **0.05概率选择随机的动作 a (ε=0.05, 逐渐减小 ε )：exploration**

**软更新**

当使用小批量梯度下降时，更新 Q 的参数 w 及 b 时：$w=0.01w_{new}+0.99w\quad b=0.01b_{new}+0.99b$

## 深度学习

- 机器学习过程：数据获取、【**特征工程】**、建立模型、评估应用
- 特征工程：数据特征决定模型上限，算法和参数用于接近上限
- 主：**计算机视觉**
- **图像识别：**将图片1000x1000像素展开为一个向量数组作为输入

### 神经网络

**整体框架**

![img](/img/ai_note.zh-cn.assets/-172845431716543.assets)

- 堆叠：$f=W_3max(0,W_2max(0,W_1x))$，参数极多 
- 神经元个数影响：神经元多，分类效果好
- 参数个数影响：参数多，拟合高
- 极大神经网络在适当正则化下不损害性能，拥有低偏差：惩罚力度小，拟合高；惩罚力度大，平稳
- 停滞区（plateaus）使学习过程慢

**参数随机初始化**

```Python
w[1] = np.random.randn((2, 2)) * 0.01 
# [1]表示第一层 初始化 w 不能只设为 0, 否则会使得多个神经元工作对称一致 0.01使得学习速度更快
b[1] = np.zeros((2, 1))
# b 不会由于初始值为 0 产生对称问题/对称失效问题
```

**隐藏层工作**

![img](/img/ai_note.zh-cn.assets/-172845431716544.assets)

**层类型**

密集层（Dense Layer）

上一层的输出经过激活函数，得到该层每个神经元输出

卷积层（Convolutional Layer）

该层每个神经元只关注上一层输入的一部分，例如图像中抽取任意个像素块，可以相互重叠

计算快，更少训练集，不易过拟合

使用TensorFlow构建神经网络模式

```Python
model = Sequential([Dense(units = 153, activation = 'sigmoid'), # 全连接层 layer1
                    Dense(units = 21, activation = 'sigmoid')]) # layer2
# activation: linear, relu, sigmoid, softmax

x = np.array([xx, xx], [xx, xx]])
y = np.array([xx, xx])

model.compile(loss=BinaryCrossentropy()) # 损失函数
# BinaryCrossentropy 适用于二元分类0或1: 逻辑回归 二元交叉熵函数
# MeanSquaredError 适用于回归: 预测数值 
# SparseCategoricalCrossentropy  适用于SoftMax多分类 稀疏范畴交叉熵函数 得到N个值中的一个值

model.fit(x, y, epochs=100) # fit:实现反向传播  epochs: 梯度下降/迭代次数

model.predict(x_new)
```

SoftMax / Sigmoid中：

```Python
# 前面的Dense最后一层activation使用'linear'输出中间值
model.compile(loss=SparseCategoricalCrossentropy(from_logits=True))
# 损失值不标准化为概率, 使得数字更准确, SoftMax操作交给TensorFlow的损失函数计算

# 预测
logits = model(X) # SoftMax输出z1-zN, 即非概率   Sigmoid输出z, 非概率
f_x = tf.nn.softmax(logits) # tf.nn.sigmoid(logits) 将中间值单独调用函数转为概率
```

**线性函数**

- 输入到输出的映射：图片（32x32x3）经$f(x, W)=Wx+b$得到每个分类的得分，x为图片，W为权重参数，b为偏置参数
- 其中，共分N个类别，则W=Nx32x32x3=Nx3072，x=32x32x3x1=3072x1，两者矩阵相乘得到 Nx1 的不同类别的得分，b为Nx1，进行微调

**损失函数** 

- 举例一个损失函数$L_i=\sum_{j\ne y_i}max(0,s_j-s_{y_i}+1)$，$s_j$是错误的，$s_{y_i}$是正确的
- 再加入正则化惩罚项防止过拟合：$L=\frac{1}{N}\sum_{i=1}^N\sum_{j\ne y_i}max(0,f(x_i;W)_j-f(x_i;W)_{y_i}+1)+\lambda R(W)$，其中$R(W)=\sum_k\sum_lW^2_{k,l}$

### 深度神经网络

- $n^{[l]}$表示第 l 层的神经元数 ，$a^{[l]}$表示第 l 层的激活函数
- $w^{[l]}$表示第 l 层中间值的权重，$b^{[l]}$表示第 l 层中间值的偏置值
- $z=g(a), \quad a=w\cdot x+b$
- $Z^{[l]}, A^{[l]},dZ^{[l]}, dA^{[l]}$矩阵: $(n^{[l]}, m)$，m为训练集数量

**超参数(Hyperparameters)**

学习率、动量值、mini-batch大小、迭代次数、隐藏层数、神经元数、激活函数选择、衰减率

### **激活函数**

模型输出的**原始值**转换为**概率分布**

- 线性激活函数：$g(z)=z$
  - 全为线性激活函数使得神经网络等价于线性回归模型
  - 隐藏层均为线性激活函数而输出层为sigmoid函数使得神经网络等价于逻辑回归模型
- 非线性变化：Sigmoid，Relu，tanh等

神经网络主要使用 **Relu函数 (Rectified Linerar Unite：线性整流函数，非二元, 更快)** 而不使用Sigmoid函数，Sigmoid函数会出现梯度消失现象( 两端平坦, 导致梯度下降慢, Relu只有一端平坦 )

**Relu函数：**$\sigma(x)=max(0,x)$

![img](/img/ai_note.zh-cn.assets/-172845431716545.assets)

**Leaky ReLU函数：**$\sigma(x)=\begin{cases}x\,\,,x\gt 0\\\alpha x\,\,,x\le 0\end{cases}$

![img](/img/ai_note.zh-cn.assets/-172845431716546.assets)

**tanh函数：**$\sigma(x)=tanh(x)=\frac{e^x-e^{-x}}{e^x+e^{-x}}$，具有居中数据效果

![img](/img/ai_note.zh-cn.assets/-172845431716547.assets)

**神经网络-激活函数选择**

- 输出层：线性: y=+/-  |  Sigmoid: y=0/1  |  Relu: y=0/+
- 隐藏层：默认选择Relu

**Frobenius norm 正则化**：$||\cdot||_F^2$

$\frac{\lambda}{2m}\sum_{l=1}^L||w^{[l]}||^2_F=\sum_{i=1}^{n^{[l-1]}}\sum_{j=1}^{n^{[l]}}(w_{ij}^{[l]})^2$

反向传播中：$dw^{[l]}=(from backprop) + \frac{\lambda}{m}w^{[l]}$

**DROP-OUT 正则化** 

随机抽取一些神经元训练，解决过拟合，以某一概率选择

![img](/img/ai_note.zh-cn.assets/-172845431716648.assets)

**反向随机失活（Inverted dropout）**

不依赖任何一个特征，所以权重将会更扩散

```Python
# dl: 布尔矩阵 
dl = np.random.rand(al.shape[0], al.shape[1]) < keep-prob # keep-prob为留存概率值 0.8
al = np.myltiply(al, dl) # 可能有20%的将会为false
al /= keep-prob
```

**归一化输入**

对训练集和测试集使用归一化，使用同样的均值及方差：

- 计算均值，每个值减去$\mu$，将均值$\mu$变为0
- 方差归一化，计算方差，每个样本除以$\sigma^2$，将方差变为1

深层网络——**梯度消失/爆炸**

- 当权重 w 只比 1 或单位矩阵大一点，激活函数/梯度将会随 L 层指数级增长到爆炸
- 当权重 w 比 1 小一点，激活函数/梯度将会指数级减少到消失

**权值初始化**减轻梯度消失/爆炸

- Xavier初始化：Tanh 对随机生成的 w 参数$\cdot \sqrt\frac{1}{n^{[l]}}$，n 为特征/神经元数，l 为层数
- ReLu函数则$\cdot \sqrt\frac{2}{n^{[l]}}$

**批量归一化(Batch Norm)**

隐藏层归一化，对隐藏单元的$z_{norm}^{(i)}=\frac{z^{(i)}-\mu}{\sqrt{\sigma^2+\varepsilon}}$及$\tilde z^{(i)}=\gamma\cdot z_{norm}^{(i)}+\beta$归一化再输入激活函数，$\gamma, \beta$参数可由梯度下降调整

### **前向传播**

输入到输出，从左往右，神经元数逐层减少，计算**激活值**及**成本**

使用指数函数扩大差异，再取平均值归一化：$P(Y=k|X=x_i)=\frac{e^{s_k}}{\sum_je^{s_j}}$，其中$s=f(x_i;W)$

计算损失值：$L_i=-logP(Y=y_i|X=x_i)$，P越接近1，log后越小

![img](/img/ai_note.zh-cn.assets/-172845431716649.assets)

![img](/img/ai_note.zh-cn.assets/-172845431716650.assets)

### 反向传播

**梯度下降** 链式法则：梯度一步步传播，参考偏导来计算 J 关于 w 和 b 参数的**导数，反向的时候需要：正向时的每个中间结点的值都存储在中间结点**

![img](/img/ai_note.zh-cn.assets/-172845431716651.assets)

例子：

![img](/img/ai_note.zh-cn.assets/-172845431716652.assets)

![img](/img/ai_note.zh-cn.assets/-172845431716653.assets)

**逻辑回归反向传播过程**

![img](/img/ai_note.zh-cn.assets/-172845431716654.assets)

【调试】梯度检查：J 函数中的 $\theta$是向量中某个$\theta_i$

计算$d\theta_{approx}=\frac{J(\theta+\varepsilon)-J(\theta-\varepsilon)}{2\varepsilon}$，计算标准化后欧几里得距离$\frac{||d\theta_{approx}-d\theta||_2}{||d\theta_{approx}||_2+||d\theta||_2}$与$\varepsilon=10^{-7}$比较

**指数加权滑动平均**

有大体趋势的多噪声散点图使用：$V_t = \beta V_{t-1} + (1-\beta \theta_t)$做出平滑曲线，相当于取$\frac{1}{1-\beta}$天的平均值

**偏差纠正**

解决初期**指数加权平均**的值与真实值相差过大，使用$\frac{V_t}{1-\beta^t}$

**反向传播门单元：**

- 加法门单元：均等分配
- MAX门单元：给最大的
- 乘法门单元：互换

![img](/img/ai_note.zh-cn.assets/-172845431716655.assets)

## 计算机视觉

**垂直边缘检测——灰度图**

![img](/img/ai_note.zh-cn.assets/-172845431716656.assets)

**N x N \* f x f = ( N - f + 1 ) \* ( N - f + 1)**，f 基本为奇数

![img](/img/ai_note.zh-cn.assets/-172845431716657.assets)

Sobel过滤器：1,2,1

Scharr过滤器：3,10,3

**padding填充**

- p=1时在矩阵外围填充一圈0
- (**N + 2p) x (N + 2p) \* f x f = ( N + 2p - f + 1 ) \* ( N + 2p - f + 1)**

Valid卷积：不进行填充；Same卷积：进行填充使卷积运算后矩阵大小保持不变

**stride步长**

- 过滤器每次计算后向上向下移动到新位置的长度均为步长，步长越大使得卷积结果矩阵大小越小,s=2时移动2格
- 输出：$( \lfloor\frac{N + 2p - f}{s} + 1 \rfloor) * ( \lfloor\frac{N + 2p - f}{s} + 1\rfloor)$

**1x1卷积**

28*28*192的输入，若要减少通道数，使用32个1*1*192的滤波器卷积，输出28*28*32大小的立方体

**三维卷积**

**通道=深度**

![img](/img/ai_note.zh-cn.assets/-172845431716658.assets)

### 卷积神经网络

常用于图像数据处理

**一层架构**

2个过滤器即2个特征

![img](/img/ai_note.zh-cn.assets/-172845431716659.assets)

多层架构：经过多个卷积核，最终展开输入Softmax单元或Logistic回归

**参数**

10个3x3x3过滤器，加入10个偏置值，一共10x(3x3x3+1)=280参数，不易过拟合

**层类型**

1. 卷积层（Convolution, CONV）
2. 池化层（Pooling, POOL）：减少展示数量

**最大池化层(max pooling)**

最大值采样：f=2，输出对应区域**最大值，若在滤波器中任何地方检测到了特征，保留最大值**

![img](/img/ai_note.zh-cn.assets/-172845431716660.assets)

**平均池化层(average pooling)**

均值采样：f=2

![img](/img/ai_note.zh-cn.assets/-172845431716661.assets)

**池化层没有需要学习的参数，只需设置过滤器大小f，步长s**

1. 全连接层（Fully connected, FC）

**经典架构**

**LeNet-5**

![img](/img/ai_note.zh-cn.assets/-172845431716762.assets)

**AlexNet**

![img](/img/ai_note.zh-cn.assets/-172845431716763.assets)

**VGG-16**

结构简单，更关注卷积层，有16层带权重的层

![img](/img/ai_note.zh-cn.assets/-172845431716764.assets)

#### 卷积残差网络

（conv residual network, ResNet），利用跳跃连接（skip connection），解决梯度爆炸和消失

![img](/img/ai_note.zh-cn.assets/-172845431716765.assets)

**残差神经网络ResNet**

![img](/img/ai_note.zh-cn.assets/-172845431716766.assets)

#### **初始网络**

（Inception network），做多次卷积并将结果合并

![img](/img/ai_note.zh-cn.assets/-172845431716767.assets)

计算成本高，计算成本=卷积核的3个参数 x 卷积核所可移动的位置数 x 卷积核数量，若使用1x1卷积先减少通道数/维度化为瓶颈层(bottleneck layer)可大量减少计算成本

 **单模块**

![img](/img/ai_note.zh-cn.assets/-172845431716768.assets)

重复多次使用该单模块

#### MobileNets

**深度可分离卷积（depthwise-separable convolutions）**

![img](/img/ai_note.zh-cn.assets/-172845431716769.assets)

成本计算为：3x3x4x4x3 + 1x1x3x4x4x5 远小于一般卷积成本

**架构**

![img](/img/ai_note.zh-cn.assets/-172845431716770.assets)

解决内存过小的问题，将输入值投射到较小的数据集

### 对象检测

**目标定位**

设置$b_x, b_y, b_h, b_w$：横坐标，纵坐标，高，宽，**y** 向量将包含是否有对象及概率$p_c$、$b_x, b_y, b_h, b_w$、是哪个对象$c_1,c_2,c_3$等

**地标检测（Landmark detection）**

全连接层转换为卷积层

![img](/img/ai_note.zh-cn.assets/-172845431716771.assets)

**滑动窗口检测（sliding Windows Detection）**

 合并成一个前向传播运算，共享运算

![img](/img/ai_note.zh-cn.assets/-172845431716772.assets)

### YOLO算法

You only look once，**边界框预测**

$b_x, b_y, b_h, b_w$中：前两个只能小于1，后两个可大于1

**交并比（Intersection over union）**

将检测的框和真实的框交集部分大小比上并集大小，大于阈值0.5（可调）则正确，用于判断算法准确性

**非极大值抑制**

保证对每个对象只得到一个检测，选择最大可能性的边框，抑制其余邻近边框

**锚框（anchor box）**

一个网格单元检测多个目标，将输出 y 向量叠加一倍，维度翻倍，分别描述不同目标

### 语义分割

Semantic Segmentation

**转置卷积（Transpose Convolution）**

重叠部分叠加相加，padding为1，stride为2，灰色部分不填充，最终将2x2扩展为4x4

![img](/img/ai_note.zh-cn.assets/-172845431716773.assets)

### U-Net

![img](/img/ai_note.zh-cn.assets/-172845431716874.assets)

![img](/img/ai_note.zh-cn.assets/-172845431716875.assets)

### 人脸识别

One-shot learning，单样本学习：在只有一个样本情况下识别正确该人

**相似方程：d(img1, img2) = 图像差异度** 与 $\tau$ 比较

**孪生网络（Siamese network）**——用相同卷积网络对不同图片处理

$d(x^{(1)},x^{(2)})=||f(x^{(1)})-f(x^{(2)})||^2_2$同一个人值极小

![img](/img/ai_note.zh-cn.assets/-172845431716876.assets)

**三元组损失（Triplet loss）**

存在A(Anchor), P(Positive), N(Negative)图片，$\alpha$表示margin，$||f(A)-f(P)||^2- ||f(A)-f(N)||^2+\alpha\le 0$

**损失函数定义：**$L(A,P,N)=\max(||f(A)-f(P)||^2- ||f(A)-f(N)||^2+\alpha,0)$

**代价函数：**$J=\sum_{i=1}^mL(A^{(i)},P^{(i)},N^{(i)})$

也可使用二分类逻辑回归，看两图片是否返回1或0分别表示相同或不同

### 神经风格迁移

图像：Content(C)和Style(S)形成Generated image(G) 

代价函数：$J(G)=\alpha J_{Content}(C,G)+\beta J_{Style}(S,G)$

1. **内容代价函数**

$J_{Content}(C,G)=\frac{1}{2}||a^{[l][C]}-a^{[l][G]}||^2$，a 为激活因子，在 l 层

1. **风格代价函数**

**风格矩阵/gram matrix**：$a_{i,j,k}^{[l]}$表示高 i 宽 j 通道 k 的激活因子，$G^{[l]}:\,\,n_c^{[l]}\times n_c^{[l]}$记录每一对通道间的相关性 

$G_{kk'}^{[l](S)}=\sum_{i=1}^{n_H^{[l]}}\sum_{j=1}^{n_W^{[l]}}a_{ijk}^{[l](S)}a_{ijk'}^{[l](S)},\quad\quad k=1,\cdots ,n_c^{[l]}$

$G_{kk'}^{[l](G)}=\sum_{i=1}^{n_H^{[l]}}\sum_{j=1}^{n_W^{[l]}}a_{ijk}^{[l](G)}a_{ijk'}^{[l](G)},\quad\quad k=1,\cdots ,n_c^{[l]}$

$J_{Style}^{[l]}(S,G)=\frac{1}{(\cdots)}||G^{[l][S]}-G^{[l][G]}||_F^2$

![img](/img/ai_note.zh-cn.assets/-172845431716877.assets)

**总风格代价函数**

$J_{Style}(S,G)=\sum_l \lambda^{[l]}J_{Style}^{[l]}(S,G)$

更新参数：$G=G-\frac{\alpha}{2G}J(G)$

## NLP

自然语言处理Natural language processing (NLP) ，有监督学习

### 序列模型

$T_x^{(i)}$表示第 i 个训练样例的序列长度，$X^{(i)}$表示 i 序列中第 t 个元素，x 表示输入 y 表示输出

**数据表示：**存在单词字典列表，使用`one hot`，即每个单词对应一个等长向量列表，对应单词索引处为1其余为0

### 循环神经网络

（Recurrent Neural）处理  一维序列化数据

**前向传播**

![img](/img/ai_note.zh-cn.assets/-172845431716878.assets)

$a^{<0>}=\vec 0$

1. Tanh, ReLU：$a^{<t>}=g(w_{aa}a^{<t-1>}+w_{ax}x^{<t>}+b_a)$
2. Sigmoid, SoftMax: $\hat y^{<t>}=g(w_{ya}a^{<t>}+b_y)$

将$W_{aa}$和$W_{ax}$矩阵左右联结表示为$W_a$，1 式转化为$a^{<t>}=g(W_a[a^{<t-1>}, x^{<t>}]+b_a)$，[ , ]中表示上下联结

**基于时间反向传播**

预测特定词是一个人名的概率是$\hat y$，使用逻辑回归损失

某一时间损失：$L^{<t>}(\hat y^{<t>},y^{<t>})=-y^{<t>}\log \hat y^{<t>}-(1-y^{<t>})\log (1-\hat y^{<t>})$

总体损失函数：$L(\hat y, y)=\sum_{t=1}^{T_y}L^{<t>}(\hat y^{<t>},y^{<t>})$，$T_x$和$T_y$可能不同

**架构类型**

![img](/img/ai_note.zh-cn.assets/-172845431716879.assets)

![img](/img/ai_note.zh-cn.assets/-172845431716880.assets)

**语言模型+序列生成**

训练集为极大**语料库**（corpus），将数据句子**标记化**（tokenize），句子末尾加入**EOS**（End Of Sentence）标记，定位句子结尾，未知单词标记为**<UNK>**（unknown word）标记，$\hat y$对应于已知条件概率P(__|已知)

**损失函数：**$L(\hat y^{<t>},y^{<t>})=-\sum_iy_i^{<t>}\log \hat y_i^{<t>}$，softmax损失函数

**字符级语言模型，字典为[a,b,c,...,z,A,...,Z]**

![img](/img/ai_note.zh-cn.assets/-172845431716881.assets)

**Gate Recurrent Unit（GRU）门控制单元**

- 解决RNN**梯度消失问题，**$C^{<t>}$记忆单元来存储记忆，如：需要记住cat是单数，使用was而不是were
- $\tilde C^{<t>}=\tanh (W_c[\Gamma_r\cdot C^{<t-1>},x^{<t>}]+b_c)$
- 门控值：**更新门**$\Gamma_u=\sigma(W_u[C^{<t-1>},x^{<t>}]+b_u)$，sigmoid使范围为0-1，为0表示不更新$C^{<t>}$，同样适用于**相关性门**$\Gamma_r$
- $C^{<t>}=\Gamma_u\cdot \tilde C^{<t>}+(1-\Gamma_u)\cdot C^{<t-1>}$ ，a和c相等

![img](/img/ai_note.zh-cn.assets/-172845431716882.assets)

**Long Short Term Memory Units（LSTM）长短期记忆单元**

- $\tilde C^{<t>}=\tanh (W_c[a^{<t-1>},x^{<t>}]+b_c)$
- **更新门**$\Gamma_u=\sigma(W_u[C^{<t-1>},x^{<t>}]+b_u)$，**遗忘门**$\Gamma_f=\sigma(W_f[C^{<t-1>},x^{<t>}]+b_f)$，**输出门**$\Gamma_o=\sigma(W_o[C^{<t-1>},x^{<t>}]+b_o)$
- 更新：$C^{<t>}=\Gamma_u\cdot \tilde C^{<t>}+\Gamma_f\cdot C^{<t-1>}$，$a^{<t>}=\Gamma_o\cdot C^{<t>}$，a和c不再相等

![img](/img/ai_note.zh-cn.assets/-172845431716883.assets)

**情感分类**

![img](/img/ai_note.zh-cn.assets/-172845431716884.assets)

**双向递归网络**

- （bi-directional recurrent neural network, BRNNs）
- 解决单词不能单从前面得出是否是人名

![img](/img/ai_note.zh-cn.assets/-172845431716885.assets)

**深度递归网络**

- Deep RNNs

![img](/img/ai_note.zh-cn.assets/-172845431716886.assets)

### 词嵌入模型

**词向量表示**

- one-hot编码两两单词相乘为0
- 需要描述一个物，需要综合多项指标（向量），向量可以用不同方法计算相似度，相似词在特征表达中比较相似
- 特征比如单词与性别（-1~1）、年龄、是否为食物的指标值（0~1）

**相似度——类比推理**

如：男生与女生对应国王和皇后，t-SAE算法以非线性方式映射到2维空间，将会把类比关系打破

**余弦相似度(相似函数)**

- $\arg \max sim(e_w,e_{king}-e_{man}+e_{woman})\\sim(u,v)=\frac{u^Tv}{||u||_2\cdot||v||_2}$，实则求 u 和 v 之间的角$\phi$的余弦值，`0~180:1~-1`

**矩阵嵌入**

使用单词矩阵与one-hot编码向量相乘获取对应单词的向量，实则一般在**嵌入层**中直接取对应列即可

暂时无法在飞书文档外展示此内容

### 词向量模型

**Word2Vec模型**，将文本向量化

**训练数据**

![img](/img/ai_note.zh-cn.assets/-172845431716887.assets)

不同模型：**CBOW（上下文推词）** 与 **Skipgram（词推上下文）**

![img](/img/ai_note.zh-cn.assets/-172845431716888.assets)

**除偏（性别、种族偏差）**

1. 识别需要消除的偏差方向，使用$e_{he}-e_{she}$等多组的平均值获取坐标轴
2. 中立化：未被定义的词通过映射到避开偏差
3. 均匀化：移动相关性别的词使得距离坐标轴相等

![img](/img/ai_note.zh-cn.assets/-172845431716989.assets)

#### **Skip-grams**

**有监督学习——**语境词**c**，目标词**t，**$\theta_t$是关于 t 的参数（w），未包含偏置项

$p(t|c)=\frac{e^{\theta_t^Te_c}}{\sum_{j=1}^{10000}e^{\theta_j^Te_c}}$，softmax 中分母的运算代价极大

**负采样（Negative Sampling）**

数据集将会对context（上下文）跟着的word（单词）进行target赋值1（正样本）或0（负样本），表示是否可以组成一个词组，使用有监督学习，根据context和word为输入【包含一个正样本和k-1个负样本】，target为预测，使得计算代价低，进行逻辑回归训练k-1个分类器，多次二分类

#### GloVe算法

- Global Vectors for word representation
- $X_{ij}$表示 i(t) 在 j(c) 的上下文出现次数，$f(X_{ij})$是权重项，调整使得常见词权重不高，罕见词权重不低，X为0时f为0，采用"0log0=0"的规则
- $minimize\,\, \sum_{i=1}^{10000}\sum_{j=1}^{10000}f(X_{ij})(\theta_i^Te_j+b_i+b_j'-\log X_{ij})^2$，随机均匀初始化$\theta,e$，梯度下降最小化目标函数
- $e_w^{(final)}=\frac{e_w+\theta_w}{2}$               

### Seq2Seq模型

- （Sequence-to-sequence），机器翻译+语音识别
- 先将语言经过编码器，然后经过解码器进行翻译，计算$P(y^{<1>}|x)$

![img](/img/ai_note.zh-cn.assets/-172845431716990.assets)

Bleu指数在句子长度小和极大时都很小

#### 定向搜索算法

- Beam Search或集束搜索
- 参数B表示集束宽度，保留备选单词数，每次选择B个最高条件概率词元
- $\arg \max_y\frac{1}{T_y^{\alpha}}\sum_{t=1}^{T_y}\log P(y^{<t>}|x,y^{<1>},\cdots ,y^{<t-1>})$，$\alpha$=0.7取部分规范化
- $P(y^{<1>}\cdots y^{<T_y>}|x)=P(y^{<1>}|x)P(y^{<2>}|x,y^{<1>})\cdots P(y^{<T_y>}|x,y^{<1>},\cdots ,y^{<T_y-1>})$

![img](/img/ai_note.zh-cn.assets/-172845431716991.assets)

**Bleu指数**

- 多个好结果下选择一个最好的看n元单词在参考翻译中出现概率
- $P_n=\frac{\sum_{n-grams\in \hat y}Count_{clips}(n-gram)}{\sum_{n-grams\in \hat y}Count(n-gram)}$再去各个n的平均值
- n个n个取参考翻译记录每n个单词的count，再在机器翻译中得出count_clip

#### 注意力模型

- （attention model），会生成多个注意力权重参数$\alpha$总和为1，将在某个词放入多少注意力，$\alpha^{<t, t'>}$ 表示生成 t 时需要对 t' 花费的注意力是多少  

![img](/img/ai_note.zh-cn.assets/-172845431716992.assets)

### Transformer

同一时间对一句话同时处理，注意力+卷积

**自注意力机制：并行计算**

为每个单词计算出一个基于注意力的表达：$A(q,K,V)$，即$A^{<1>},A^{<2>},\cdot$

![img](/img/ai_note.zh-cn.assets/-172845431716993.assets)

将每个单词与q(Query), K(Key), V(Value)关联，W为学习参数

1. $q^{<i>}=W^Q\cdot x^{<i>}$
2. $K^{<i>}=W^K\cdot x^{<i>}$
3. $V^{<i>}=W^V\cdot x^{<i>}$

![img](/img/ai_note.zh-cn.assets/-172845431716994.assets)

**多头注意力机制：循环并行计算自注意力**

通过不同矩阵参数集进行重复多次的自注意力计算，用于回答不同问题：when,where,who,how...

**transformer架构**

![img](/img/ai_note.zh-cn.assets/-172845431716995.assets)

## 人工智能

1. ANI( Artificial Narrow Intelligence )：自动驾驶，网页搜索引擎
2. AGI( Artificial General Intelligence )，通用人工智能，基本人类
