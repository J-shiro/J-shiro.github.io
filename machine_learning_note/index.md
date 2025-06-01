# 机器学习


## 概念

**灰度图**

- 图像一般为三个数相乘：宽 x 高 x 通道数，单位为像素
- 彩色图像通道数为3，灰度图为1
- 输入图像数据被平展为一列向量作为模型输入

**均方误差**

- mean_squared_error，MSE，衡量回归任务中预测值和真实值差异

- $\text{MSE} = \frac{1}{m} \sum_{i=1}^m (\hat{y}^{(i)} - y^{(i)})^2$

**专业术语**

| 名称                 | 符号或说明                                     |
| -------------------- | ---------------------------------------------- |
| 输入变量（特征）     | **x**                                          |
| 输出变量（目标变量） | **y**                                          |
| 训练样本总数         | **m**                                          |
| 单个训练样本         | $(x, y)$                                       |
| 第 $i$ 个训练样本    | $(x^{(i)}, y^{(i)})$                           |
| 模型输出（预测值）   | $\hat{y}$                                      |
| 模型函数             | **f**                                          |
| 模型参数（权重）     | **w**，**b** 等                                |
| 满足指标             | 如准确率、精确率等                             |
| 优化指标             | 通常是损失函数值                               |
| 人类水平误差         | 可作为贝叶斯最优误差下界                       |
| F-范数               | 矩阵所有元素平方和再开根号（常用于矩阵正则化） |

**模型训练步骤**

> **定义模型结构**：明确输入 $x$、权重 $w$、偏置 $b$，构造模型输出 $\hat{y} = f(x; w, b)$
>
> **定义损失函数**：如 MSE、交叉熵等衡量模型输出与真实标签的差异
>
> **最小化损失**：使用梯度下降等优化算法，更新模型参数以最小化损失函数值

**迁移学习**

- 针对小数据集，前提为新旧两模型输入类型相同

- **预训练阶段**（获取大模型）

  - 在大数据集（如 ImageNet）上训练神经网络

  - 获取前 $N-1$ 层参数（提取通用特征）

- **微调阶段**（迁移到新任务）

  - 保留前 $N-1$ 层，初始化或冻结

  - 替换输出层（如从1000类 → 10类）

  - 对最后一层或所有层进行微调（梯度下降）

**多任务学习**

一个神经网络模型同时学习多个相关任务，对每张图预测多个标签

**端到端深度学习（end-to-end）**

- 大量数据包括各种子数据，不经过中间过程
- 直接从原始输入学习到最终输出，中间过程不再人为特征设计

## 类别

- **有监督学习**：给定输入输出对训练，最终可通过输入预测输出【回归（拟合）、分类（边界）】
- **无监督学习**：将未标记的数据自动分配到不同组【聚类、异常检测、推荐系统、降维】



## 模型评估

多元特征时无法可视化所有维度 → 借助系统化评估方法

数据构造可辅助评估：

- **数据增强**：旋转、扭曲等
- **数据合成**：人工合成样本

### **数据处理**

**数据划分**

需要相同分布

- **训练集**：训练模型

- **交叉验证集**：模型选择

- **测试集**：评估泛化性能
- 训练集60%、测试集20%、交叉验证集20%，**大数据集时：分为98%、1%、1%**

**训练与评估方式**

- 回归问题：用均方误差 MSE 评估训练集/测试集的代价函数
- 分类问题：统计预测错误的样本数：$\hat y \ne y$

**标准化**

需要先将数据规格化，即减去平均值并除以标准差，得到[-1, 1]的范围，并且打乱数据

### 模型选择

**流程**

1. 练模型：N个模型使用训练集得到N组参数
2. 选模型：使用交叉验证集求每个模型的平方误差$J_{cv}$比较
3. 测模型：测试集求平方误差，评估泛化误差(Generalization Error)

**利用K折交叉验证**（cross validate）

- 将训练集分成 K 份，[n1, n2, ..., nk]，进行 K 次实验
- 第 **i** 次实验中，取 ni 作为训练集中的**验证集**，其余为训练集中的**训练子集**
-  **K** 次实验最终取平均

<img src="/img/machine_learning_note.zh-cn.assets/172845431716996.png" alt="图片无法加载" />

### 偏差方差

| 情况   | $J_{train}$ | $J_{cv}$ | 特征                                          |
| ------ | ----------- | -------- | --------------------------------------------- |
| 高偏差 | 高          | 高       | 欠拟合，能力不足，相差不大                    |
| 高方差 | 低          | 高       | 过拟合，泛化能力差，$J_{train}$远小于$J_{cv}$ |

与多项式程度的关系图

<img src="/img/machine_learning_note.zh-cn.assets/17284543171621.png" alt="图片无法加载" />

正则化参数 $\lambda$ 影响偏差、方差

<img src="/img/machine_learning_note.zh-cn.assets/17284543171622.png" alt="图片无法加载" />

**表现基准**

需要加入**人类基准表现**，来判断模型的训练误差$J_{train}$和交叉验证误差$J_{cv}$

**学习曲线**

- 高偏差下，增加训练集不会有助于模型（例如：使用线性模型拟合二次函数，再多点都不利于拟合）

<img src="/img/machine_learning_note.zh-cn.assets/17284543171623.png" alt="图片无法加载" />

- 高方差下，增加训练集有助于模型（例如：模型过拟合匹配了四次函数，数据增多使模型逐渐接近四次函数模型）

<img src="/img/machine_learning_note.zh-cn.assets/17284543171624.png" alt="图片无法加载" />

- 解决高方差：更多训练集、更少特征、减少正则化
- 解决高偏差：更多特征、增加多项式特征、增加正则化、更大神经网络

### 混淆矩阵

**Confusion Matrix**

|                          | 相关(Relevant)，正类                           | 无关(NonRelevant)，负类                      |
| ------------------------ | ---------------------------------------------- | -------------------------------------------- |
| 被检索到(Retrieved)      | **TP** (true positives)检索到正确的值          | **FP** (false positives)检索到错误的值：存伪 |
| 未被检索到(Not Retrieved | **FN** (false negatives)未检测到正确的值：去真 | **TN** (true negatives)未检测到错误的值      |

**性能指标**

- **精准度**：$precision=\frac{TP}{TP+FP(total\,predicted\,positive)}$：预测病人得某病，大概率病人确实有该病

- **召回率**：$recall=\frac{TP}{TP+FN(total\,actual\,positive)}$：病人有该病，大概率模型能够识别出来确有该病

当$f_{w,b}(x)\gt$threshold阈值，预测为1：

<img src="/img/machine_learning_note.zh-cn.assets/17284543171625.png" alt="图片无法加载" />

- **F1-score**：综合指标，调和平均，惩罚极端值，给低值更多权重
  - $F_1=\frac{2}{\frac{1}{precision}+\frac{1}{recall}}=\frac{TP}{TP+\frac{FN+FP}{2}}$
  - 不使用平均值$\frac{Precision+Recall}{2}$，因为会有P很低R很高情况

### ROC曲线

- Receiver Operating Characteristic，二元分类中常用评估方法

- 计算各种阈值的 **true positive rate(TPR)** 和 **false positive rate(FPR)** 进行绘制

- y 轴：TPR = TP / (TP + FN) (Recall)
- x 轴：FPR = FP / (FP + TN)

**AUC指标**

比较分类器：测量曲线下面积（**AUC**），完美的AUC为**1**，纯随机分类器的AUC为**0.5**，一个好的分类器尽可能**朝左上方**远离虚线

<img src="/img/machine_learning_note.zh-cn.assets/17284543171626.png" alt="图片无法加载" />

## 优化方法

### 梯度下降

[Gradient Descent，GD]

- 多参数下可能获得代价函数的多个局部极小值，迭代次数自定义，沿梯度方向将增加损失函数值
- 使用偏导更新所有参数 w 和 b：$\begin{cases}w_j = w_j-\alpha \frac{\partial}{\partial w}J(w,b)\\ b=b-\alpha\frac{\partial}{\partial b}J(w,b) \end{cases}$

- $\alpha$为学习率控制每次更新幅度，后面一项为 J 关于 w 和 b 的导数

### 动量法

计算 dw 和 db 的滑动平均值 v ，更新权重时使得梯度下降更平滑，减少震荡，加速收敛

<img src="/img/machine_learning_note.zh-cn.assets/17284543171627.png" alt="图片无法加载" />

### RMSprop

均方根传递（Root Mean Square prop），当梯度下降震荡时，减少某 w 参数方向的震荡

- $S_{dW}=\beta_2 S_{dW} + (1-\beta_2)dW^2$
- $W=W-\alpha \frac{dW}{\sqrt{S_{dW}}+\varepsilon}$

### Adam

> - Adaptive Moment estimation，自适应矩估计
> - 结合RMSprop和动量法，对每个参数($w_i, b$)使用不同的学习率
> - 默认：$\beta_1:0.9,\quad \beta_2: 0.999\quad \varepsilon: 10^{-8}$， $\alpha$ 需要调整

1. 动量项计算：$V_{dW}=\beta_1 V_{dW}+(1-\beta_1)d_W\quad V_{db}=\beta_1 V_{db}+(1-\beta_1)d_b$
2. RMSprop，平方项计算：$S_{dW}=\beta_2 S_{dW} + (1-\beta_2)dW^2\quad S_{db}=\beta_2 S_{db} + (1-\beta_2)db^2$
3. 偏差修正： $V_{dW}^{correct}=\frac{V_{dW}}{1-\beta_1^t}\quad V_{db}^{correct}=\frac{V_{db}}{1-\beta_1^t}\quad S_{dW}^{correct}=\frac{S_{dW}}{1-\beta_2^t}\quad S_{dW}^{correct}=\frac{S_{dW}}{1-\beta_2^t}$
4. 更新参数：$W=W-\alpha\frac{V_{dW}^{correct}}{\sqrt{S_{dW}^{correct}}+\varepsilon}\quad b=b-\alpha\frac{V_{db}^{correct}}{\sqrt{S_{db}^{correct}}+\varepsilon}$

1️⃣ 使用等高图绘制代价函数，由梯度下降从start到minimum，若每次参数移动方向基本一致，Adam将**提高学习率**，加快速度

<img src="/img/machine_learning_note.zh-cn.assets/17284543171628.png" alt="图片无法加载" />

2️⃣ 当梯度下降呈现下图形式，参数不断来回振荡，Adam将减少学习率，加快速度

<img src="/img/machine_learning_note.zh-cn.assets/17284543171639.png" alt="图片无法加载" />

## 回归模型

### 线性回归

- 解决回归问题，预测一个连续型的因变量

- 线性回归模型：$f(x)=wx+b$【w: weight权重, b: bias偏置】

**代价函数**

> Cost function，或**平方误差**成本(Squared error cost)函数
>
> $J(w, b)=\frac{1}{2m}\cdot\sum_{i-1}^{m}(\hat y^{(i)} - y^{(i)})^2=\frac{1}{2m}\cdot\sum_{i-1}^{m}(f_{w,b}(x^{(i)}) - y^{(i)})^2$，找 w 和 b 使得$J(w,b)$最小

**步长/学习率**

范围 [0, 1]，对结果产生影响，从小选择

<img src="/img/machine_learning_note.zh-cn.assets/172845431716310.png" alt="图片无法加载" />

步长过小：收敛慢，花费时间长

步长过大：抖动幅度大，无法收敛或发散

**学习率衰减**

- **Mini-batch SGD** 在每次迭代中使用一小部分数据，会带来噪声（随机性），使得最终无法收敛

1️⃣ 训练前期：学习率大有利于快速下降

2️⃣ 训练后期：学习率过大会来回震荡，不能稳定收敛到最优

**解决思路**：让学习率随着时间逐渐减小，即 “学习率衰减”

🔹 分数衰减（Inverse Scaling Decay)

公式：$\alpha=\frac{1}{1+d\cdot t}\alpha_0$

- d 为衰减率，t 为迭代数，$\alpha_0$为初始学习率
- 收敛较平稳，但后期衰减可能太慢

🔹 指数衰减（Exponential Decay）

公式：$\alpha=0.95^{t}\cdot \alpha_0$

- 学习率迅速减小，后期基本接近0

🔹 根号衰减

公式：$\alpha_t =\frac{k}{\sqrt{t}}\alpha_0$

- 学习率缓慢下降，稳定且不容易突降到太小

**过拟合**

`degree`值过高可能会出现**过拟合**，表明模型过于贴合训练集，方差大

解决过拟合：可以增加训练集数；使用更少特征；正则化

**正则化**

- **L1 正则化**：$\frac{\lambda}{2m}\sum_{j=1}^n|w_j|$

- **L2 正则化**
  - 对**权重参数**用$\lambda$进行惩罚，减小参数大小，让权重参数尽可能平滑
  - 若有 n 个参数 w ，对每个参数都进行惩罚

代价函数变为：$J(w, b)=\frac{1}{2m}\sum^m_{i=1}(f_{w,b}(x^{(i)})-y^{(i)})^2+\frac{\lambda}{2m}\sum^n_{j=1}w_j^2$

$\lambda\gt0$是正则化参数，第二项为正则化项

<img src="/img/machine_learning_note.zh-cn.assets/172845431716311.png" alt="图片无法加载" />

**提早停止（Early stopping）**

随着迭代次数增加，训练误差递减， 交叉验证误差先减后增，在表现最好时提前停止，解决过拟合

### 多元线性回归

- 当输入特征维度增加到多个（$x_1, x_2,\cdots,x_n$）时，线性回归变为拟合一个超平面

- $x_j^{(i)}$表示：第 **i** 个测试示例中特征 **j** 的值

**模型描述**

拟合平面：$h_\theta(x)=\theta_0+\theta_1x_1+\theta_2x_2$

拟合超平面：$h_{\theta}(x)=\theta_0 + \theta_1x_1+\theta_2x_2+\cdots +\theta_nx_n=\theta^Tx$，$x_0=1$

>  特征 $x_1,x_2$
>
> 权重参数 $\theta_1,\theta_2$
>
> 偏置值$\theta_0$，微调平面位置

**误差项**

误差$\varepsilon$是真实值和预测值间的差异，每个样本真实值：$y^{(i)}=\theta^Tx^{(i)}+\varepsilon^{(i)}$

**独立同分布**

误差 $\varepsilon^{(i)}$ 是**独立同分布**的，服从均值为 0 ，方差为 $\theta^2$ 的**高斯分布/正态分布**

即 $p(\varepsilon^{(i)})=\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(\varepsilon^{(i)}-0)^2}{2\sigma^2})$

**似然函数**

1️⃣ 消去误差 $\varepsilon$ 得到概率：$p(y^{(i)}|x^{(i)};\theta)=\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(y^{(i)}-\theta^Tx^{(i)})^2}{2\sigma^2})$

2️⃣ 似然函数：多样本累乘，求什么样的参数跟数据组合后恰好为真实值

- $L(\theta)=\prod_{i=1}^mp(y^{(i)}|x^{(i)};\theta)$，

3️⃣ 对数似然，将累乘法转换为加法：$logL(\theta)$

- 化简

$\sum_{i=1}^mlog\frac{1}{\sqrt{2\pi}\sigma}exp(-\frac{(y^{(i)}-\theta^Tx^{(i)})^2}{2\sigma^2})\\=mlog\frac{1}{\sqrt{2\pi}\sigma}-\frac{1}{\sigma^2}\cdot\frac{1}{2}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$

- 目标：让似然函数越大越好，则使后面项越小 $J(\theta)=\frac{1}{2}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$（最小二乘法）

- 求对 $\theta$ 的偏导等于 0 ，$\theta=(X^TX)^{-1}X^Ty$，此处 $X$ 为行/列向量

4️⃣ 梯度下降

目标函数：$J(\theta,m)=\frac{1}{2m}\sum_{i=1}^m(y^{(i)}-\theta^Tx^{(i)})^2$，求偏导得到梯度方向，下降：向梯度反方向走

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

1. 基础归一化：除以最大值
2. 均值归一化：$\frac{var - 均值\mu}{max - min}$ 转换为范围[-1, 1]
3. Z分数归一化(Z-score normalization)：$\frac{var - 均值\mu}{标准差\sigma}$ 转换为范围[-1, 1]

### 多项式回归

- 通过修改**多项式特征**程度的大小，即不同的维度，来拟合不同的数据，拟合曲线
- 如：当有二维样本 a 和 b ，程度degree为2时的多项式特征将为$[1, a, b, a^2, b^2, ab]$，最终拟合后得到各个多项式特征变量前的参数，$y=\theta\cdot 1+\theta_1\cdot a+\theta_2\cdot b+\theta_3\cdot a^2+\theta_4\cdot b^2+\theta_5\cdot ab$

**样本数量对结果影响**

- 训练集大小极小时，测试集均方差高，训练集均方差低
- 随训练集大小增大，两均方差之差减小

<img src="/img/machine_learning_note.zh-cn.assets/172845431716312.png" alt="图片无法加载" />

### 岭回归

**公式**：$J(\theta)=MSE(\theta)+\alpha \frac{1}{2}\sum_{i=1}^n\theta_i^2$

- $MSE(\theta)$为均方误差
- 正则项中是 L2正则化项，对所有权重参数平方后求和，用来惩罚过大权重
- $\alpha$正则化系数，用于确定左右式的比重谁大，用于调整正则化程度
  - $\alpha$很大，更关注控制参数值大小，可能导致欠拟合
  - $\alpha$很小，几乎等同普通线性回归，正则化效果不明显

### Lasso回归

**公式**：$J(\theta)=MSE(\theta)+\alpha \sum_{i=1}^n|\theta_i|$

- 正则项中对每一个$\theta$绝对值求和（L1范数）
- L1正则化的稀疏性：Lasso 会让某些$\theta_i=0$，自动完成特征选择，留下的重要变量更少
- 适用于特征数目远多于样本数情况

## 分类算法

**有监督**问题

### 逻辑回归

1. **概述**

- logistic regression，二元分类算法，输出为类别（0或1）
- 适合预测离散型因变量，决策边界可以是**非线性**

2. **Sigmoid函数**

- $g(z)=\frac{1}{1+e^{-z}}=P(y=1|x)=\hat y$，**z** 可取任意实数，值域[0, 1]
- 线性回归中得到的预测实数值，可以映射到Sigmoid函数中完成**值**到**概率**的转换

<img src="/img/machine_learning_note.zh-cn.assets/172845431716313.png" alt="图片无法加载" />

3. **预测函数**

$h_{\theta}(x)=g(\theta^Tx)=\frac{1}{1+e^{-\theta^Tx}}$，其中$z=\theta^Tx=\sum_{i=1}^n\theta_ix_i=\theta_0+\theta_1x_1+\cdots+\theta_nx_n$

4. **分类概率**

二分类任务：$\begin{cases}P(y=1|x;\theta)=h_{\theta}(x) \\P(y=0|x;\theta)=1-h_{\theta}(x)\end{cases}$，整合：$P(y|x;\theta)=(h_{\theta}(x))^y(1-h_{\theta}(x))^{1-y}$

-  $P(y=1|x;\theta)$ 中 $\theta$ 是影响该概率的参数

- 设定一个阈值 a，概率大于等于 a 时，分类为1，当概率小于 a 时，分类为0

5. **决策边界**

- 决策边界是将图形中的所有像素点代入分类器进行划分，假设划分为了0和1两种，则基于等高线划分为0高度和1高度，则可以绘制出决策边界
- 得到参数$\theta$，将特征点代入$h_{\theta}(x)$得到概率，按阈值划分类别，使用`plt.contour`可视化

> **非线性决策边界**
>
> 使用多项式程度（polynomial_degree）来对特征值进行非线性变化
>
> 用**多项式线性回归**的式子替代**sigmoid函数**中的 **z** 后通过 **z = 1** 得出决策边界

6. **损失函数与代价函数**

> 平方误差代价函数不适合逻辑回归，会导致梯度下降时有多个局部最低点
>
>  分类问题的**损失函数**：损失值可以通过作图观察到随着迭代次数增加，逐渐减小趋于稳定

- 根据$l(\theta)=logL(\theta)=\sum_{i=1}^m(y_ilogh_{\theta}(x_i)+(1-y_i)log(1-h_{\theta}(x_i)))$计算
- 需要借助$f(x)=|logx|$来计算，离1越远损失越大

**但样本损失函数**

$$L(f_{w,b}(x^{(i)}), y^{(i)})=\begin{cases}-log(f_{w,b}(x^{(i)}))\quad y^{(i)}=1\\\ -log(1-f_{w,b}(x^{(i)}))\quad y^{(i)}=0\end{cases}$$

其中$f(x)$是`sigmoid`函数，取值[0, 1]

<img src="/img/machine_learning_note.zh-cn.assets/172845431716314.png" alt="图片无法加载" />

预测值接近1时，损失最低，越接近0，损失越高

<img src="/img/machine_learning_note.zh-cn.assets/172845431716315.png" alt="图片无法加载" />

预测值接近1时，损失越高，越接近0，损失最低

损失函数合并：$L(f_{w,b}(x^{(i)}), y^{(i)})=-y^{(i)}log(f_{w,b}(x^{(i)}))-(1-y^{(i)})log(1-f_{w,b}(x^{(i)})$

**代价函数**

- $J(w,b)=\frac{1}{m}\sum^m_{i=1}L(f_{w,b}(x^{(i)}), y^{(i)})$

- $=-\frac{1}{m}\sum^m_{i=1}[y^{(i)}log(f_{w,b}(x^{(i)}))+(1-y^{(i)})log(1-f_{w,b}(x^{(i)}))]$

7. **最大似然估计与梯度下降**

- **似然函数**：$L(\theta)=\prod_{i=1}^mP(y_i|x_i;\theta)=\prod_{i=1}^m(h_{\theta}(x_i))^{y_i}(1-h_{\theta}(x_i))^{1-y_i}$
- **对数似然**：$l(\theta)=logL(\theta)=\sum_{i=1}^m(y_ilogh_{\theta}(x_i)+(1-y_i)log(1-h_{\theta}(x_i)))$
- **梯度上升求最大值**，引入$J(\theta)=-\frac{1}{m}l(\theta)$转换为**梯度下降任务**
- **求偏导**：$\frac{\partial}{\partial\theta_j}J(\theta)=\cdots=-\frac{1}{m}\sum_{i=1}^m(y_i-g(\theta^Tx_i))x_i^j$
- **参数更新**：$\theta_j':=\theta_j-\alpha\frac{1}{m}\sum_{i=1}^m(h_{\theta}(x_i)-y_i)x_i^j$

8. **正则化**

防止过拟合，加入惩罚项：

$J(w,b)-\frac{1}{m}\sum^m_{i=1}[y^{(i)}log(f_{w,b}(x^{(i)}))+(1-y^{(i)})log(1-f_{w,b}(x^{(i)}))]+\frac{\lambda}{2m}\sum^n_{j=1}w_j^2$

**多分类逻辑回归**

- **One-vs-All (OvA)方法**：将多分类转换为**多次二分类**

每次分为 2 类筛选出其中 1 类，n 分类即进行 n 次二分类，以概率值进行分类

### Softmax回归

- 多类别分类，multi class classification

- 多分类Logistic回归的推广

**Softmax函数**

$\hat P_k=\sigma(s(x))\_k=\frac{exp(s_k(x))}{\sum_{j=1}^Kexp(s_j(x))}$，将不同组的得分值 **s** 进行指数化来使得差异更大

假设**四**个输出：

$z_1=w_1\cdot x + b_1\\\ z_2=w_2\cdot x + b_2\\\ z_3=w_3\cdot x + b_3\\\ z_4=w_4\cdot x + b_4$，$a_i=\frac{e^{z_i}}{e^{z_1}+e^{z_2}+e^{z_3}+e^{z_4}}=P(y=i|x)$

**损失函数**

$loss(a_1, \cdots, a_N, y)=\begin{cases}-\log{a_1}\quad if\\,y=1\\\ -\log{a_2}\quad if\\,y=2\\\ \quad\vdots\\\ -\log{a_N}\quad if\\,y=N\end{cases}$，使用 `-log `函数来使得概率越接近 **1**，损失函数值越小

**损失函数（交叉熵）**：$J(\theta)=-\frac{1}{m}\sum_{i=1}^m\sum_{k=1}^Ky_k^{(i)}log(\hat p_k^{(i)})$

> 运用到神经网络：输出层将需要 N 个神经元，以分为 N 个类别
>
> 使用Softmax激活函数，将得分映射为概率
>
> 使得$a_i$与$z_1 \cdots z_N$所有值相关，全局归一化，区别于logistic回归：$a_i$只与$z_i$有关

**多标签分类(multi label classification)**

- 输入单图像，判断是否有行人，是否有车，是否有公交，向量[1 0 1]

<img src="/img/machine_learning_note.zh-cn.assets/172845431716316.png" alt="图片无法加载" />

### KNN算法

- K-近邻算法：非参数、有监督的分类回归算法，K为奇数

- 给定一个测试数据，若离它最近的**K**个训练数据大多都属于某一类别，则认为该测试数据也属于该类别

**计算流程**：

1. 计算已知类别数据集中点与当前点距离，并排序
2. 选取与当前点距离最小的K个点
3. 确定前K个点所在类别的出现概率
4. 返回出现频率最高的类别作为当前点预测分类

**分析**：

- 无需训练集，计算复杂度与训练集文档数目成正比O(n)
- K值选择、距离度量、分类决策规则是三个基本要素

## 决策树

<img src="/img/machine_learning_note.zh-cn.assets/172845431716317.png" alt="图片无法加载" />

- **有监督算法**，可以用于**分类**（离散型输出）和**回归**（连续型输出）
- **根结点**（第一个选择点）到**叶子结点**（最终决策结果）
- 训练阶段构造树，测试阶段跟随树走一遍，适用于电子表格/结构化数据，不适用于非结构化数据：图像、音频、文本

1️⃣ **决策依据**

**选择决策结点的先后顺序，使用熵的原理，最大化纯度**

✅ **信息熵**（Entropy）

测量纯度，衡量标准，随机变量不确定性的度量

**公式**

- $H(X)=-\sum p_i\cdot \log_{2} p_i$，$p_i$ 表示第 $i$类样本的概率

- $log$ 函数使得概率 $p_i$ 越靠近1，值越小，熵越小，纯度越高

<img src="/img/machine_learning_note.zh-cn.assets/172845431716318.png" alt="图片无法加载" />

当概率为1或0时纯度最高，熵最小

✅**信息增益原理**（Information Gain）

用于选择分裂特征，衡量特征能减少多少熵，即特征值X使得类Y的不确定性减少的程度

**公式**：

$H(p_1^{root})-(w^{left}H(p_1^{left})+w^{right}H(p_1^{right}))$

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

- 衡量样本集合的**不纯度**，越小越纯，用于分类时选择最优分裂特征

$Gini(p)=\sum^K_{k=1}p_k(1-p_k)=1-\sum_{k=1}^Kp_k^2$，选取GINI系数最小的来构建优先决策节点

<img src="/img/machine_learning_note.zh-cn.assets/172845431716319.png" alt="图片无法加载" />

**回归树**

- 决策树推广为回归算法，预测值：使用最终构建好的叶子结点中训练集数据的样本平均值
- 连续型输出

选择决策点：

- 将信息增益公式中计算**熵值**更换为计算**决策分裂完的子集中预测数据值的平均方差**
- **根结点最初熵值**换为**原始数据的总方差**
- 分裂标准：使用**平方误差最小化**

**剪枝策略**

- 决策树**过拟合风险**很大，防止过拟合
- **预剪枝**：边建立决策树边剪枝，限制深度、叶子结点数、叶子结点样本数、信息增益量等
- **后剪枝**：建立完决策树后剪枝，根据验证集性能剪除某些分支
  
  - 代价函数（CART）：$C_{\alpha}(T)=C(T)+\alpha\cdot|T_{leaf}|$
  - $T_{leaf}$：叶子结点个数，$C(T)$：Gini值乘数量，$\alpha$：惩罚系数
  
  - 分别计算分裂前和分裂后的损失值，若剪完后损失值减小则进行剪枝

### ID3

- 基于信息增益，适用于分类
- 倾向于选择取值较多的属性作为节点

**过程**：

输入：训练数据集D，特征集A，阈值$\epsilon$

输出：决策树T

**（1）** 若 D 中所有实例都属于同一个类 $C_k$ ，则 T 为单节点树，将 $C_k$ 作为该节点的类标记，返回 T

**（2）** 若 A=∅ ，则 T 为单节点树，并将 D 中的实例数最大的类 $C_k$ 作为该节点的类标记，返回 T

**（3）** 否则，**计算特征 A 对数据集 D 的信息增益，选择信息增益最大的特征** $A_g$

**（4）** 如果 $A_g$ 的信息增益小于阈值 $\epsilon$ ，则置 T 为单节点树，并将 D 中实例数最大的类 $C_k$ 作为该节点的类标记，返回 T【剪枝】

**（5）** 否则，对 $A_g$ **的每一可能值** $a_i$ **依** $A_g=a_i$ **将 D 划分为若干非空子集** $D_i$ **，将** $D_i$ **中实例数最大的类作为标记，构建子节点**，由节点及其子节点构成树 T ，返回 T

<img src="/img/machine_learning_note.zh-cn.assets/172845431716320.png" alt="图片无法加载" />

**（6）** 对第 i 个子节点，以 $D_i$ 为训练集，以 $A-\{A_g\}$ 为特征集，递归调用 (1)~(5) ，得到子树 T ，返回 T

### C4.5

- 举例：当有一行特征为ID编号，从0~K，将会导致ID的熵为0，而ID并不与结果相关，即信息增益不适合解决特征中及其稀疏的情况
- 解决ID3问题，考虑自身熵，使用**信息增益率=信息增益/属性熵**
- 当属性有很多值时，虽然信息增益变大，但相应属性熵也会变大，所以信息增益率计算不会很大

### CART

- 使用**GINI系数**作为衡量标准
- 适用于分类和回归，本质是二叉树

### 集成学习

**分类**

- **Bagging**：并行训练多个分类器取平均，降低方差，$f(x)=\frac{1}{M}\sum_{m=1}^Mf_m(x)$，代表为随机森林

<img src="/img/machine_learning_note.zh-cn.assets/172845431716321.png" alt="图片无法加载" />

- **Boosting**：串联，从弱学习器开始加强，通过**加权**来训练，大部分情况下，**经过 boosting 得到的结果偏差更小，**$F_m(x)=F_{m-1}(x)+argmin_h\sum_{i=1}^nL(y_i,F_{m-1}(x_i)+h(x_i))$

<img src="/img/machine_learning_note.zh-cn.assets/172845431716422.png" alt="图片无法加载" />

- **Stacking**：堆叠，聚合多个分类或回归模型（KNN, SVM, RF），第一阶段得出各自结果，第二阶段用前一阶段结果训练，多个模型结果输入，用一个元模型组合结果

<img src="/img/machine_learning_note.zh-cn.assets/172845431716423.png" alt="图片无法加载" />

### 随机森林

- RF，由于决策树对数据轻微变化敏感，属于Bagging模型，由多个决策树组成
- 能处理高维，抗过拟合，可解释性强，并行化速度快，能给出哪些特征值重要
- 分别训练多个相同参数的模型，预测时将所有模型结果再进行集成
- **随机**：
  - **数据随机采样**：原始数据中进行放回抽样（取得值可能重复），构造新的训练集
  - **特征选择随机**：每个节点，选择随机子集k(<n, or $k=\sqrt n$)个特征
- **森林**：多个决策树并行放一起

<img src="/img/machine_learning_note.zh-cn.assets/172845431716424.png" alt="图片无法加载" />

✅ **投票策略**

- 软投票：各自分类器的概率值进行加权平均，要求各个分类器都有概率值
- 硬投票：直接用类别值，少数服从多数

✅ **OOB策略**

**Out of Bag**，在随机抽取的样本中，剩余的样本可以作为验证集进行验证

✅ **提升方法**

**XGBoost**

- eXtreme Gradient Boosting，极端梯度提升，属于boosting模型
- 在下一轮时，随机抽样更大概率选择前一轮预测出错的样本，每个样本都有权重

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

## 聚类算法

**无监督**问题：不存在标签，将相似的东西分到一组

### K-MEANS

**概念**

- 需指明簇的个数**K**
- 质心：均值，向量各维取平均
- 距离：用**欧几里得距离**和**余弦相似度**（先标准化）
- **优化目标**：$min\sum_{i=1}^K\sum_{x\in C_i}dist(c_i,x)^2$
- **代价函数/失真函数**：$J(c^{(1)},\cdots,c^{(m)},\mu_1,\cdots,\mu_K)=\frac{1}{m}\sum_{i=1}^m||x^{(i)}-\mu_{c^{(i)}}||^2$
- 应用举例：x轴身高，y轴体重，离散点类似线性增加，可用于分类小中大三个簇，K越多，分类越细

**工作过程**

<img src="/img/machine_learning_note.zh-cn.assets/172845431716425.png" alt="图片无法加载" />

- 优势：简单，快速，适合常规数据集
- 劣势：难确定K，复杂度与样本呈线性关系，难发现形状复杂的簇，初始化不当会导致陷入局部最优值

肘法（Elbow method）：x轴K的值，y轴代价函数值，看图像是否有斜率突变的情况

<img src="/img/machine_learning_note.zh-cn.assets/172845431716426.png" alt="图片无法加载" />

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

**结论**：

- $s_i$接近1，说明样本i聚类合理
- $s_i$接近-1，说明样本i更应该分类到其他簇
- $s_i$近似0，说明样本i在2个簇边界上

### DBSCAN

（Density-Based Spatial Clustering of Applications with Noise）

**基本概念**

- **核心点**：某个点的**密度**达到算法设定的阈值 —— r邻域内点的数量≥ 阈值 **minPts**
- $\epsilon$-邻域的距离阈值：设定的半径 **r**
- **直接密度可达：若点 p 在点 q 的 r邻域内，且 q 是核心点，则 p-q 直接密度可达**
- 密度可达：一个点的序列$q_0,q_1,\cdots,q_l$，对任意$q_i-q_{i-1}$是直接密度可达的，则称从$q_0$到$q_k$密度可达，“传播”
- **边界点**：每一个类的非核心点
- **噪声点**：不属于任何一个类簇的点，从任何一个核心点出发都密度不可达
- K-距离：给定数据集$P=\{p(i);\,i=0,1,\cdots,n\}$，p(i)到P中其他点的距离并且从小到大排序，分别为d(k)，k=1,2,3,....，称为K-距离

<img src="/img/machine_learning_note.zh-cn.assets/172845431716427.png" alt="图片无法加载" />

**工作流程**

输入：**数据集**$D$、**指定半径**$\epsilon$、**密度阈值**$MinPts$

1. 所有对象标记 unvisited
2. 随机选择一个对象p，标记为visited
3. 若 p 的$\epsilon$-邻域至少有 MinPts 个对象[a, b, c, d...]：创建新簇 C，p 加入 C 中
4. 令 N 为 p 的$\epsilon$-邻域中的对象集合，遍历[a, b, c, d...]中每个点 p' 【不断扩张的过程】：
   1. 若 p' 为unvisited，标记为visited；
   2. 若 p' 的$\epsilon$-邻域至少有 MinPts 个对象，将这些对象加入N
   3. 若 p' 不是任何簇的成员，加入 C 中
5. 输出 C （若不满足3条件，则为噪声点）
6. 接着继续找标记为unvisited的对象，重复3-5
7. 直到没有标记为unvisited的对象

**参数选择**：

- 选择半径$\epsilon$：根据K-距离找突变的点
- 选择 MinPrs：K-距离中的 k 值，一般取小一点

优点：擅长找离群点，可分任意形状

劣势：高维数据困难，参数难以选择，效率低

## 异常检测

- Anomaly Detection，非线性检测，无监督学习
- 对应的数据特征空间维度为 $n$，样本数为 $m$

1️⃣ **数据集**

- $\{x^{(1)},x^{(2)},\cdots,x^{(m)}\}$
- 每个样本$x^{(i)}$有 m 个特征$x^{(i)}=[x_1^{(i)},x_2^{(i)},\cdots,x_n^{(i)}]$，检测$x_{test}$是否异常
- 以二维即2个特征为例，x轴为x1，y轴为x2，可作图观察点分布

2️⃣ **核心方法**

**密度估计**：越内部概率越高，越外圈概率越低，计算$x_{test}$概率

<img src="/img/machine_learning_note.zh-cn.assets/172845431716428.png" alt="图片无法加载" />

> **单变量高斯分布**（Gaussian Distribution）

$p(x)=\frac{1}{\sqrt{2\pi}\sigma}e^{\frac{-(x-\mu)^2}{2\sigma^2}}$，轴线与均值 $\mu$ 有关，宽度与方差 $\sigma$ 有关

<img src="/img/machine_learning_note.zh-cn.assets/172845431716429.png" alt="图片无法加载" />

> 多特征联合概率密度模型

假设各个特征独立，则联合密度为：$p(x)=\prod_{j=1}^np(x_j;\mu_j,\sigma^2_j)$

**算法实现**

✅ 训练阶段，只用正常样本

1. 选择 n 个特征
2. 估计参数

   - $\mu_j=\frac{1}{m}\sum_{i=1}^mx_j^{(i)}$

   - $\sigma_j^2=\frac{1}{m}\sum(x_j^{(i)}-\mu_j)^2$

✅ 测试阶段

1. 计算待测点概率密度
   - $p(x)=\prod_{j=1}^np(x_j;\mu_j,\sigma^2_j)=\prod_{j=1}^n\frac{1}{\sqrt{2\pi}\sigma_j}e^{\frac{-(x_j-\mu_j)^2}{2\sigma_j^2}}$

2. 判断是否异常：$p(x)\lt \varepsilon$ 则异常

**评估方法**

- 虽然是无监督学习，但为了选择合适$\varepsilon$，借助交叉验证集
- 与有监督的区别：异常检测中的异常不断变化可能与训练集中不一致，有监督学习区别的垃圾邮件大多与训练集中相似

数据划分：

> 训练集：测试正常数据，估计均值和方差
>
> 交叉验证集：加入少许异常数据，帮助设置阈值
>
> 测试集：也有少许异常数据测试来公平判断系统

评估指标：混淆矩阵、准确率、召回率、F1值等

**特征选择**

- 非高斯特征可通过计算转化为高斯性质：$log(x+c)$，$x^{\frac{1}{c}}$，特征图的x轴为索引，y轴为特征的值
- 添加特征可以使用原有特征的比率来使得更容易进行异常检测

## 推荐系统

- 根据用户的历史行为和物品特征，预测用户可能喜欢的内容
  - 协同过滤 Collaborative Filtering（CF）
  - 内容过滤 Content-based Filtering（CBF）

**场景**

a - d 四个人对 m1 - m5 电影评分数据

| Movie | a    | b    | c    | d    | x1(浪漫电影) | x2(动作电影) |
| ----- | ---- | ---- | ---- | ---- | ------------ | ------------ |
| m1    | 5    | 5    | 0    | 0    | 0.9          | 0            |
| m2    | 5    | ?    | ?    | 0    | 1.0          | 0.01         |
| m3    | ?    | 4    | 0    | ?    | 0.99         | 0            |
| m4    | 0    | 0    | 5    | 4    | 0.1          | 1.0          |
| m5    | 0    | 0    | 5    | ?    | 0            | 0.9          |

- $n_u$：人数
- $n_m$：电影数
- $r(i,j)=1/0$：用户 j 是否给电影 i 打分
- $y^{(i,j)}$：用户 j 对 i 的打分值
- $w^{(j)},b^{(j)}$：用户 j 的参数
- $x^{(i)}$：电影 i 的特征向量
- 已知  w 和 b，对 a(j) 预测第 3(i) 个电影：$w^{(j)}\cdot x^{(i)}+b^{(j)}=[5\quad 0]\cdot \begin{bmatrix}0.99\\\ 0\end{bmatrix}+0=4.95$

**成本函数**

对单个用户 j

<img src="/img/machine_learning_note.zh-cn.assets/172845431716430.png" alt="图片无法加载" />

对所有用户

<img src="/img/machine_learning_note.zh-cn.assets/172845431716431.png" alt="图片无法加载" />

假设已知参数w和b，x1和x2特征值未知，可以通过成本函数推测特征值

<img src="/img/machine_learning_note.zh-cn.assets/172845431716432.png" alt="图片无法加载" />

<img src="/img/machine_learning_note.zh-cn.assets/172845431716433.png" alt="图片无法加载" />

### 协同过滤

- Collaborative filtering，基于部分用户已打分情况推荐相似电影
- **多个用户合作评价同一部电影，可以猜测什么是适合该电影的功能，以及猜测尚未评价同一部电影的用户如何评价**

上述成本函数结合：

<img src="/img/machine_learning_note.zh-cn.assets/172845431716434.png" alt="图片无法加载" />

**梯度下降**变化

- $w_i^{(j)}=w_i^{(j)}-\alpha\frac{\partial}{\partial w_i^{(j)}}J(w,b,x)$
- $b^{(j)}=b^{(j)}-\alpha\frac{\partial}{\partial b^{(j)}}J(w,b,x)$
- $x_k^{(i)}=x_k^{(i)}-\alpha\frac{\partial}{\partial x_k^{(i)}}J(w,b,x)$，x也为参数

协同过滤算法可以通过逻辑回归运用到二进制标签应用

**均值归一化**

将评分都减去均值$\mu$，获取新的评分矩阵

对于用户 j，对于电影 i 预测：$w^{(j)}\cdot x^{(i)}+b^{(j)}+\mu_i$，对于新用户，此时参数均为0，则预测的值为均值而不是0，更合理

寻找**相关项：寻找**$x^{(k)}$相似于$x^{(i)}$，求$\sum_{l=1}^n(x_l^{(k)}-x_l^{(i)})^2$

**限制**：冷启动问题，新项很少用户点评

### 内容过滤

- Content-based Filtering，基于用户和项的特征寻找合适匹配推荐
- 用户 j 特征$X_u^{(j)}$，电影 i 特征$X_m^{(i)}$，两个向量包含的**评分数字**可能不同，看是否 i 和 j 能匹配
- 预测 j 对 i 的评分由 wx+b 更改为 $V_u^{(j)}\cdot V_m^{(i)}$，分别从$X_u^{(j)}$和$X_m^{(i)}$计算得来，且包含评分数字相同

**神经网络架构**

<img src="/img/machine_learning_note.zh-cn.assets/172845431716435.png" alt="图片无法加载" />

$g(V_u^{(j)}\cdot V_m^{(i)})$预测用户 j 对电影 i 即$y^{(i,j)}=1$的概率

- 32位向量$v_u^{(j)}$描述用户 j 的特征$x_u^{(j)}$
- 32位向量$v_m^{(i)}$描述电影 i 的特征$x_m^{(i)}$

**成本函数**

<img src="/img/machine_learning_note.zh-cn.assets/172845431716536.png" alt="图片无法加载" />

推荐类似 i 的电影：$small\,\,||V_m^{(k)}-V_m^{(i)}||^2$

大数据集高效推荐：

- **检索**（Retrieval）：生成大量合理项目候选并去除重复项

- **排名**（Ranking）：将候选使用上述神经网络框架预测分数并排名

## SVM算法

- Support Vector Machine，支持向量机算法，有监督学习，二分类问题
- 目标：解决特征数据本身难分，在样本空间中找到一条**最优分类超平面（决策边界）**，使得不同类别的数据点被最大间隔（margin）地分开
- 选出离边界点最远的，分类面离支持点越远，泛化能力越好

<img src="/img/machine_learning_note.zh-cn.assets/172845431716537.png" alt="图片无法加载" />

**公式推导**

**计算距离**

<img src="/img/machine_learning_note.zh-cn.assets/172845431716538.png" alt="图片无法加载" />

**数据标签**

- 数据集：$(X_1,Y_1),(X_2,Y_2),\cdots,(X_n,Y_n)$
  - Y为样本类别，X为正例Y=+1；X为负例Y=-1
- **决策方程**：$y(x)=w^T\Phi(x)+b$，$\Phi(x)$对数据做了变换，使$x$线性可分
  - 假设超平面：$w^T\Phi(x)+b=0$
  - $\begin{cases}y(x_i)\gt 0\Leftrightarrow y_i=+1\\\ y(x_i)\lt 0\Leftrightarrow y_i=-1\end{cases}\quad\Rightarrow\quad y_i\cdot y(x_i)\gt 0$
  

**优化目标**

1. **点到直线的距离**化简：$\frac{y_i\cdot(w^T\cdot \Phi(x_i)+b)}{||w||}$
2. 目标：找到一条线（w和b），使得离该线最近的点能够最远，最大化间隔
   - $\mathop{arg\,max}\limits_{w,b} \{\frac{1}{||w||}\mathop{min}\limits_{i}[y_i\cdot(w^T\cdot\Phi(x_i)+b]\}$
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

**软间隔**

- soft-margin，解决数据不是线性可分情况，容忍少数点被错误分类

- 有时候数据中存在噪音点，对其进行考虑时会对决策线产生影响，需要要求放松一点

引入松弛因子 $\xi_i$ ：$y_i(w\cdot x_i+b)\ge 1-\xi_i$

则新的目标函数：$min\frac{1}{2}||w||^2+C\sum_{i=1}^n\xi_i$，使得函数越小，$C$是惩罚系数

- $C$ 很大时，意味分类严格
- $C$ 很小时，意味有更大错误容忍

**核函数**

- 线性不可分时，将数据从低维映射到高维特征空间可能更容易分，高维映射计算开销大，用核函数替代点积运算$K(x_i, x_j) = \Phi(x_i)^T \Phi(x_j)$

- $\Phi(x)$，将低维中决策边界可能复杂过饱和的情况变换为高维中更简单决策边界的情况

<img src="/img/machine_learning_note.zh-cn.assets/172845431716539.png" alt="图片无法加载" />

**常见核函数**

| 核函数名                          | 表达式                                                    |
| --------------------------------- | --------------------------------------------------------- |
| 线性核                            | $K(x, y) = x^T y$                                         |
| 多项式核                          | $K(x, y) = (x^T y + c)^d$                                 |
| RBF（高斯）核：处理任意非线性问题 | $K(x, y) = \exp\left(-\frac{|x - y|^2}{2\sigma^2}\right)$ |
| Sigmoid核                         | $K(x, y) = \tanh(\kappa x^T y + c)$                       |

<img src="/img/machine_learning_note.zh-cn.assets/172845431716540.png" alt="图片无法加载" />

## 朴素贝叶斯

贝叶斯公式：$P(A|B)=\frac{P(B|A)P(A)}{P(B)}$

### 邮件过滤

- 判定邮件D是否为垃圾邮件，h+表示垃圾邮件，h-表示正常邮件

$\begin{cases}P(h+|D)=\frac{P(h+)P(D|h+)}{P(D)}\\\ P(h-|D)=\frac{P(h-)P(D|h-)}{P(D)}\end{cases}$，P(h+)和P(h-)为先验概率

- D由N个单词组成，所以有$P(D|h+)=P(d_1,d_2,\cdots,d_n|h+)=P(d_1|h+)\cdot P(d_2|d_1,h+)\cdot P(d_3|d_2,d_1,h+)\cdots$
- 朴素贝叶斯假设特征之间是独立的，则化简为$P(d_1|h+)\cdot P(d_2|h+)\cdot P(d_3|h+)\cdots$，则只要统计$d_i$这个单词在垃圾邮件中出现的概率即可

