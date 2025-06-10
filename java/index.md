# Java



## 概述

```java
public class Xxxx {
	public static void main(String[] args) {
```

**概念**

- `javac`编译，`java`执行，`javap xxx.class`反编译，`jre`：核心类库 + `jvm`
- 大小写敏感

### 工具

**IDEA**

`command + alt + ←`：回退

`command + D`：复制当前行到后一行

`ctrl + H`：查看实现类父子关系

结构：**项目 - 模块 - 包 - 类**

## 基本语法

**注释**

```java
/**
* meaning
* @param arg1 mean
*/
```

&& 与 & 的区别：左侧为 false 右侧不再执行

### 变量

- 成员变量：类中、方法体外，创建对象时实例化，可被类中方法访问
- 类变量：类中、方法体外，必须为static类型
- 局部变量：栈中分配，声明时必须初始化，不可用访问修饰符

### static

静态，修饰成员变量和成员方法

> static修饰，静态变量：类变量，只存一份，被类的全部对象共享，通过类访问，`classname.var`
>
> 无static修饰，实例变量：对象的变量，属于每个对象

<img src="/img/java.zh-cn.assets/image-20250527190020442.png" alt="图片无法加载" />

>  static 修饰，静态方法：属于类， classname.func，设计工具类，可private私有化构造函数
>
> 无static修饰，实例方法，属于对象

- 静态方法可直接访问静态成员，不可直接访问实例成员
- 实例方法既可访问静态成员也可访问实例成员
- 实例方法可出现`this`，静态方法不可出现`this`关键字

## 数据结构

### 数组

```java
double[] xxx = new double[8]; // 动态

String[] name = new String[]{"aa", "bb"};
String[] name = {"a", "b"};
String name[] = {"a", "b"};

name.length; // 长度
Arrays.toString(xxx); // 打印数组
```

### 二维数组

```java
// 动态
int[][] arr = new int[][]{ {x,x}, {x, x}};
int[][] arr = new int[2][2]; // 2 可换为变量

//静态
String[][] s = {
	{"a", "b"},
	{"c", "d"},
};
```

### 字符串

- String，对象类型

```java
String s = "aaa";

String ss = new String("abc");

char[] chars = {'a', 'b'};
String sss = new String(chars);

byte[] bytes = {97, 98};
String sss = new String(bytes);
```

**区别**

- `""`方式的字符串对象，存储在字符串常量池，相同内容只存一份

- `new`方式的字符串对象，`new`一次产生一个新对象在堆内存中

**方法**

```java
s.length(); // 返回大小
s.equals("xxx"); // 判断是否相等
s.substring(0, 2); // 返回[0, 2)子串
s.charAt(index); // 返回索引对应的字符
s.startsWith("xx"); // 以xx开始
```

**字符串拼接**，`+`号性能差，`String`为不可变对象，`+`后一直生成新对象

```java
// 更高效的字符串拼接
StringBuilder sb = new StringBuilder(); // 可变内容容器
sb.append("xx").append('a'); // 支持链式编程
String s = sb.toString();
```



### 集合

容器，大小可变，泛型类

#### Collection

单列集合

接口：`Collection<E>`

实现类：

- `List<E>`：有序、可重复、有索引
  - `ArrayList<E>`
  - `LinkedList<E>`
- `Set<E>`：无序、不重复、无索引
  - `HashSet<E>`：无序、不重复、无索引
    - `LinkedHashSet<E>`：有序、不重复、无索引
  - `TreeSet<E>`：大小默认升序排序、不重复、无索引

**Collection方法**

```java
c.add("xx");
c.size();
c.remove("aa");
c.isEmpty(); // 是否为空
c.clear(); // 清空集合
c.contains(obj); // 是否存在某个数据

Object[] arr = c.toArray(); // 集合转换成数组
String[] arr2 = c.toArray(String[]::new); // 集合转换成字符数组
```

**遍历方式**

迭代器 Iterator 遍历集合

```java
Iterator<E> iterator() // 返回集中中迭代器对象，默认指向当前集合第一个元素
Iterator<String> it = xx.iterator();

// 方法
hasNext() // 当前位置是否有元素存在
next() // 获取当前位置元素，同时迭代器对象指向下一个元素处
it.remove(xxx); // 防止并发修改异常
```

遍历

```java
// 迭代器遍历
while(it.hasNext()){
	String e = it.next();
}

// 下列遍历无法解决并发修改异常问题
// 增强 for 循环 java5引入
for(String name : names) {
	xxx
}

// Lambda 表达式
names.forEach(new Consumer<String>() {
	@Override
	public void accept(String s) {
		System.out.println(s);
	}
};

// 简化
names.forEach(s -> System.out.println(s));
// 简化
names.forEach(System.out::println);
```

并发修改异常：在遍历同时使用增删查改

##### List

```java
add(index, "xx")
add("xxx")
remove // 返回删除的数据
get
set    // 返回修改前的数据
```

**ArrayList**：数组，查询速度快，增删数据效率低

- 第一次添加数据开始扩容，扩成10，后面再次扩容为1.5倍

```java
ArrayList<String> list = new ArrayList<>();

list.add("xxx");// 添加数据
list.get(index); // 取数据
list.size(); // 大小
list.remove(index); // 索引删除
list.remove("xx"); // 直接删除
list.set(index, "xxx"); // 修改
list.subList(start_index, end_index); // 截取
```

**LinkedList** ：双向链表，有前后结点地址，有头节点和尾节点，查询慢，增删相对快，可实现对列和栈

```java
addFirst() // 列表开头插入指定元素
addLast() // 元素追加列表末尾
getFirst() // 第一个元素
getLast() // 最后一个元素
removeFirst() // 删除并返回第一个元素
removeLast() // 删除并返回最后一个元素

// 栈
push(); 
pop();
```

##### Set

**HashSet**

- 每个对象都有一个哈希值（int类型随机值），`hashCode()` ，哈希表实现：数组+链表+红黑树
- 默认16长度数组，名为table，默认加载因子0.75，超过16*0.75时扩容，同位置用链表连接，新元素在旧元素后
- 链表长度超过8，数组长度≥64时，自动将链表转为红黑树

```java
Set<String> set = new HashSet<>();

set.add("xx");
```

`HashSet`无法对对象去重，`new`的对象地址不同，

实现自动去重，需重写对象的`hashCode()`和`equals()`方法

```java
@Override
public int hashCode() {
    return Objects.hash(field1, field2, ...); // field为对象字段
}

@Override
public boolean equals(Object o) {
    if (this == 0) return true;
    if (o == null || getClass() != o.getClass()) return false;
    Classname cn = (Classname) o;
    return field1 == cn.field1 && Objects.equals(field2, cn.field2);
    // 分别为 int 比较和 String 比较
```

**LinkedHashSet**

哈希表（数组、链表、红黑树），每个元素额外多一个双链表机制记录前后元素位置

**TreeSet**

基于红黑树排序，对象需自定义排序规则

```java
// 对象类实现一个Comparable比较接口，重写compareTo方法，指定大小比较规则
implements Comparable<Classname> {
    @Override
    public int compareTo(Classname o) { // 规定： >+, <-, =0
        // t2.compareTo(t1)
        // t2 == this
        // t1 == o
        return this.getAttr() - o.getAttr(); // 升序
    }
}

// public TreeSet (Comparator c) 集合自带比较器Comparator对象，指定比较规则
```

**Collections工具类**

操作集合的工具类

```java
List<String> list = new ArrayList<>();
Collections.addAll(list, "xx", "bb"); // 可变参数
Collections.shuffle(list); // 打乱顺序
Collections.sort(List<T> list, Comparator<? super T> c) // 排序
```

#### Map

双列集合

- 键值对集合，键不可重复，值可重复
- `Map<K, V>`，键值对均可为null

```java
Map<String, Integer> map = new HashMap<>();
// 常用方法
map.put("a", 1); // 加入内容，返回被覆盖数据
map.get("a"); // 根据键取值
map.containsKey(key);
map.containsValue(value);
map.remove(key);
map.clear();
map.isEmpty();
// 获取所有键集合
Set<String> keys = map.keySet();
// 获取所有值集合
Collection<Integer> values = map.values();
```

**遍历**

```java
Set<String> keys = map.keySet();
for(String key : keys) {
    Integer value = map.get(key);
}

// 利用 Set<Map.Entry<K, V>> entrySet()
Set<Map.Entry<String, Double>> entries = map.entrySet();
for(Map.Entry<String, Double> entry : entries) {
    String key = entry.getKey();
    Double value = entry.getValue();;
}

map.forEach((k, v) -> System.out.println(k + "=" + v);
```

## 类

> 堆中存对象和类地址，类及类方法在方法区中
>
> `this`用于在方法中拿到当前对象，解决变量名称冲突

```java
public class Object {
	private type name;
	
	// public 修饰的 get 和 set 方法
	public void setName(xx){};
	
	// 构造函数 创建对象会调用
	public Object(xxx){ // 可有参数, 有参存在后无参需要自己构造
		name = xxx;
	}
	
	public type func(){
		xxx
	}
}

Object ob = new Object();
ob.name = "xxx";
ob.func();
```

### 继承

```java
public class Son extends Dad {}
```

- 子类能继承父类非私有成员，优先访问自己类，`super.xxx`来指定访问父类的变量和方法
- 所有类均为`Object`类的子类

**权限修饰符**

- private：只能本类访问，类和接口不能声明为private，不能被子类继承
- 缺省：本类、同一个包中的类可访问
- protected：本类、同一个包中的类、子孙类中可访问

**方法重写**

- 方法名称、参数列表一样，覆盖
- 子类重写父类方法时，访问权限必须大于或等于父类方法权限
- 私有方法、静态方法不能被重写

```java
@Override
public void xx() {}
```

重写`Object`类的`toString`方法

- 子类构造器先调用父类构造器，再执行自己
- 默认情况下，子类全部构造器第一行代码都是 `super()`，会调用父类的无参数构造器
- 若父类没有无参构造器需要在子类构造器第一行手写 `super(…)`，指定调用父类的有参构造器

`this` 调用兄弟构造器：首行

```java
this(xxx, xxx, xxx, "xxx");
```

### 多态

**成员函数运行子类的，成员变量看父类的**

- 父类引用子类对象
- 父类类型变量作为参数，可接收子类对象
- 多态无法调用子类独有功能 → 判断后强转

```java
Animal d = new Dog();
Animal w = new Wolf(); // 子类
```

**类型转换**

- 自动类型转换：Person p = new Teacher();

- 强制类型转换：Teacher t = (Teacher) p;

  - 判断真实类型后再强转：

  ```java
  a1 instanceof Student
  ```

`lombok`自动添加构造函数和get，set函数

```java
import lombok.Data;

@Data
@AllArgsConstructor // 有参构造
@NoArgsConstructor  // 无参构造
```

**final** 修饰类、方法、变量

- 最终类：不能被继承
- 最终方法：不能被重写
- 该变量有且仅能被赋值一次，final + static 系统配置变量
- 修饰引用类型的变量，变量存储的地址不能被改变，所指向对象内容可变

**代码编译后，常量被宏替换，替换为字面量**

### 实体类

- `javabean`，需提供无参数构造器

- 类中成员变量全私有，提供 `public` 修饰的 `getter/setter`方法

- 实体类对象只负责数据存取，对数据的业务处理交给其他类的对象完成（`XxxOperator`）

### 单例类

该类只能创建一个对象

```java
// 饿汉式
public class A {
	// 定义一个静态变量，用于基本本类的一个唯一对象
	private static A a = new A();
	
	// 私有化构造器
	private A() {
	}
	
	// 提供公开静态方法，返回该类唯一对象
	public static A getInstance() {
		return a;
	}
}

// 懒汉式 用对象时才创建
public class B {
	// 定义一个类变量存储对象
	private static B b;
	
	private B() {
	}
	
	// 提供一个类方法返回类的一个对象
	public static B getObject() {
		if (b == null){
			b = new B();
		}
		return b;
	}
}
```

### 枚举类

- 最终类，不可被继承，构造器私有

```java
public enum A {
    X, Y, Z; // 只能写枚举类的对象名称，且用逗号隔开
    // 均为常量，每个对应一个对象
    ...
}

A a1 = A.X;
// a1.name() 名字
// a1.ordinal() 索引
```

### 抽象类

可修饰类和成员方法

```java
public abstract class A{
    public substract void func(); // 只能有方法签名，无方法体
}
```

- 抽象类中不一定有抽象方法，有抽象方法一定是抽象类
- 抽象类不能创建对象，仅作为父类被子类继承并实现，重写所有抽象方法，支持多态

**抽象类**：建议使用 final 修饰模板方法，父类定义抽象方法，子类实现抽象方法

### 内部类

定义在类的内部

1️⃣ **成员内部类**

- 可以访问外部类静态成员，静态方法，实例成员
- 可以获取当前寄生的外部类对象：`外部类名.this`

```java
// 无 static 修饰，属于外部类对象持有
public class Outer {
	public class Inner {
		xx
	}
}

Outer.Inter oi = new Outer().new Inner();
```

2️⃣ **静态内部类**

有 static 修饰，属于外部类自己持有，可访问外部类的静态成员

```java
public class Outer {
	public static class Inner {
	}
}

Outer.Inner in = new Outer.Inner();
```

3️⃣ **匿名内部类**

本质是一个子类，立即创建一个子类对象

```java
new Animal(args...){
	@Override
	public void cry() {
	}
};
```

匿名类实现排序

```java
Arrays.sort(T[] a, Comparator<T> c);

new Comparator<T>() {
	@Override
	public int compare(T o1, T o2) {
		// +: o1 > o2, -: o1 < o2, 0: o1 = o2
		...
	}
}
```

**简化**：函数式编程，Lambda只能简化函数式接口的匿名内部类

```java
@FunctionalInterface // 声明函数式接口：只有一个抽象方法的接口
interface Swim {
	void swimming();
}

// lambda 重写swimming了, 进一步呢简化，参数类型也可省略，只有一个参数,()也可省略，一行代码则省略;和return
Swim s = (args) -> {
	xxxx
};
s.swimming(args);
```

简化 Lambda：方法引用

**静态方法引用：`类名::静态方法`，Lambda表达式只调用一个静态方法， →前后参数形式一致**

```java
 Arrasy.sort(Students, (o1, o2) -> o1.getAge() - o2.getAge());
 
 // compareByAge(o1, o2)为静态方法
 Arrays.sort(Students, Student::compareByAge);
```

**实例方法引用：`对象名::实例方法` ，Lambda表达式只通过对象名称调用实例方法，→前后参数一致**

```java
Student t = new Student();
Arrays.sort(Students, (o1, o2) -> t.compareH(o1, o2));

// 简化
Arrays.sort(Students, t::compareH);
```

**特定类型方法引用：**

```java
Arrays.sort(names, (o1, o2) -> o1.comparexxx(o2));
// 简化，o1和o2为特定类型String
Arrays.sort(names, String::comparexxx);
```

**构造器引用：`类名::new`**

### 包装类

byte-Byte, short-Short, int-Integer, long-Long, char-Character, float-Float, double-Double, boolean-Boolean

```java
// 手工包装
Integer it = Integer.valueOf(100); // 130超过127边界，会new新的对象

// 自动装箱 
Integer it = 100;

// 自动拆箱
int i = it;
```

**功能**

基本类型转字符串

```java
int j = 23;
String rs = Integer.toString(j);

// 转换为字符串
String a = j + ""; // 也可
```

**字符串数值转换为对应基本数据类型**

```java
String str = "91";
int i = Integer.parseInt(str);
int i = Integer.valueOf(str); // 均可
```

## 基本操作

**随机数**

```java
Random r = new Random();
r.nextInt(100) + 1; // 1-100

Math.random() // 返回[0, 1)的随机小数
```

**代码块**

静态代码块：`static{}`，类加载时优先自动执行，只会执行一次，可完成类及静态资源的初始化

实例代码块：`{}`，创建对象时执行，在构造器前执行，对实例变量初始化

**输入输出**

```java
Scanner sc = new Scanner(System.in);
if(sc.hasNext()) {
	String xx = sc.next();
}
sc.close()
```

**时间**

```java
long start = System.currentTimeMillis(); // 此刻时间毫秒值

LocalDateTime now = new LocalDateTime.now(); // 可直接输出
now.getYear();
now.getDayOfYear();
// 格式化
DataTimeFormatter dtf = DataTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss EEE a");
String res = dtf.format(now);
```

**字符集**

```java
// 编码
String name = "fewio";
byte[] bytes = name.getBytes(); // UTF-8编码
Arrays.toString(bytes);

// 解码
String name2 = new String(bytes, "GBK");
```

## 高级操作

### 异常

```java
Java.lang.Throwable
- Error: 系统级别错误
- Exception: 异常
	- RuntimeException 运行时异常，编译不出错，运行时出错
	- other
	编译时异常，编译报错
```

**处理异常**

```java
public static void xx() throws ParseException { // 所有异常，直接throws Exception
	xxx
	throw new ParseException();
}

try {
	xxx
} catch (ParseException e) {
	// throw new RuntimeException(e);
	e.printStackTrace(); // 打印异常信息
}finally{
  xxx
}
```

**自定义异常**

```java
public class XException extends Exception { // RuntimeException 运行时异常   
	// 无参有参构造器
	public XException(String message){
		super(message);
	}
}

if(xx){
	throw new XException("wrong info");
}
```

### 接口

- 接口不能创建对象
- 无构造函数，方法只能被类实现，extends继承接口
- 类要实现接口中所有方法，否则声明为抽象类

```java
// JDK 8 以前
public interface interfacename {
    // 可省略 public final static 公开
    // 成员变量(常量)
    // 成员方法(抽象方法) void func();
}

// JDK 8 以后
public interface A {
    // 默认方法，默认加上public，只能使用接口的实现类对象调用
    default void test1(){
        ...
    }

    // 私有方法，JDK 9 以后, 使用接口中其他实例方法来调用
    private void test2() {
        ...
    }

    // 静态方法，默认加上public，只能使用当前接口名调用
    static void test3() {
        ...
    }
}
```

- 接口是用来被类实现的，实现接口的类为实现类，一个类可同时实现多个接口，在其中重写抽象方法

```java
public class impcla implements interf1, interf2, interf3 {
interfacename xx = new impcla();
xx.func();
```

- 一个接口可以同时继承多个接口，需要被继承接口函数签名不冲突
- 一个类继承父类，同时实现接口，父类中和接口有同名方法，优先使用父类方法，使用接口需要：子类自定义新函数中使用`接口名.super.func()`
- 一个类实现多个接口，存在同名默认方法，可以重写方法防止冲突

### 泛型

泛型类、泛型接口、泛型方法

- 提供了在编译阶段约束所能操作的数据类型，自动检查

```java
ArrayList<String> list = new ArrayList<String>();

public class ArrayList<E> {
	...
}
```

**泛型类**

```java
public class ArrayList<E> { // 大写:ETKV 
	void func(E e){
		xxx;
	}
}
```

**泛型接口**

```java
public interface A<E>{
	
}

public class X implements A<E> {
}
```

**泛型方法**

```java
public static <T> void test(T t) {
	//定义方法时同时自定义声明的T
}
```

通配符：`?` 使用泛型时代表一切类型，上下限

泛型上限：`? extends C:` 能接收的必须是C或其子类

泛型下限：`? super C:` 能接收的必须是C或其父类

```java
public static void go(ArrayList<? extends XXX> xx) {
}
```

- 泛型不支持基本数据类型，只支持对象/引用数据类型，Object类t，包装类解决

### Stream流

- `java.util.stream.*`，操作集合或数组

```java
List<String> list = new ArrayList<>();
// 过滤并收集
List<String> newlist = list.stream().filter(s -> s.startsWith("xx")).filter(s -> s.length() == 3).collect(Collectors.toList());
```

获取集合的Stream流

```java
Collection<String> list = new ArrayList<>();
Stream<String> s = list.stream();
```

获取数组的Stream流

```java
String[] names = {"a", "b"};
Stream<String> s = Arrays.stream(names);

Stream<String> s1 = Stream.of(names);
```

**流方法**，中间方法调用完方法后会返回新的流

```java
s.filter() // 过滤
.sorted() // 排序
.sorted((s1, s2) -> Double.compare(s2. s1)) // 重写规则排序
.limit(2) // 只要前2个
.skip(2) // 跳过前2个
.distinct() // 去重
.map(s -> "加工后: " + (s + 10)).forEach(System.out::println); // 映射为新数据放入流上
.concat(stream1, stream2) // 合并两个流为一个流
```

**流获取结果**

```java
.forEach(System.out::println) // 遍历输出
.count() // 统计流中的个数

Otional<Teacher> max = teachers.stream().max((t1, t2) -> Double.compare(t1.getSalary(), t2.getSalary()));
Teacher maxTeacher = max.get(); // 获取薪水最高的老师
Teacher minTeacher = min.get();
```

**收集**：结果转回集合或数组中，流只能收集一次

```java
List<String> list1 = stream1.collect(Collectors.toList());
Set<String> set1 = stream1.collect(Collectors.toSet());
Object[] array = stream1.toArray();

Map<String, Double> map = stream1.collect(Collectors.toMap(Teacher::getName, Teacher::getSalary));
```

数组到集合中：

```java
Set<String> set2 = newHashSet<>();
set2.addAll(list1);
```

函数式接口

- 创建一个匿名内部类，实现该接口
- 大括号中需要重写apply方法

```java
new Function<Type1, Type2>() { xxx }
// 该接口接受一个类型为Type1的输入参数，返回一个类型为Type2的结果
```

可变参数：形参中只能有一个，且放在形参列表最后

```java
public static void x(int...nums){
    nums.length;
}
```

### IO流

实际对文件中数据进行读写，不适合处理中文字符

#### 字节流

FileInputStream，文件字节输入流，磁盘文件数据到内存中

```java
InputStream is = FileInputStream("xx"); // 参数也可为 File 对象

// int b;
// while((b = is.read()) != -1) { // 每次读取一个字节
// 	System.out.println((char) b);
// }

// 无法避免中文截断导致乱码
byte[] buffer = new byte[1024];
int len;
while((len = is.read(buffer)) != -1) {
	String str = new String(buffer); // 字节数组转换为字符串输出
}

// 一次读完文件中所有字节, 适用于小文件
byte[] bytes = is.readAllBytes();
String rs = new String(bytes);
```

FileOutputStream，内存写到文件中

```java
OutputStream os = FileOutputStream("xx", true); // true表示追加数据, 不覆盖
os.write('s');
os.write(97);

// 写入一个字节数组
byte[] bytes = "foewifjow\\r\\n".getBytes();
os.write(bytes);

// 写入一个字节数组一部分
os.write(bytes, 0, 3); // 偏移0处，长度为3

os.close(); // 关闭流
```

**资源释放**

```java
try {
	...
} catch (IOException e) {
	e.printStackTrace();
} finally {
	...
	// 无论 try 中程序是否正常执行，最终均会执行finally区，除非JVM终止
}
```

**try-with-resource**

```java
// try-with-resource 更实用
try(// 只能放置资源对象，用完会自动调用close函数关闭
	InputStream fis = new FileInputStream(srcPath);
	OutputStream fos = new FileOutputStream(destPath);
) {
		xxxx
} catch (Exception e {
		e.printStackTrace();
}
```

资源一般指最终实现了AutoCloseable接口

<img src="/img/java.zh-cn.assets/image-20250527202528146.png" alt="图片无法加载" />

#### 字符流

适合中文字符

FileReader，文件字符输入流，文件数据以字符形式读入到内存

```java
// 返回读取多少字符
Reader fr = new FileReader("xx");

char[] chs = new char[3];
int len;
while((len = fr.read(chs)) != -1){
	String str = new String(chs, 0, len); // 0:offset
}
```

FileWriter，文件字符输出流，内存数据字符形式写出文件中

- 写出数据后，必须刷新流或关闭流，数据才生效

```java
Writer fw = new FileWriter("xx", true); // true 追加

fw.write('a'); // 写一个字符
fw.write("aa"); // 写一个字符串
fw.write("java".toCharArray()); // 写一个字符数组
fw.write("few", 1, 2); // offset:1, len:2

fw.flush(); // 数据全部写出去
```

#### 缓冲流

- 为提高原始字节字符流性能
- BufferedInputStream, BufferedOutputStream, BufferedReader, BufferedWriter
- 缓冲字节输入流、缓冲字节输出流、缓冲字符输入流、缓冲字符输出流

缓冲流自带8KB缓冲池

```java
// 把低级字节流包装成高级流
InputStream fis = new FileInputStream(path);
InputStream bis = new BufferedInputStream(fis);

// 把低级字符流包装成高级流，缓冲字符输入流提供新方法 readLine()
Reader fr = new FileReader(path);
BufferedReader br = new BufferedReader(fr);

String line;
while((line = br.readLine()) != null) {
	System.out.println(line);
}

// 缓冲字符输出流提供新方法换行 newLine()
bw.newLine();
```

#### 字符输入转换流

- 继承自字符输入流，解决不同编码乱码问题

```java
InputStream is = new FIleInputStream("xx");
Reader isr = new InputStreamReader(is, "GBK");
```

#### 打印流

继承自字节输出流和字符输出流，实现打印啥就是啥

```java
PrintStream ps = new PrintStream("aa");
ps.println(97);
ps.println('a');
ps.println(true); // 打印true
```

#### 数据流

DataInputStream，DataOutputStream，允许把数据和其他类型一并写出去

```java
DataOutputStream dos = new DataOutputStream(new FileOutputStream("a"));

dos.writeByte(34);
dos.writeUTF("你好");
dos.writeInt(12323);
dos.writeDouble(9.9);

DataInputStream dis = new DataInputStream(new FileInputStream("aa"));
dis.readByte();
dis.readUTF(); //...
```

### File

- `File`: `java.io`包下的类，操作文件本身
- 相对路径从工程下项目文件找

```java
File f = new File("path");
f.length(); // 字节个数
f.getName(); // 文件名字
f.isFile(); // 是否是文件
f.isDirectory(); // 是否是文件夹

f.exists(); // 判断是否存在
f.createNewFile(); // 创建文件
f.mkdir(); // 创建文件夹，只创建一级
f.mkdirs(); // 创建多级文件夹
f.delete(); // 删除文件及空文件夹，返回是否成功，删除不进入回收站

String[] names = f.list(); // 获取当前目录下所有一级文件名
File[] files = f.listFiles(); // 获取当前目录下所有一级文件对象，包含隐藏文件
// 路径不存在、文件、无权限返回null
// 空文件夹，返回长度为0数组

f.getAbsoluteFile(); // 获取绝对路径
```

### 线程

**创建线程**

1. 继承Thread类

```java
// 创建线程
class zThread extends Thread {
    @Override
    public void run() {
        System.out.println("thread");
    }
}

Thread t1 = new zThread();
t1.start(); // 开启子线程，子线程和主线程同时跑
```

1. 实现Runnable接口

```java
class zRunnable implements Runnable {
    @Override
    public void run() {

    }
}

// 创建线程任务类
Runnable r = new zRunnable();
// 将线程任务对象交给线程对象处理
Thread t = new Thread(r);
t.start(); // 启动
```

1. 实现Callable接口，重写call方法，解决线程无法返回结果，Callable类型对象封装成FutureTask，线程任务对象，再交给Thread对象，start启动，get拿结果

- 主线程发现第一个线程未执行完，会由CPU等一个线程执行完后，才往下执行

```java
class zCallable implements Callable<Integer> {
    public Integer call() throws Exception {
        int sum = 0;
        for (int i = 0; i <= 100; i++){
            System.out.println(i);
            sum += i;
        }
        return sum;
    }
}

Callable<Integer> c = new zCallable();
FutureTask<Integer> f = new FutureTask<>(c); // 本身是Runnable线程任务对象
Thread t = new Thread(f);
t.start();

t.get(); // 获取返回值
```

**线程方法**

```java
Thread t = new zThread();
t.setName("aa"); // 设置线程名字
t.getName(); // 获取线程名字
System.out.println(Thread.crrentThread().getName()); // 输出当前线程名字，以区分

Thread.sleep(1000);// 线程休眠1s

// join方法 让调用这个方法的线程先执行完
t.join(); // 插队 让t线程先执行完毕，再执行主线程
```

**线程安全**

多线程操作同一个共享资源

**方法一：同步代码块**

- 把访问共享资源的核心代码上锁，每次只允许一个线程加锁后进入，执行完毕自动解锁
- 建议使用共享资源为锁对象，实例方法建议使用this，静态方法用字节码（类名.class对象）

```java
synchronized(同步锁) { // 同时执行的线程：同步锁必须是同一对象 （this）
	访问共享资源
}
```

**方法二：同步方法**

- 把访问共享资源的核心方法上锁
- 默认用锁：实例方法使用`this`，静态方法用字节码（类名.class对象）

```java
修饰符 synchronized 返回值类型 方法名称(形参列表) {
	操作共享资源代码
}
```

**方法三：Lock 锁**

- `JDK5`提供，创建锁对象加锁解锁
- `Lock`是接口，不可直接实例化，采用实现类`ReentrantLock`来创建`Lock`锁对象

```java
private final Lock lk = new ReentrantLock();
lk.lock() // 上锁
lk.unlock() // 解锁 放在finally中
```

### 线程池

- 复用线程
- `JDK5`提供接口`ExecutorService`的实现类：`ThreadPoolExecutor`自创建一个线程池对象
- 使用`Executors`线程池工具类调用方法返回不同特点的线程池对象

```java
ThreadPoolExecutor(int corePoolSize, // 核心线程数量
	int maximumPoolSize, // 最大线程数量
	long keepAliveTime, // 临时线程的存活时间，空闲多久被消灭
	TimeUnit unit, // 指定临时线程存活的时间单位，秒分时天
	Blocking Queue<Runnable> workQueue, // 线程池任务队列
	ThreadFactory threadFactory, // 线程池的线程工厂，招聘线程的 HR
	RejectedExecutionHandler handler) // 任务拒绝策略：线程都在忙，任务队列也满，新任务来如何处理
	
```

临时线程创建：新任务提交，核心线程都在忙，任务队列满，可创建临时线程

```java
ExecutorService pool = new ThreadPoolExecutor(xx, xx, xx);

pool.execute(Runnable command); // 执行任务
pool.shutdown(); // 等全部任务执行完关闭线程池
pool.shutdownNow(); // 立刻关闭线程池，停止正在执行的任务
```

任务拒绝策略

<img src="/img/java.zh-cn.assets/image-20250527203014591.png" alt="图片无法加载" />

**Callable**: `Future<T> submit(Callable<T> task); // 执行，返回未来任务对象，用于获取线程返回结果`

```java
public class myCallable implements Callable<String>{
    private int n;
    public myCallable(int n)
    {
        this.n = n;
    }

    public String call() throws Exception {
        int sum = 0;
        for(int i = 0; i <= n; i++){
            sum += i;
        }
        return  Thread.currentThread().getName() + "计算1-" + n + "的和是" + sum;
    }
}

Future<String> f1 = pool.submit(new myCallable(100));
System.out.println(f1.get());
```

**Executors创建线程池**

- 静态方法返回不同特点的线程池对象

| `public static ExecutorService newFixedThreadPool(int nThreads)` | 创建固定线程数量线程池，若某线程因执行异常结束，则线程池会补充一个新线程替代他 |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `public static ExecutorService newSingleThreadExecutor()`    | 创建只有一个线程的线程池对象，线程异常结束则补充一个新线程   |
| `public static ExecutorService newCachedThreadPool()`        | 线程数随任务增加而增加，若线程任务执行完毕，空闲60s则被回收掉 |
| `public static ScheduledExecutorService newScheduledThreadPool(int corePoolSize)` | 创建一个线程池，在给定延迟后运行任务，定期执行任务           |

### 网络编程

**InetAddress**

```java
InetAddress ip = InetAddress.getLocalHost(); // 获取本机IP对象
InetAddress ip2 = InetAddress.getByName("www.baidu.com"); // 获取IP对象

ip.getHostName(); // 域名
ip.getHostAddress(); // 优先公网IP
ip2.isReachable(5000); // 判断本机与对方主机是否相通
```

**BigDecimal** 解决浮点型运算时结果失真问题

```java
double a = 0.1;
BigDecimal a1 = BigDecimal.valueOf(a);
BigDecimal b1 = BigDecimal.valueOf(b);
BigDecimal c1 = a1.add(b1); // divide
double res = c1.doubleValue();
```

### 反射

**反射**：加载类，允许以编程方式解剖类中成员变量、方法、构造器等

1. 加载类，获取类的字节码：Class 对象

   ```java
   // 获取类的对象
   Class c = 类名.class; // 打印为包到类名
   
   Class c = forName("package_name类的全类名(xx.xx.xx)");
   
   Class c = 对象.getClass();
   
   c.getName(); // 全类名
   c.getSimpleName(); // 类名
   ```

2. 获取类的构造器：Constructor 对象

   ```java
   Constructor[] cons = c.getDeclaredConstructors(); // 获取全部构造器（public）
   cons.getParameterCount(); // 获取参数个数
   
   Constructor con = c.getDeclaredConstructor(); // 无参构造器
   Constructor con = c.getDeclaredConstructor(String.class, int.class); // 2个参数的有参构造器
   
   // 创建对象
   // 暴力反射，可访问私有构造器、方法、属性
   con.setAccessible(true); // 绕过访问权限
   Class_name d = (Class_name) con.newInstance(arg1, arg2, ...);
   ```

3. 获取类的成员变量：Field 对象

   ```java
   Field[] fields = c.getDeclaredFields(); 
   
   Field field = c.getDeclaredField("xxx"); // 获取单个成员变量对象
   field.getType.getName();
   
   // 获取成员变量进行取值赋值 对象d
   field.setAccessible(true); // 暴力访问private
   field.set(d, "xxx"); // 设置该成员变量
   type xxx = (type) field.get(d); // 获取成员变量
   ```

4. 获取类的成员方法：Method 对象

   ```java
   Method[] methods = c.getDeclaredMethods();
   
   Method a = c.getDeclaredMethod("func"); // 无参数func方法
   Method a = c.getDeclaredMethod("func", String.class); // 有参数func方法
   
   // 调用方法 对象d
   a.setAccessible(true);
   Object res = a.invoke(d, arg1, arg2, ...);
   ```

**绕过泛型约束**

当限制了`List<String>`时，可通过反射向其中写入其他类型数据

### 注解

- 特殊标记：`@Override`，让其他程序根据注解信息来决定如何执行该程序
- 可用在类上、构造器上、方法上、成员变量上、参数上

**自定义注解Annotation**

- 特殊属性名value，若注解中只有一个value属性，使用注解时，value名可不写

```java
public @interface 注解名 {
	public 属性类型 属性名() default 默认值;
}
public @interface A {
	String name();
	int age() default 18;
	String[] address();
	// 当只有 String value() 以下改为 @("xxx")
}

@A(name="aa", age=18, address= {"北京", "上海"})
```

**元注解**

用于注解注解

```java
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
public @interface B ... 
```

<img src="/img/java.zh-cn.assets/image-20250527203248794.png" alt="图片无法加载" />

**解析**

- 判断类、方法、成员变量上是否有注解，将注解里内容解析出来
- Clas、Method、Field、Constructor都实现了AnnotatedElement接口，可解析注解

```java
Class c = Demo.class;
if(c.isAnnotationPresent(TestDemo.class) {// 判断类上是否有注解TestDemo
	TestDemo testdemo = (TestDemo)c.getDeclaredAnnotation(TestDemo.class);
	
	// 获取值
	xxx = testdemo.xxx();
}
```

### 动态代理

使用 `java.lang.reflect.Proxy` 类为对象创建代理对象

```java
public static Object newProxyInstance(
	ClassLoader loader, // 指定用哪个类加载器，加载生成的代理类
	Class<?>[] interfaces, // 指定接口，这些接口用于指定生成的代理长啥样，有哪些方法
	InvocationHandler h) // 指定生成的代理对象做什么事情

public class ProxyUtil{
	public static StarService createProxy(Star s){
		StarService proxy = (StarService) Proxy.newProxyInstance(
			ProxyUtil.class.getClassLoader(),
			s.getClass().getInterfaces(),
			new InvocationHandler() {
				@Override
				public Object invoke(
					Object proxy, // proxy接收到代理对象本身
					Method method, // 正在被代理的方法
					Object[] args) throws Throwable { // 正在被代理方法的参数
						Object result = method.invoke(s, args);
						return result;
				}
			}
		);
	}
}
```

## 框架

**Commons-io**

- IO框架，框架：类、接口编译为class形式，压缩为.jar结尾文件发出去

- `commons-io-2.6.jar`，项目新建`lib`文件夹，复制到其中，jar文件右键：`Add as Library`

- 类中导包使用

```java
FileUtils.copyFile(new File("a"), new File("b")); // 复制文件
FileUtils.deleteDirectory(new File("a")); // 删除文件夹

// JDK
Files.copy(Path.of("x"), Path.of("b")); // 已存在则报错
```

**单元测试**

- `Junit`：单元测试框架

```java
import org.junit.Test

public class XXTest {
	// public, 无参, 无返回值 选中测试方法右键"Junit运行"
	@Test
	public void testFunc(){
		...
		// 断言结果与预期是否一致
		Assert.assertEquals("test failed", expected_value, test_value);
	}
}
```
