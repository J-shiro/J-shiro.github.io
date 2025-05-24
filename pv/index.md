# 哲学家进餐问题


## 问题分析

使用信号量机制解决，会出现产生死锁的情况，所以需要解决死锁，有一种方法为**至多只允许四位哲学家同时去拿左边的筷子，最终能保证至少有一位哲学家能够进餐，并在用毕时能释放用过的两只筷子**

```c
do{
	wait(chopstick[i]);
	wait(chopstick[(i+1)%5]);
	eat;
	signal(chopstick[i]);
	signal(chopstick[(i+1)%5]);
	think;
}while(TRUE);
```

## 伪代码

```c
semaphore chopstick[5] = {1, 1, 1, 1, 1}; 
semphore room=4;
Pi (){
	while(1){
		P(room);//只能有四个人进入拿左边的筷子
		P(chopstick[i]); //先拿左筷子
		P(chopstick[(i+1)%5]);//再拿右筷子
		进餐; 
		V(chopstick[(i+1)%5]; 
		V(chopstick[i]); 
		V(room);
		思考 
	} 
}
```

## 分析及知识点

### sembuf结构体

```c
struct sembuf  
{
	unsigned short int sem_num;   	//信号量集中的第几个信号量(0~nsems-1,0:第一个,nsems-1:最后一个)
	short int sem_op;            	//对信号量的操作，>0:挂起操作, 0, <0 
	short int sem_flg;            	//操作标识：0， IPC_WAIT, SEM_UNDO
};
```

 **sem_op**标识对信号量的所进行的操作类型。对信号量的操作有三种类型：

- **sem_op > 0，对该信号量执行挂出操作**，挂出的值由sem_op决定，系统会把sem_op的值加到该信号量的当前值semval上。如果sem_flag指定了SEM_UNDO（还原）标志，那么相应信号量的semadj值会减掉sem_op的值。
- **sem_op < 0，对该信号量执行等待操作**，当信号量的当前值semval >= -sem_op时，semval减掉sem_op的绝对值，为该线程分配对应数目的资源。如果指定SEM_UNDO，相应信号量的semadj就加上sem_op的绝对值。当semval < -sem_op时，相应信号量的semncnt就加1，调用线程被阻塞，直到semval >= -sem_op，当此条件满足时，调用线程被唤醒，执行相应的分配操作，然后semncnt减去1.
- **sem_op = 0，表示调用者希望semval变为0**。如果为0则立即返回，如果不为0，相应信号量的semzcnt加1，调用调用线程被阻塞。

 **sem_flg**：信号量操作的属性标志。①如果为0，表示正常操作；②如果为IPC_WAIT，使对信号量的操作是非阻塞的，即指定了该标志，调用线程在信号量的值不满足条件的情况下不会被阻塞，而是直接返回-1，并将errno设置为EAGAIN；③如果为SEM_UNDO，那么将维护进程对信号量的调整值，以便进程结束时恢复信号量的状态。

**semadj**：指定信号量针对某个特定进程的调整值。只有sembuf结构的sem_flag指定为SEM_UNDO后，semadj才会随着sem_op而更新。

**semncnt**：等待semval变为大于当前值的线程数。

**semzcnt**：等待semval变为0的线程数。

### semop函数

 在 Linux 下，PV 操作通过调用**semop**函数来实现，用于请求和释放信号量，改变信号量的值。当请求的信号量值 > 0 时，semop 直接返回，否则会阻塞，直到信号量值大于 0。如果是释放（归还）资源，semop 直接返回。

该函数定义在头文件 sys/sem.h中，原型如下：

   `int  semop(int  semid, struct sembuf  *sops, size_t nsops);`成功返回0，失败返回-1

-  semid 为信号量集的标识符
- 参数 sops 指向进行操作的结构体数组的首地址
- 参数 nsops 指出将要进行操作的信号的个数

### semget函数

是用来创建或获取信号量的ipc内核对象，同时返回id号，函数原型：

`int semget(key_t key, int nsems, int semflg);`

- **key：整数值（唯一非零）**，用户可自己设定
  - 键值是IPC_PRIVATE，该值通常为0，意思就是创建一个仅能被进程访问的信号量。
  - 键值不是IPC_PRIVATE，我们可以指定键值。
  - 不相关的进程可以通过它访问一个信号量，它代表程序可能要使用的某个资源，程序对所有信号量的访问都是间接的，程序先通过调用semget()函数并提供一个键，再由系统生成一个相应的信号标识符（semget()函数的返回值），只有semget()函数才直接使用信号量键，所有其他的信号量函数使用由semget()函数返回的信号量标识符。如果多个程序使用相同的key值，key将负责协调工作。

- **num_sems：指定需要的信号量数目**，它的值几乎总是1。

- **sem_flags：是一组标志**，IPC_CREAT如果信号量不存在，则创建一个信号量，否则获取；IPC_EXCL只有信号量不存在的时候，新的信号量才建立，否则就产生错误。0660代表读写权限等

返回值：semget()函数成功返回一个相应信号标识符（非零），失败返回-1

### semctl函数

设置、获取、控制信号量值，原型为：

`int semctl(int sem_id, int sem_num, int command, ...);`

若有第四个参数一般为：

```c
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *arry;
};
```

command通常是下面两个值中的其中一个

- **SETVAL**：用来把信号量初始化为一个已知的值。p 这个值通过union semun中的val成员设置，其作用是在信号量第一次使用前对它进行设置。

-  **IPC_RMID**：用于删除一个已经无需继续使用的信号量标识符。

## 代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/types.h>

#define MAX_BUFFER_SIZE 5
#define SHM_MODE 0600
#define SEM_MODE 0600
#define mutex 5
#define true 1
#define room 6

int chopstick[5] = {0,1,2,3,4};
int sem_id = -1;
pid_t philosopher;

//P操作
void Wait(int sem_id,int sem_num)
{
	struct sembuf buf;
	buf.sem_num = sem_num;//第几个信号量
	buf.sem_op = -1;//对该信号量执行等待
	buf.sem_flg = SEM_UNDO;//维护进程对信号量的调整值
	if(semop(sem_id,&buf,1) < 0)
	{
		perror("wait failed");
		exit(1);
	}
}

//V操作
void Signal(int sem_id,int sem_num)
{
	struct sembuf buf;
	buf.sem_num = sem_num;
	buf.sem_op = 1;//对该信号量执行挂出
	buf.sem_flg = SEM_UNDO;

	if(semop(sem_id,&buf,1) < 0)
	{
		perror("signal failed");
		exit(1);
	}
}

void think(int i)
{
    printf("the philosopher of %d is thinking(pid is %d)\n",i,getpid());
}

void eat(int i)
{
    printf("the philosopher of %d is eating(pid is %d)\n",i,getpid());
}

void Philosophers1(int sem_id,int i)
{
	int j;
	for(j=0;j<2;j++){
		think(i);
		Wait(sem_id,room); 
		Wait(sem_id,chopstick[i]); 
		Wait(sem_id,chopstick[(i+1)%5]); 
		eat(i);
		Signal(sem_id,chopstick[i]); 
		Signal(sem_id,chopstick[(i+1)%5]); 
		printf("the process of %d(pid is %d,ppid is %d)has finished eating\n",i,getpid(),getppid());
		Signal(sem_id,room); 
		fflush(stdout);
	}
	exit(0);
}

int main()
{
    int i = 0;
	if((sem_id = semget(IPC_PRIVATE,7,SEM_MODE)) < 0)
	{					
		perror("create semaphore failed! \n");
		exit(1);
	}
	if(semctl(sem_id,mutex,SETVAL,1) == -1)
	{
		perror("sem set value error! \n");
		exit(1);
	}
	for(i=0;i<5;i++){
        if(semctl(sem_id,chopstick[i],SETVAL,1) == -1)
        {
            perror("sem set value error! \n");
            exit(1);
        }
	}
	if(semctl(sem_id,room,SETVAL,4) == -1)
	{
		perror("sem set value error! \n");
		exit(1);
	}
    for(i=0;i<5;i++){
        philosopher = fork();
        if(philosopher < 0){
            perror("the fork failed");
			exit(1);
        }
        else if(philosopher == 0){
            Philosophers1(sem_id,i);       
        }
    }
    while (wait(0) != -1);
    shmctl(sem_id,IPC_RMID,0);
    printf("finish!!!\n");
    fflush(stdout);//在prinf()后加上fflush(stdout); 强制马上输出，避免错误。
    exit(0);
    return 0;
}
```

**结果显示：**

```shell
[j@master test]$ ./test
the philosopher 1 is thinking(pid is 5185)
the philosopher 1 is eating(pid is 5185)
the process of 1(pid is 5185,ppid is 5183)has finished eating
the philosopher 1 is thinking(pid is 5185)
the philosopher 1 is eating(pid is 5185)
the process of 1(pid is 5185,ppid is 5183)has finished eating
the philosopher 2 is thinking(pid is 5186)
the philosopher 2 is eating(pid is 5186)
the process of 2(pid is 5186,ppid is 5183)has finished eating
the philosopher 2 is thinking(pid is 5186)
the philosopher 2 is eating(pid is 5186)
the process of 2(pid is 5186,ppid is 5183)has finished eating
the philosopher 3 is thinking(pid is 5187)
the philosopher 3 is eating(pid is 5187)
the process of 3(pid is 5187,ppid is 5183)has finished eating
the philosopher 3 is thinking(pid is 5187)
the philosopher 3 is eating(pid is 5187)
the process of 3(pid is 5187,ppid is 5183)has finished eating
the philosopher 4 is thinking(pid is 5188)
the philosopher 4 is eating(pid is 5188)
the process of 4(pid is 5188,ppid is 5183)has finished eating
the philosopher 4 is thinking(pid is 5188)
the philosopher 4 is eating(pid is 5188)
the process of 4(pid is 5188,ppid is 5183)has finished eating
the philosopher 0 is thinking(pid is 5184)
the philosopher 0 is eating(pid is 5184)
the process of 0(pid is 5184,ppid is 5183)has finished eating
the philosopher 0 is thinking(pid is 5184)
the philosopher 0 is eating(pid is 5184)
the process of 0(pid is 5184,ppid is 5183)has finished eating
end
```


