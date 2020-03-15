#### 												Hook实现思路与效果



#### 以子进程的形式执行待执行的二进制文件

##### 为了满足多样化的需求，这里实现两种HOOK模式

* Hook syscall

  * 主要问题与解决思路

    Linux提供的关于创建进程的API，fork是创建一个子进程（复制当前进程的上下文）；exec族则是执行新的文件完全覆盖了当前进程！并不能满足我们创建新进程、并Attach的目的。

    参考下strace的实现，是结合fork和exec族函数！

    ```
     A process can initiate a trace by calling fork(2) and having the
     resulting child do a PTRACE_TRACEME, followed (typically) by an
     execve(2).  Alternatively, one process may commence tracing another
     process using PTRACE_ATTACH or PTRACE_SEIZE.
    ```
    
    syscall函数hook注册
    
    ```c 
    void Hunter_sys_reg(long syscall, Hunter_sys_hook callback);
    ```

* HOOK glibc库函数

  * 主要问题与解决思路

    选择何种方式HOOK

    为了更加便捷、易于扩展的实现HOOK目的，我们采用PLT的方式HOOK

    ##### 基本原理

    ```
    借鉴ret2_dl_resolve机制
    （有点类似该过程的逆过程）
    
    根据libc函数的名称找到对应的plt地址，将该地址下一个0xcc断点，当tracee程序运行到该地址时，tracer即Hunter可以基于ptrace做出任何检查！
    当不需要监视该函数时，即将该plt地址的0xcc恢复！
    ```
    
    ##### 难点
    
    该思路的实现基于下面的步骤
    
    ```
    	遍历.dynstr得到函数字符串的偏移也就是.symbol中的st_name
    
    	遍历dynsym得到对应的st_name的项index  计算出r_info值
    	遍历rela_plt得到对应的r_info的项 index in rela_plt
    	得到plt下的index
    ```
    
    而上述步骤的所有字段是在main函数执行之前的libc初始化过程实现的，我们通过fork + exec方式启动一个程序，是在libc初始化之前就断下，我们必须在完成初始化工作后再次断下以实施上述步骤
    
    由于不能目标进程是hunter的子进程，我们只能在hunter里搜索目标进程的内容。
    
    ##### 解决思路
    
    针对这一点，没找到一个完美的解决方案。目前只能根据大多数的调试器的做法，**通过解析符号，获得main函数的地址，在main函数入口处下int3中断**，tracer接受到该信号后才可以完成解析plt的操作。（我们的hunter也没有必跟踪libc初始化的过程，所以也有必要在execve启动目标进程之后，让目标进程运行至main再trace！
    
    
    
    ##### 断点结构体
    
    ```c 
    struct breakpoint{
    	size_t bkaddr;	//addr % 0x1000
    	Hunter_hook dealfunc;	//Hunter function
    	union breakval bakval;	//breakpoint's value
    
    };
    ```
    
    在addr处设置断点，将地址处的值写入0xcc
    
    ```c 
    extern void setbreak(pid_t tracee, bkpoint* bkp)
    ```
    
    libc函数hook注册
    
    ``` c
    void Hunter_libc_reg(pid_t tracee, plthook_t* plthook, const char* name, Hunter_libc_hook Hunter_function);
    ```
    
    

* 注意

  * 这里的HOOK，其实更像是监听，我们并不将HOOK代码插入目标执行程序，而是在**Hunter**里监听到我们HOOK的对象时，在Hunter里做出反应。



相关知识

* ptrace、fork 
* ELF动态加载过程
* C语言回调函数

