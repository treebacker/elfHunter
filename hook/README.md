​													Hook实现思路与效果



#### 以子进程的形式执行待执行的二进制文件

* 主要问题与解决思路

  Linux提供的关于创建进程的API，fork是创建一个子进程（复制当前进程的上下文）；exec族则是执行新的文件完全覆盖了当前进程！并不能满足我们创建新进程、并Attach的目的。

  参考下strace的实现，是结合fork和exec族函数！

  ```
   A process can initiate a trace by calling fork(2) and having the
   resulting child do a PTRACE_TRACEME, followed (typically) by an
   execve(2).  Alternatively, one process may commence tracing another
   process using PTRACE_ATTACH or PTRACE_SEIZE.
  ```

相关知识

* ptrace、fork
* C语言回调函数

