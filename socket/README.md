该目录存放有关socket编程的事例代码。

说明：该目录下的libdebug.c是基础lib库，各模块基本都会用到该lib中的函数。

下面以ip_client为例，讲解事例代码是如何编译和运行的。
编译方法：gcc libdebug.c ip_client.c -o ip_client
运行方法：./ip_client -h
