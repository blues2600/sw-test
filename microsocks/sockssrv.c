/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "server.h"
#include "sblist.h"

/* timeout in microseconds on resource exhaustion to prevent excessive
   cpu usage. */
// 资源耗尽超时以微秒为单位，以防止过度CPU使用率
#ifndef FAILURE_TIMEOUT
#define FAILURE_TIMEOUT 64
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN    // 启动线程所需的堆栈空间量
#define THREAD_STACK_SIZE MAX(8*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__sun__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

static int quiet;
static const char* auth_user;
static const char* auth_pass;
static sblist* auth_ips;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static const struct server* server;   
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF
};

enum errorcode {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

// 这个结构用来处理套接字
struct thread {
	pthread_t pt;
	struct client client;   //地址加fd
	enum socksstate state;
	volatile int  done;     //不优化变量，每次存取都直接到内存
};

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
/* 我们记录到 stderr，因为它没有使用行缓冲，即从不同线程调用时需要锁定的 malloc。 
 * 出于同样的原因，我们使用 dprintf，它直接写入 fd。*/
#define dolog(...) do { if(!quiet) dprintf(2, __VA_ARGS__); } while(0)

/*
    do { 
        if(!quiet) 
            dprintf(2, __VA_ARGS__);     
       } while(0);

    dolog = if(!quiet) dprintf(2, "%d : %d : %d", ID1, ID2, ID3);
    dolog = 检查quiet，向stderr写入数据
*/
#else
static void dolog(const char* fmt, ...) { }
#endif


// 网络地址选择函数
// 从getaddrinfo返回的链表中（参数1）选择和参数2匹配的地址
static struct addrinfo* addr_choose(struct addrinfo* list, union sockaddr_union* bind_addr) {
	int af = SOCKADDR_UNION_AF(bind_addr); //bind_addr->v4->sin_family 地址家族
	if(af == AF_UNSPEC) return list; //AF_UNSPEC则意味着适用于指定主机名和服务名且适合任何协议族的地址
	struct addrinfo* p;
	for(p=list; p; p=p->ai_next)
		if(p->ai_family == af) return p; //选择地址
	return list;
}

/*
输入：缓冲区，缓冲区长度，客户端信息

功能：检查缓冲区头部，根据头部信息解读缓冲区中的数据（IP/DNS名称和端口）
利用从缓冲区中获取的IP或DNS + 端口，获得target的socket地址
如果target 和 bind_addr是相同类型的地址，则创建套接字并将新套接字绑定到bind_addr上面(用户可以输入bind_addr
最后，套接字连接到target

返回：新套接字fd

总结：连接buf中包含的目标主机

*/
static int connect_socks_target(unsigned char *buf, size_t n, struct client *client) {
    //检查缓冲区的长度和头部
	if(n < 5) return -EC_GENERAL_FAILURE; //缓冲区长度小于5，报错
	if(buf[0] != 5) return -EC_GENERAL_FAILURE; //缓冲区第一个字节不等于5，报错
	if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
	if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

	int af = AF_INET;
	size_t minlen = 4 + 4 + 2, l;
	char namebuf[256];
	struct addrinfo* remote;

    //检查缓冲区第四个字节，根据该字节的内容解读缓冲区后面的数据
	switch(buf[3]) {
		case 4: /* ipv6 */
			af = AF_INET6;
			minlen = 4 + 2 + 16;
			/* fall through */
		case 1: /* ipv4 */
			if(n < minlen) return -EC_GENERAL_FAILURE;
			if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))//ip转换为字符
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			break;
		case 3: /* dns name */
			l = buf[4]; //缓冲区第五个字节是长度
			minlen = 4 + 2 + l + 1;
			if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
			memcpy(namebuf, buf+4+1, l);//复制数据
			namebuf[l] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}


    //缓冲区有效数据的最后2个字节保存了端口
	unsigned short port;

    //端口号最大值0xFF00
	port = (buf[minlen-2] << 8) | buf[minlen-1];
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */

    //给定host和port，remote返回（被动套接字）的ip和端口地址结构信息
	if(resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;

    //从remote（链表）中选择和参数2匹配的地址
	struct addrinfo* raddr = addr_choose(remote, &bind_addr);

    //创建套接字
	int fd = socket(raddr->ai_family, SOCK_STREAM, 0);
	if(fd == -1) {
		eval_errno:
		if(fd != -1) close(fd);
		freeaddrinfo(remote);
		switch(errno) {
			case ETIMEDOUT:
				return -EC_TTL_EXPIRED;
			case EPROTOTYPE:
			case EPROTONOSUPPORT:
			case EAFNOSUPPORT:
				return -EC_ADDRESSTYPE_NOT_SUPPORTED;
			case ECONNREFUSED:
				return -EC_CONN_REFUSED;
			case ENETDOWN:
			case ENETUNREACH:
				return -EC_NET_UNREACHABLE;
			case EHOSTUNREACH:
				return -EC_HOST_UNREACHABLE;
			case EBADF:
			default:
			perror("socket/connect");
			return -EC_GENERAL_FAILURE;
		}
	}


    // raddr是服务端套接字,bind_addr是服务端用户参数输入的值
    // 若raddr地址族和bind_addr的一样，则将bing_addr地址和套接字绑定
	if(SOCKADDR_UNION_AF(&bind_addr) == raddr->ai_family &&
	   bindtoip(fd, &bind_addr) == -1)
		goto eval_errno;

    //新套接字连接到raddr服务器
	if(connect(fd, raddr->ai_addr, raddr->ai_addrlen) == -1)
		goto eval_errno;

    //地址转换打印信息
	freeaddrinfo(remote);
	if(CONFIG_LOG) {
		char clientname[256];
		af = SOCKADDR_UNION_AF(&client->addr);
		void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
		inet_ntop(af, ipdata, clientname, sizeof clientname);
		dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
	}
	return fd;
}


//比较参数1和参数2的ip是否一样
static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
	int af = SOCKADDR_UNION_AF(authedip); //地址族
	if(af == SOCKADDR_UNION_AF(client)) { //比较参数1和参数2的地址族是否相同
		size_t cmpbytes = af == AF_INET ? 4 : 16; //判断参数2是ipv4 or ipv6
		void *cmp1 = SOCKADDR_UNION_ADDRESS(client);//根据client的内容选择ipv4 or ipv6地址
		void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);//同上
		if(!memcmp(cmp1, cmp2, cmpbytes)) return 1; //比较两个ip是否相同
	}
	return 0;
}

//输入:地址联合体
//功能：在auth_ips中查询是否有ip和参数的ip一样
static int is_in_authed_list(union sockaddr_union *caddr) {
	size_t i;
	for(i=0;i<sblist_getsize(auth_ips);i++)
		if(is_authed(caddr, sblist_get(auth_ips, i)))//ips里面保存了sock地址信息,比较两个参数的ip是否相同
			return 1;
	return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
	sblist_add(auth_ips, caddr);
}

// 输入：缓冲区、缓冲区长度、客户端套接字信息
// 根据参数1的内容，返回身份验证的方式(或者返回失败),参数3用来辅助完成函数内容
static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
	if(buf[0] != 5) return AM_INVALID; //第一个字符如果不是5，则验证失败
	size_t idx = 1;
	if(idx >= n ) return AM_INVALID;//缓冲区长度小于或等于1，则验证失败
	int n_methods = buf[idx]; //n_methods = 缓冲区第二个字符，如果小于或等于0，则验证失败
	idx++; //idx=2
	while(idx < n && n_methods > 0) {

        //从缓冲区第三个字符开始验证,这个字符指定身份验证模式
		if(buf[idx] == AM_NO_AUTH) {
			if(!auth_user)          //若指定不验证身份，且用户名为空，返回AM_NO_AUTH
                return AM_NO_AUTH;
			else if(auth_ips) {     //若指定不验证身份，且用户名和ips不为空
				int authed = 0;
				if(pthread_rwlock_rdlock(&auth_ips_lock) == 0) {//阻塞线程直到获得读写锁
					authed = is_in_authed_list(&client->addr);//在auth_ips中查询是否有ip和参数的ip一样
					pthread_rwlock_unlock(&auth_ips_lock);//释放读写锁
				}
				if(authed) return AM_NO_AUTH;//如果客户端ip存在于auth_ips中，就返回步需要验证
			}
		}
        else if(buf[idx] == AM_USERNAME) { //使用用户名和密码认证
			if(auth_user) return AM_USERNAME;
		}

		idx++;
		n_methods--; //由于这个变量存在，整个循环正常状态下最多循环两次
	}
	return AM_INVALID;
}

//向fd写入版本和身份验证方式代码
static void send_auth_response(int fd, int version, enum authmethod meth) {
	unsigned char buf[2];
	buf[0] = version; //版本
	buf[1] = meth;    //身份验证方式
	write(fd, buf, 2);//向fd写入版本和身份验证方式
}

//向参数1写入包含参数2（错误代码）的数据
static void send_error(int fd, enum errorcode ec) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	write(fd, buf, 10);
}

//监视fd1 fd2，任意套接字发来消息，则转发给另外一个
static void copyloop(int fd1, int fd2) {

    //监视fd1 fd2的可读事件
	struct pollfd fds[2] = {
		[0] = {.fd = fd1, .events = POLLIN},
		[1] = {.fd = fd2, .events = POLLIN},
	};

	while(1) {
		/* inactive connections are reaped after 15 min to free resources.
		   usually programs send keep-alive packets so this should only happen
		   when a connection is really unused. 
           
            15 分钟后将回收非活动连接以释放资源。
            通常程序会发送保持活动的数据包，因此只有当连接确实未被使用时才会发生这种情况。
           */
		switch(poll(fds, 2, 60*15*1000)) {
			case 0:
				return;
			case -1:
				if(errno == EINTR || errno == EAGAIN) continue;
				else perror("poll");
				return;
		}

        //判断是否为可读事件，有可读事件的那个fd发来了消息
		int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
		int outfd = infd == fd2 ? fd1 : fd2;
		char buf[1024];
		ssize_t sent = 0, n = read(infd, buf, sizeof buf);
		if(n <= 0) return;
        //转发所有收到的消息给outfd
		while(sent < n) {
			ssize_t m = write(outfd, buf+sent, n-sent);
			if(m < 0) return;
			sent += m;
		}
	}
}


//从第一个参数中提取用户名和密码，并进行验证，然后返回结果
static enum errorcode check_credentials(unsigned char* buf, size_t n) {
	if(n < 5) return EC_GENERAL_FAILURE; //缓冲区长度小于5则报错
	if(buf[0] != 1) return EC_GENERAL_FAILURE;//缓冲区第一个字符不等于1则报错
	unsigned ulen, plen;
	ulen=buf[1]; //缓冲区第二个字符是用户名长度
	if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;//如果缓冲区长度 < 用户名长度+4,报错
	plen=buf[2+ulen]; //用户名的后面一个字节是密码长度
	if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
	char user[256], pass[256];
	memcpy(user, buf+2, ulen);
	memcpy(pass, buf+2+ulen+1, plen);
	user[ulen] = 0;//末尾添加空字节
	pass[plen] = 0;//末尾添加空字节
	if(!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;//密码验证
	return EC_NOT_ALLOWED;
}

// 新线程主函数
// 从客户端接收数据，验证客户身份，连接目标主机，并为客户和目标主机提供数据转发服务
static void* clientthread(void *data) {
	struct thread *t = data; // t = data = 线程套接字信息结构 struct thread
	t->state = SS_1_CONNECTED; //线程状态
	unsigned char buf[1024];
	ssize_t n;
	int ret;
	int remotefd = -1;
	enum authmethod am; //身份认证方法

    //从客户端接收数据
	while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
		switch(t->state) { //检查线程状态
			case SS_1_CONNECTED: 
				am = check_auth_method(buf, n, &t->client); //根据客户端的输入内容，返回身份验证的方式(或者返回失败)
				if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
				else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
				send_auth_response(t->client.fd, 5, am); //向客户端发送版本和身份验证方式代码
				if(am == AM_INVALID) goto breakloop; //验证失败，断开连接，结束线程
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, n);//根据用户发送的数据，验证用户名和密码
				send_auth_response(t->client.fd, 1, ret); //向客户端发送版本和身份验证结果
				if(ret != EC_SUCCESS) //身份验证失败，断开连接，结束线程
					goto breakloop;
				t->state = SS_3_AUTHED; //验证成功

                //如果用户的身份验证成功，它的ip加入到auth_ips中
				if(auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
					if(!is_in_authed_list(&t->client.addr)) //在auth_ips中查询是否有ip和参数的ip一样
						add_auth_ip(&t->client.addr); //如果没有一样的ip,添加item的内容到auth_ips中
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				break;
			case SS_3_AUTHED:  //已验证，连接buf中包含的目标主机
				ret = connect_socks_target(buf, n, &t->client);
				if(ret < 0) {
					send_error(t->client.fd, ret*-1);
					goto breakloop;
				}
				remotefd = ret;
				send_error(t->client.fd, EC_SUCCESS); //发送成功消息
				copyloop(t->client.fd, remotefd); //在客户端和远程服务器之间转发消息,无限循环，除非15分钟不活动
				goto breakloop;

		}
	}
breakloop:

	if(remotefd != -1)
		close(remotefd);

	close(t->client.fd);
	t->done = 1;

	return 0;
}

static void collect(sblist *threads) {
	size_t i;

    //sblist_getsize(threads) = (X)->count
	for(i=0;i<sblist_getsize(threads);) {
        //如果参数2的值小于参数1的count成员，移动参数1的items指针，让它指向更高的地址
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if(thread->done) { //主线程等待客户端线程终止,释放资源
			pthread_join(thread->pt, 0);
			sblist_delete(threads, i);
			free(thread);
		} else
			i++;
	}
}

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -1 -q -i listenip -p port -u user -P password -b bindaddr\n"
		"all arguments are optional.\n"
		"by default listenip is 0.0.0.0 and port 1080.\n\n"
		"option -q disables logging.\n"
		"option -b specifies which ip outgoing connections are bound to\n"
		"option -1 activates auth_once mode: once a specific ip address\n"
		"authed successfully with user/pass, it is added to a whitelist\n"
		"and may use the proxy without auth.\n"
		"this is handy for programs like firefox that don't support\n"
		"user/pass auth. for it to work you'd basically make one connection\n"
		"with another program that supports it, and then you can use firefox too.\n"
	);
	return 1;
}

/* prevent username and password from showing up in top.
 * 防止用户名和密码显示在顶部*/
static void zero_arg(char *s) {
	size_t i, l = strlen(s);
	for(i=0;i<l;i++) s[i] = 0;
}

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "0.0.0.0"; 
	unsigned port = 1080;

    //接收用户的参数，并逐个参数解析，直到解析完所有选项返回-1
	while((ch = getopt(argc, argv, ":1qb:i:p:u:P:")) != -1) {
		switch(ch) {
			case '1':               //新建并初始化sblist对象,auth_ips指向这个对象，这里会保存通过身份验证的用户ip
				auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
				break;
			case 'q':               //禁用日志记录
				quiet = 1;
				break;
			case 'b':               //给定host和port，resolve_sa让第三个参数接收一个struct sockaddr结构
                                    //optarg 是一个全局变量，定义在头文件 <unistd.h> 中
                                    //它保存getopt()解析的选项参数
                                    //即optarg = -b 后面的字符
                                    //即 app -b hostname 获得主机struct sockaddr结构
                                    //服务器收到的数据包可以通过这个ip来传出（有时候服务器不止一个ip）
				resolve_sa(optarg, 0, &bind_addr);
				break;
			case 'u':
                                    //若app -u astring，则auth_user指向astring
                                    //从u选项获得用户名
				auth_user = strdup(optarg);
				zero_arg(optarg);  // 内容置0 
				break;
			case 'P':               //从P选项获得密码
				auth_pass = strdup(optarg);
				zero_arg(optarg);
				break;
			case 'i':           //从i选项获得ip(也可以是主机名
				listenip = optarg;
				break;
			case 'p':           //从p选项获得端口
				port = atoi(optarg);
				break;
			case ':':       //用户输入的选项未定义
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':       //非法选项或缺少必要的参数
				return usage();
		}
	}


    // 当用户输入的用户名或密码任何一个为空，输出错误提示
	if((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
		dprintf(2, "error: user and pass must be used together\n");
		return 1;
	}
    //使用-1参数但没有输入密码，输出错误提示
	if(auth_ips && !auth_pass) {
		dprintf(2, "error: auth-once option must be used together with user/pass\n");
		return 1;
	}

    //这里没有验证密码，check_credentials函数可以用来验证密码

    // 忽略SIGPIPE信号
    // 一个socket已经断开了连接（信道），就会产生SIGPIPE信号，默认情况下这个信号会终止整个进程
	signal(SIGPIPE, SIG_IGN);
	struct server s; 


    //sblist_new(itemsize, blockitems)
	sblist *threads = sblist_new(sizeof (struct thread*), 8);

    //根据用户给出的主机信息，获得主机socket地址并建立监听的服务器，s指向监听套接字
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

    //持续等待客户端的socket连接，并且为每个连接新建一个执行线程
	while(1) {
                          //这里是个while，所以下次调用的时候就有意义了
		collect(threads); //这里没看懂，此时threads.count的值为0，这次调用毫无意义
		struct client c; //socket地址 + fd
		struct thread *curr = malloc(sizeof (struct thread)); //分配一个处理套接字的内存
		if(!curr) goto oom; //出错，并休眠
		curr->done = 0;

        //服务器接受一个客户端连接
		if(server_waitclient(&s, &c)) {
			dolog("failed to accept connection\n");
			free(curr);
			usleep(FAILURE_TIMEOUT);
			continue;
		}

        //客户端信息添加到threads
		curr->client = c;
		if(!sblist_add(threads, &curr)) { //添加curr的内容到threads中
			close(curr->client.fd);     //内存用完（OUT OF MEMORY）
			free(curr);
			oom:
			dolog("rejecting connection due to OOM\n");
			usleep(FAILURE_TIMEOUT); /* prevent 100% CPU usage in OOM situation */
			continue;
		}

        //对线程属性结构体进行初始化。这样可以确保所有属性都被正确设置为默认值，避免出现未定义行为
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
            //设置线程的堆栈大小
			pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
		}

        //创建线程，新线程在clientthread,curr是传递给新函数的参数
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0)
			dolog("pthread_create failed. OOM?\n");
        //销毁线程属性
		if(a) pthread_attr_destroy(&attr);
	}
}
