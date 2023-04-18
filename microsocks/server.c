struct server#include "server.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 给定host和port，addr返回（被动套接字）的ip和端口地址结构信息
int resolve(const char *host, unsigned short port, struct addrinfo** addr) {
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,     //未指定地址族
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE,     //返回适用于被动套接字的地址信息
	};
	char port_buf[8];
	snprintf(port_buf, sizeof port_buf, "%u", port);
    // 给定主机信息，返回用于服务器使用的ip和port
	return getaddrinfo(host, port_buf, &hints, addr);
}

// 给定host和port，res接收一个struct sockaddr结构
int resolve_sa(const char *host, unsigned short port, union sockaddr_union *res) {
	struct addrinfo *ainfo = 0; //任意网络地址结构
	int ret;
	SOCKADDR_UNION_AF(res) = AF_UNSPEC; //res->v4.sin_family ,未指定地址族
	if((ret = resolve(host, port, &ainfo))) return ret; //getaddrinfo失败
    //getaddrinfo返回一个列表，但是这里只用了第一个项
	memcpy(res, ainfo->ai_addr, ainfo->ai_addrlen); //套接字地址输出到res
	freeaddrinfo(ainfo);
	return 0;
}

//将参数2的地址绑定到参数1
int bindtoip(int fd, union sockaddr_union *bindaddr) {
	socklen_t sz = SOCKADDR_UNION_LENGTH(bindaddr);
	if(sz)
		return bind(fd, (struct sockaddr*) bindaddr, sz);
	return 0;
}

//server接受一个客户端连接
int server_waitclient(struct server *server, struct client* client) {
	socklen_t clen = sizeof client->addr;
	return ((client->fd = accept(server->fd, (void*)&client->addr, &clen)) == -1)*-1;
}

//根据listenip和port提供的主机信息，获得该主机socket地址,再用地址创建服务器并监听
// server 获得监听套接字fd
int server_setup(struct server *server, const char* listenip, unsigned short port) {
	struct addrinfo *ainfo = 0;
	if(resolve(listenip, port, &ainfo)) return -1;  //获得服务器地址
	struct addrinfo* p;
	int listenfd = -1;

    //创建套接字
	for(p = ainfo; p; p = p->ai_next) {           
		if((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
			continue;
		int yes = 1;            
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		if(bind(listenfd, p->ai_addr, p->ai_addrlen) < 0) {
			close(listenfd);
			listenfd = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(ainfo);
	if(listenfd < 0) return -2;
	if(listen(listenfd, SOMAXCONN) < 0) {
		close(listenfd);
		return -3;
	}
	server->fd = listenfd;
	return 0;
}
