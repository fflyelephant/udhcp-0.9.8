	/* dhcpd.c
 *
 * udhcp Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>

#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "leases.h"
#include "packet.h"
#include "serverpacket.h"
#include "pidfile.h"


/* globals */
struct dhcpOfferedAddr *leases;
struct server_config_t server_config;
static int signal_pipe[2];

/* Exit and cleanup */
static void exit_server(int retval)
{
	pidfile_delete(server_config.pidfile);
	CLOSE_LOG();
	exit(retval);
}


/* Signal handler */
static void signal_handler(int sig)
{
	if (send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT) < 0) {
		LOG(LOG_ERR, "Could not send signal: %s", 
			strerror(errno));
	}
}


#ifdef COMBINED_BINARY	
int udhcpd_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{	
	fd_set rfds;
	struct timeval tv;
	int server_socket = -1;
	int bytes, retval;
	struct dhcpMessage packet;
	unsigned char *state;
	unsigned char *server_id, *requested;
	u_int32_t server_id_align, requested_align;
	unsigned long timeout_end;
	struct option_set *option;
	struct dhcpOfferedAddr *lease;
	int pid_fd;
	int max_sock;
	int sig;
	
	OPEN_LOG("udhcpd");
	LOG(LOG_INFO, "udhcp server (v%s) started", VERSION);

	memset(&server_config, 0, sizeof(struct server_config_t));
	
	/* 读取配置文件到server_config结构中供全局使用 */
	if (argc < 2)
		read_config(DHCPD_CONF_FILE);/* use default config file */
	else read_config(argv[1]);/* use designated config file */

	/* record pid number */
	pid_fd = pidfile_acquire(server_config.pidfile);
	pidfile_write_release(pid_fd);

	/* 通过code值找到options链表中lease(租赁时间)设置给server_config.lease */
	if ((option = find_option(server_config.options, DHCP_LEASE_TIME))) 
	{
		memcpy(&server_config.lease, option->data + 2, 4);
		server_config.lease = ntohl(server_config.lease);
	}
	else 
		/* 配置文件中没有指定租赁时间就使用默认值LEASE_TIME(10天) */
		server_config.lease = LEASE_TIME;
	/* max_leases默认是254条 */
	leases = malloc(sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	memset(leases, 0, sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	read_leases(server_config.lease_file);

	/*
	  通过interface获得ip地址、mac地址(arp)、interface index三个量
	  将这三个量写入到server_config结构体中
	*/
	if (read_interface(server_config.interface, &server_config.ifindex,
			   &server_config.server, server_config.arp) < 0)
		exit_server(1);//异常退出

#ifndef DEBUGGING
	pid_fd = pidfile_acquire(server_config.pidfile); /* hold lock during fork. */
	/* 调用daemon使函数运行于后台 */
	if (daemon(0, 0) == -1) {
		perror("fork");
		exit_server(1);
	}
	pidfile_write_release(pid_fd);
#endif
	/*
	  socketpair创建一对套接字，可实现全双工通信
			signal_pipe[1] --> write
			signal_pipe[0] --> read
	*/
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);

	/*
	  监听两种信号，收到后通过signal_pipe[1]将信号对应的信号数值发送给signal_pipe[0]
	  SIGUSR1:用户自定义信号？数值：16
	  SIGTERM:后台进程被结束(kill掉)，数值:15
	*/
	signal(SIGUSR1, signal_handler);
	signal(SIGTERM, signal_handler);

	/* server_config.auto_time 是指定更新lease_file文件的周期 */
	timeout_end = time(0) + server_config.auto_time;
	while(1) { /* loop until universe collapses */

		//拿到一个套接字
		if (server_socket < 0)
			if ((server_socket = listen_socket(INADDR_ANY, SERVER_PORT, server_config.interface)) < 0) {
				LOG(LOG_ERR, "FATAL: couldn't create server socket, %s", strerror(errno));
				exit_server(0);
			}			
		/*
			select监控server_socket & signal_pipe[0] 的可读状态
			select非阻塞,可监控多个文件描述符状态,以下是使用select的几个要点
			1:FD_SET将某个fd记录在位图rfds中(rfds若是一个字节长度最多只能监听8个fd)，select调用先清空rfds位图，在
			  某个fd状态就绪后将它原先的位置1，之后FD_ISSET检测此fd对应的位图是否为一即准备就绪。
			2:参数5是struct timeval *类型，表示阻塞时间
		      NULL ---> 完全阻塞方式，一定要等到监听的fd有就绪的才返回(变成了可以监听多个fd的阻塞函数比如accept,
			 	        recv,等)
			   0   ---> 不阻塞，select函数执行后立即返回
			  >0   ---> 半阻塞,在timeout内阻塞，有状态改变即返回，timeout时间到也要返回
			注:select每次都会清空此参数的值，所以必须每次执行select前都要设置一下此参数值否则很可能意外变为不阻
			  塞的select.
		*/
		FD_ZERO(&rfds);
		FD_SET(server_socket, &rfds);
		FD_SET(signal_pipe[0], &rfds);
		if (server_config.auto_time) {
			tv.tv_sec = timeout_end - time(0);
			tv.tv_usec = 0;
		}
		if (!server_config.auto_time || tv.tv_sec > 0) {
			max_sock = server_socket > signal_pipe[0] ? server_socket : signal_pipe[0];
			retval = select(max_sock + 1, &rfds, NULL, NULL, 
					server_config.auto_time ? &tv : NULL);
		} else retval = 0; /* If we already timed out, fall through */

		/*
			retval == 0 select timeout,此时间内没有监听到准备好的fd
		*/
		if (retval == 0) {
			write_leases();
			timeout_end = time(0) + server_config.auto_time;
			continue;
		} else if (retval < 0 && errno != EINTR) {
			DEBUG(LOG_INFO, "error on select");
			continue;
		}
		
		/* 先处理信号的输入 */
		if (FD_ISSET(signal_pipe[0], &rfds)) {
			if (read(signal_pipe[0], &sig, sizeof(sig)) < 0)
				continue; /* probably just EINTR */
			switch (sig) {
			case SIGUSR1:
				LOG(LOG_INFO, "Received a SIGUSR1");
				write_leases();
				/* why not just reset the timeout, eh */
				timeout_end = time(0) + server_config.auto_time;
				continue;
			case SIGTERM:
				LOG(LOG_INFO, "Received a SIGTERM");
				exit_server(0);
			}
		}

		/* 走到这里说明server_socket已准备就绪 */
		if ((bytes = get_packet(&packet, server_socket)) < 0) { /* this waits for a packet - idle */
			if (bytes == -1 && errno != EINTR) {
				DEBUG(LOG_INFO, "error on read, %s, reopening socket", strerror(errno));
				close(server_socket);
				server_socket = -1;
			}
			continue;
		}

		/* 下面就是按照DHCP报文交互逻辑进行执行 */

		/* 获得DHCP报文的类型 */
		if ((state = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
			DEBUG(LOG_ERR, "couldn't get option from packet, ignoring");
			continue;
		}
		
		/* ADDME: look for a static lease */
		/* 通过报文源MAC查找租赁链表中是否有租IP给过此MAC的client */
		lease = find_lease_by_chaddr(packet.chaddr);

		/* 根据协议给对应的报文回复动作 */
		switch (state[0]) {
		case DHCPDISCOVER:	
			DEBUG(LOG_INFO,"received DISCOVER");
			
			if (sendOffer(&packet) < 0) {
				LOG(LOG_ERR, "send OFFER failed");
			}
			break;			
 		case DHCPREQUEST:
			DEBUG(LOG_INFO, "received REQUEST");

			requested = get_option(&packet, DHCP_REQUESTED_IP);
			server_id = get_option(&packet, DHCP_SERVER_ID);

			if (requested) memcpy(&requested_align, requested, 4);
			if (server_id) memcpy(&server_id_align, server_id, 4);
		
			/* 客户端位于租赁链表中 */
			if (lease) { /*ADDME: or static lease */
				/* 有server IP值 */
				if (server_id) {
					/* SELECTING State */
					DEBUG(LOG_INFO, "server_id = %08x", ntohl(server_id_align));
					/* 是服务器IP 并且 请求的IP地址在租赁链表中 */
					if (server_id_align == server_config.server && requested && 
					    requested_align == lease->yiaddr) {
						sendACK(&packet, lease->yiaddr);// ACK
					}
				} else {
					/* 没有服务器IP 但有请求IP*/
					if (requested) {
						/* INIT-REBOOT State */
						/* 请求IP在租赁链表中 */
						if (lease->yiaddr == requested_align)
							sendACK(&packet, lease->yiaddr);// ACK
						else sendNAK(&packet); //NAK
					} else {
						/* RENEWING or REBINDING State */
						if (lease->yiaddr == packet.ciaddr)
							sendACK(&packet, lease->yiaddr);
						else {
							/* don't know what to do!!!! */
							sendNAK(&packet);
						}
					}						
				}
			
			/* what to do if we have no record of the client */
			} else if (server_id) {
				/* SELECTING State */
				/* 发给其他服务器的，不处理 */
			} else if (requested) {
				/* INIT-REBOOT State */
				if ((lease = find_lease_by_yiaddr(requested_align))) {
					if (lease_expired(lease)) {
						/* probably best if we drop this lease */
						memset(lease->chaddr, 0, 16);
					/* make some contention for this address */
					} else sendNAK(&packet);
				} else if (requested_align < server_config.start || 
					   requested_align > server_config.end) {
					sendNAK(&packet);
				} /* else remain silent */

			} else {
				 /* RENEWING or REBINDING State */
			}
			break;
		case DHCPDECLINE:
			DEBUG(LOG_INFO,"received DECLINE");
			if (lease) {
				memset(lease->chaddr, 0, 16);
				lease->expires = time(0) + server_config.decline_time;
			}			
			break;
		case DHCPRELEASE:
			DEBUG(LOG_INFO,"received RELEASE");
			if (lease) lease->expires = time(0);
			break;
		case DHCPINFORM:
			DEBUG(LOG_INFO,"received INFORM");
			send_inform(&packet);
			break;	
		default:
			LOG(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring", state[0]);
		}
	}

	return 0;
}

