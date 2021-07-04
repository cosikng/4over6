#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#define MYPORT 2333
#define QUERY_TIME 60
unsigned char local[2048];
unsigned char remote[2048];
int sock, s;
struct sockaddr_ll to;
struct sockaddr_in6 local_addr; //本地地址结构
struct sockaddr_in6 server_addr;
/*struct sockaddr_in local_addr; //本地地址结构
struct sockaddr_in server_addr;*/
int len;

char arp_table[256][6];
char arp_enable[256];
char wait_for_dns;
unsigned char local_mac[6];
char domain[100];

void *wan(void *args)
{
	int n;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (1)
	{
		n = recvfrom(sock, remote, 2048, 0, NULL, NULL);
		memcpy(remote, arp_table[remote[14 + 19]], 6);
		memcpy(remote + 6, local_mac, 6);
		sendto(s, remote, n, 0, (struct sockaddr *)&to, sizeof(to));
	}
}

void *dns(void *args)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	size_t len;
	ssize_t nread;
	char buf[500];
	struct sockaddr_in6 *ipv6;

	/* Obtain address(es) matching host/port */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6; /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ALL;
	hints.ai_protocol = IPPROTO_TCP;

	while (1)
	{

		s = getaddrinfo(domain, "https", &hints, &result);
		if (s != 0)
		{
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
			continue;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next)
		{

			ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
			inet_ntop(rp->ai_family, &ipv6->sin6_addr, buf, sizeof(buf));
			wait_for_dns = 0;
			printf("[IPv%d]%s\n", rp->ai_family == AF_INET ? 4 : 6, buf);
			server_addr.sin6_addr = ipv6->sin6_addr;
		}
		sleep(60);
	}
}

int main(int argc, char **argv)
{
	int n, err;
	struct ifreq ifr;
	pthread_t pt, pt1;
	if (argc != 3)
	{
		printf("Please input interface and server_domain.\n");
		return 0;
	}
	if (0 > (sock = socket(AF_INET6, SOCK_DGRAM, 0)))
	{
		perror("socket sock");
		exit(1);
	}
	if (0 > (s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))))
	{
		perror("socket s");
		exit(1);
	}
	bzero(&to, sizeof(to));
	bzero(&ifr, sizeof(ifr));
	bzero(arp_enable, 256);
	wait_for_dns = 1;
	strcpy(ifr.ifr_name, argv[1]);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1)
	{
		perror("interface");
		return 0;
	}
	to.sll_ifindex = ifr.ifr_ifindex;
	to.sll_family = PF_PACKET;
	to.sll_protocol = htons(ETH_P_IP);
	if (bind(s, (struct sockaddr *)&to, sizeof(to)) < 0)
	{
		perror("bind");
	}
	ioctl(sock, SIOCGIFHWADDR, &ifr);
	local_mac[0] = ifr.ifr_hwaddr.sa_data[0];
	local_mac[1] = ifr.ifr_hwaddr.sa_data[1];
	local_mac[2] = ifr.ifr_hwaddr.sa_data[2];
	local_mac[3] = ifr.ifr_hwaddr.sa_data[3];
	local_mac[4] = ifr.ifr_hwaddr.sa_data[4];
	local_mac[5] = ifr.ifr_hwaddr.sa_data[5];
	bzero(&local_addr, sizeof(local_addr)); /*清空地址结构*/
	bzero(&server_addr, sizeof(server_addr));
	local_addr.sin6_family = AF_INET6;	  //协议族
	local_addr.sin6_port = htons(MYPORT); //协议端口
	local_addr.sin6_addr = in6addr_any;
	//IPv6任意地址
	/*local_addr.sin_family = AF_INET;	 //协议族
	local_addr.sin_port = htons(MYPORT); //协议端口
	local_addr.sin_addr.s_addr = INADDR_ANY;*/
	server_addr.sin6_family = AF_INET6;	 //协议族
	server_addr.sin6_port = htons(2334); //协议端口
	//IPv6任意地址
	/*server_addr.sin_family = AF_INET;	//协议族
	server_addr.sin_port = htons(2334); //协议端口
	inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);*/
	err = bind(sock, (struct sockaddr *)&local_addr, sizeof(struct sockaddr_in6 /*struct sockaddr_in*/));
	if (err == -1)
	{ /*判断错误*/
		perror("bind error");
		return (1);
	}
	else
	{
		printf("bind() success\n");
	}
	len = sizeof(local_addr);
	printf("mac:%02X-%02X-%02X-%02X-%02X-%02X\n", local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
	strcpy(domain, argv[2]);
	pthread_create(&pt, NULL, (void *)wan, NULL);
	pthread_create(&pt1, NULL, (void *)dns, NULL);
	while (wait_for_dns)
		;
	while (1)
	{

		n = recvfrom(s, local, 2048, 0, NULL, NULL);
		if (memcmp(local_mac, local, 6) == 0 && (local[14 + 16] != 192 || local[14 + 17] != 168))
		{
			if (arp_enable[local[14 + 15]] == 0)
			{
				memcpy(arp_table[local[14 + 15]], local + 6, 6);
				arp_enable[local[14 + 15]] = 1;
			}
			sendto(sock, local, n, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
		}
	}
}