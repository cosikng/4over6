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
#include "funcs.h"
#define MYPORT 2334
#define QUERY_TIME 60
unsigned char local[2048];
unsigned char remote[2048];
int sock, s;
struct sockaddr_ll to;
struct sockaddr_in6 local_addr; //本地地址结构
struct sockaddr_in6 client_addr;
/*struct sockaddr_in local_addr; //本地地址结构
struct sockaddr_in client_addr;*/
int len;

unsigned char local_mac[6];
unsigned char gateway_mac[6];
unsigned char local_ip;

unsigned char htoi(char *s)
{
	char sum = 0;
	for (int i = 0; i < 2; i++)
	{
		sum = sum * 16 + (s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : s[i] - 'a' + 10);
	}
	return sum;
}

void *arp(void *args)
{
	int sock, n, j = 0, c = 0;
	struct ifreq ifr;
	struct ethhdr *eth;
	struct sockaddr_ll ad;
	unsigned char buffer[256];

	if (0 > (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))))
	{
		perror("socket");
		exit(1);
	}
	bzero(&ad, sizeof(ad));
	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, (char *)args);
	ioctl(sock, SIOCGIFINDEX, &ifr);
	ad.sll_ifindex = ifr.ifr_ifindex;
	ad.sll_family = PF_PACKET;
	ad.sll_protocol = htons(ETH_P_ARP);
	if (bind(sock, (struct sockaddr *)&ad, sizeof(ad)) < 0)
	{
		perror("bind");
		return 0;
	}
	while (1)
	{
		n = recvfrom(sock, buffer, 256, 0, NULL, NULL);
		if (buffer[38 + 3] == 233 && buffer[21] == 1)
		{
			buffer[0] = buffer[6];
			buffer[1] = buffer[7];
			buffer[2] = buffer[8];
			buffer[3] = buffer[9];
			buffer[4] = buffer[10];
			buffer[5] = buffer[11];
			buffer[21] = 2;
			memcpy(buffer + 6, local_mac, 6);
			buffer[0 + 22] = buffer[6];
			buffer[1 + 22] = buffer[7];
			buffer[2 + 22] = buffer[8];
			buffer[3 + 22] = buffer[9];
			buffer[4 + 22] = buffer[10];
			buffer[5 + 22] = buffer[11];
			buffer[0 + 32] = buffer[0];
			buffer[1 + 32] = buffer[1];
			buffer[2 + 32] = buffer[2];
			buffer[3 + 32] = buffer[3];
			buffer[4 + 32] = buffer[4];
			buffer[5 + 32] = buffer[5];
			buffer[0 + 38] = buffer[0 + 28];
			buffer[1 + 38] = buffer[1 + 28];
			buffer[2 + 38] = buffer[2 + 28];
			buffer[3 + 38] = buffer[3 + 28];
			buffer[31] = local_ip;
			if (sendto(sock, buffer, n, 0, (struct sockaddr *)&ad, sizeof(ad)) == -1)
			{
				perror("send");
				break;
			}
		}
	}
}

void *wan(void *args)
{
	int n, delta;
	OInfo info;
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (1)
	{
		n = recvfrom(s, remote, 2048, 0, NULL, NULL);
		if (memcmp(remote, local_mac, 6) != 0)
			continue;
		if (remote[14 + 9] == 6)
		{ //TCP
			if (get_src(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 2), TCP, &info) == -1)
				continue;
			//update ip checksum
			delta = remote[14 + 19] - info.ori_host;
			*(unsigned short *)(remote + 14 + 10) = htons(update_checksum(get_word(remote + 14 + 10), delta));
			//update tcp checksum
			delta += get_word(remote + 14 + (remote[14] & 0xf) * 4 + 2) - info.ori_port;
			*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 16) = htons(update_checksum(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 16), delta));
			//update ip
			//remote[14 + 18] = 18;
			remote[14 + 19] = info.ori_host;
			//update port
			*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 2) = htons(info.ori_port);
		}
		else if (remote[14 + 9] == 17)
		{ //UDP
			if (get_src(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 2), UDP, &info) == -1)
				continue;
			//update ip checksum
			delta = remote[14 + 19] - info.ori_host;
			*(unsigned short *)(remote + 14 + 10) = htons(update_checksum(get_word(remote + 14 + 10), delta));
			if (get_word(remote + 14 + (remote[14] & 0xf) * 4 + 6) != 0)
			{
				//update udp checksum
				delta += get_word(remote + 14 + (remote[14] & 0xf) * 4 + 2) - info.ori_port;
				*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 6) = htons(update_checksum(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 6), delta));
			}
			//update ip
			//remote[14 + 18] = 18;
			remote[14 + 19] = info.ori_host;
			//update port
			*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 2) = htons(info.ori_port);
		}
		else if (remote[14 + 9] == 1)
		{
			//ICMP(Request/Reply)
			if (get_src(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 4), UDP, &info) == -1)
				continue;
			//update ip checksum
			delta = remote[14 + 19] - info.ori_host;
			*(unsigned short *)(remote + 14 + 10) = htons(update_checksum(get_word(remote + 14 + 10), delta));
			//update icmp checksum
			delta = get_word(remote + 14 + (remote[14] & 0xf) * 4 + 4) - info.ori_port;
			*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 2) = htons(update_checksum(get_word(remote + 14 + (remote[14] & 0xf) * 4 + 2), delta));
			//update ip
			//remote[14 + 18] = 18;
			remote[14 + 19] = info.ori_host;
			//update id
			*(unsigned short *)(remote + 14 + (remote[14] & 0xf) * 4 + 4) = htons(info.ori_port);
		}
		else
			continue;
		sendto(sock, remote, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
	}
}

int main(int argc, char **argv)
{
	int n, err, delta;
	unsigned short port;
	struct ifreq ifr;
	pthread_t pt;
	if (argc != 4)
	{
		printf("interface local_ip gateway_mac\n");
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
	gateway_mac[0] = htoi(argv[3]);
	gateway_mac[1] = htoi(argv[3] + 3);
	gateway_mac[2] = htoi(argv[3] + 6);
	gateway_mac[3] = htoi(argv[3] + 9);
	gateway_mac[4] = htoi(argv[3] + 12);
	gateway_mac[5] = htoi(argv[3] + 15);
	local_ip = atoi(argv[2]);
	bzero(&local_addr, sizeof(local_addr)); /*清空地址结构*/
	bzero(&client_addr, sizeof(client_addr));
	local_addr.sin6_family = AF_INET6;	  //协议族
	local_addr.sin6_port = htons(MYPORT); //协议端口
	local_addr.sin6_addr = in6addr_any;
	//IPv6任意地址
	/*local_addr.sin_family = AF_INET;	 //协议族
	local_addr.sin_port = htons(MYPORT); //协议端口
	local_addr.sin_addr.s_addr = INADDR_ANY;*/
	client_addr.sin6_family = AF_INET6; //协议族
	//client_addr.sin_family = AF_INET; //协议族
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
	init();
	printf("mac:%02X-%02X-%02X-%02X-%02X-%02X\n", local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
	pthread_create(&pt, NULL, (void *)wan, NULL);
	pthread_create(&pt, NULL, (void *)arp, argv[1]);
	while (1)
	{

		n = recvfrom(sock, local, 2048, 0, (struct sockaddr *)&client_addr, &len);
		if (local[14 + 9] == 6)
		{ //TCP
			//update ip checksum
			delta = local[14 + 15] - local_ip;
			*(unsigned short *)(local + 14 + 10) = htons(update_checksum(get_word(local + 14 + 10), delta));
			//update tcp checksum
			port = get_tra(local[14 + 15], get_word(local + 14 + (local[14] & 0xf) * 4), TCP);
			if (port == 0xffff)
				continue;
			delta += get_word(local + 14 + (local[14] & 0xf) * 4) - port;
			*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4 + 16) = htons(update_checksum(get_word(local + 14 + (local[14] & 0xf) * 4 + 16), delta));
			//update ip
			//local[14 + 14] = 36;
			local[14 + 15] = local_ip;
			//update port
			*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4) = htons(port);
		}
		else if (local[14 + 9] == 17)
		{ //UDP
			//update ip checksum
			delta = local[14 + 15] - local_ip;
			*(unsigned short *)(local + 14 + 10) = htons(update_checksum(get_word(local + 14 + 10), delta));
			port = get_tra(local[14 + 15], get_word(local + 14 + (local[14] & 0xf) * 4), UDP);
			if (port == 0xffff)
				continue;
			if (get_word(local + 14 + (local[14] & 0xf) * 4 + 6) != 0)
			{
				//update udp checksum
				delta += get_word(local + 14 + (local[14] & 0xf) * 4) - port;
				*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4 + 6) = htons(update_checksum(get_word(local + 14 + (local[14] & 0xf) * 4 + 6), delta));
			}
			//update ip
			//local[14 + 14] = 36;
			local[14 + 15] = local_ip;
			//update port
			*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4) = htons(port);
		}
		else if (local[14 + 9] == 1)
		{
			//ICMP(Request/Reply)
			//update ip checksum
			delta = local[14 + 15] - local_ip;
			*(unsigned short *)(local + 14 + 10) = htons(update_checksum(get_word(local + 14 + 10), delta));
			port = get_tra(local[14 + 15], get_word(local + 14 + (local[14] & 0xf) * 4 + 4), UDP);
			if (port == 0xffff)
				continue;
			//update icmp checksum
			delta = get_word(local + 14 + (local[14] & 0xf) * 4 + 4) - port;
			*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4 + 2) = htons(update_checksum(get_word(local + 14 + (local[14] & 0xf) * 4 + 2), delta));
			//update ip
			//local[14 + 14] = 36;
			local[14 + 15] = local_ip;
			//update id
			*(unsigned short *)(local + 14 + (local[14] & 0xf) * 4 + 4) = htons(port);
		}
		else
			continue;

		memcpy(local, gateway_mac, 6);
		memcpy(local + 6, local_mac, 6);
		sendto(s, local, n, 0, (struct sockaddr *)&to, sizeof(to));
	}
}