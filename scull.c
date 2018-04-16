/*
 * scull.c
 *
 *  Created on: Apr 7, 2018
 *      Author: parallels
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>


#include <errno.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <net/if.h>

/**
 * get macAddress and ipAddress
 */
int GetLocalMac (const char * device,char * mac,char *ip) {
	int sockfd;
	struct ifreq req;
	struct sockaddr_in * sin;

	if ((sockfd = socket(PF_INET,SOCK_DGRAM,0)) < 0) {
		printf("access socket interface error");
		return -1;
	}

	memset(&req,0,sizeof(req));
	strcpy(req.ifr_name,device);
	if (ioctl(sockfd,SIOCGIFHWADDR,(char*)&req) < 0) {
		printf("ioctl SIOCGIFHWADDR:%s\n",strerror(errno));
		return -1;
	}
	memcpy(mac,req.ifr_hwaddr.sa_data,6);

	req.ifr_addr.sa_family = PF_INET;
	if (ioctl(sockfd,SIOCGIFADDR,(char*)&req) < 0) {
		printf("ioctl SIOCGIFADDR:%s\n",strerror(errno));
		return -1;
	}
	sin = (struct sockaddr_in *)&req.ifr_addr;
	memcpy(ip,(char*)&sin->sin_addr,4);

	return 0;
}

/*
 * show macAddress
 */
char * mac_ntoa (const unsigned char * mac) {
	static char buffer[18];
	memset(buffer,0,sizeof(buffer));
	sprintf(buffer,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return buffer;
}

/*
 * define the structure that describe ARP message
 *
 *  _______________________________________________________________________________________________________________
 * |			 |			   |ether|		|	   |ar_|ar_|	 |			   |		 |			   |		   |
 * | ether_dhost | ether_shost |_type|ar_hrd|ar_pro|hln|pln|ar_op|   arp_sha   | arp_spa |   arp_tha   |  arp_tpa  |
 * |_____________|_____________|_____|______|______|___|___|_____|_____________|_________|_____________|___________|
 *
 * 		6		       6	      2      2      2    1   1    2			6			  4			6			 4
 *
 */
struct _Ether_pkg {
	/*
	 * header of Ethernet
	 */
	unsigned char ether_dhost[6];	//destination of hardware address
	unsigned char ether_shost[6];	//source hardware address
	unsigned short int ether_type;	//type : 1.ARP 2.RARP 3.IP

	/*
	 * ARP message
	 */
	unsigned short int ar_hrd;		//type of hardware address (here is Ethernet)
	unsigned short int ar_pro;		//type of protocol address (here is IP)
	unsigned char ar_hln;			//length of hardware address (here is 6 byte)
	unsigned char ar_pln;			//length of protocol address (here is 4 byte)
	unsigned short int ar_op;		//operation type : 1.ARP request 2.ARP response 3.RARP request 4.RARP response
	unsigned char arp_sha[6];		//source hardware address (here is Ethernet address)
	unsigned char arp_spa[4];		//source protocol address (here is IP address)
	unsigned char arp_tha[6];		//destination hardware address (here is Ethernet address)
	unsigned char arp_tpa[4];		//destination protocol address (here is IP address)
};

typedef struct _Ether_pkg Ether_pkg;

void parse_ether_package(const Ether_pkg * pkg ){
	printf ( "\nsrc IP=[%s] MAC=[%s]\n",inet_ntoa ( * ( struct in_addr * ) pkg->arp_spa ),mac_ntoa ( pkg->arp_sha ) );
	printf ( "dst IP=[%s] MAC=[%s]\n",inet_ntoa ( * ( struct in_addr * ) pkg->arp_tpa ),mac_ntoa ( pkg->arp_tha ) );
}

/*
 * send ARP message
 */
int sendpkg (char * mac,char * broad_mac,char * ip,char * dest) {
	Ether_pkg pkg;
	/*
	struct hostent
	{
		char *h_name;         //正式主机名
		char **h_aliases;     //主机别名
		int h_addrtype;       //主机IP地址类型：IPV4-AF_INET
		int h_length;         //主机IP地址字节长度，对于IPv4是四字节，即32位
		char **h_addr_list;   //主机的IP地址列表
	};
	#define h_addr h_addr_list[0]   //保存的是IP地址
	 */
	struct hostent * host = NULL;
	struct sockaddr sa;
	int sockfd,len;
	unsigned char buffer[255];
	memset((char *)&pkg,'\0',sizeof(pkg));//clear the space of structure Rther_pkg

	//fill the Ethernet header
	memcpy((char *)pkg.ether_dhost,(char *)broad_mac,6);
	memcpy((char *)pkg.ether_shost,(char *)mac,6);
	pkg.ether_type = htons(ETHERTYPE_ARP);

	//fill the ARP message
	pkg.ar_hrd = htons(ARPHRD_ETHER);
	pkg.ar_pro = htons(ETHERTYPE_IP);
	pkg.ar_hln = 6;
	pkg.ar_pln = 4;
	pkg.ar_op = htons(ARPOP_REQUEST);
	memcpy((char *)pkg.arp_sha,(char *)mac,6);
	memcpy((char*)pkg.arp_spa,(char*)ip,4);
	memcpy((char*)pkg.arp_tha,(char*)broad_mac,6);//I feel this is useless

	//resolve destination IP address
	fflush(stdout);
	memset(ip,'\0',sizeof(ip));
	if (inet_aton(dest,(struct in_addr*)ip) == 0) {
		if ((host = gethostbyname(dest)) == NULL) {
			printf("destination IP format error\n%s\n",hstrerror(h_errno));
			return -1;
		}
		memcpy((char*)ip,host->h_addr,4);
	}

	memcpy((char*)pkg.arp_tpa,(char*)ip,4);

	//create socket
	if ((sockfd = socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL))) < 0) {
		printf("create raw socket failed:%s\n",strerror(errno));
		return 0;
	}

	memset(&sa,'\0',sizeof(sa));
	strcpy(sa.sa_data,"eth1");

	//send ARP message
	len = sendto(sockfd,&pkg,sizeof(pkg),0,&sa,sizeof(sa));
	if (len != sizeof(pkg)) {
		printf("send to error:%s\n",strerror(errno));
		return 0;
	}

	Ether_pkg * parse;
	parse = (Ether_pkg*)buffer;

	/*
	 * int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);
	 */
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(sockfd,&readfds);

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 5000;

	printf("1\n");
	len = select(sockfd+1,&readfds,0,0,&tv);
	printf("2\n");
	if (len > -1) {
		printf("3\n");
		//there are some available file descriptors
		if (FD_ISSET(sockfd,&readfds)) {
			memset(buffer,0,sizeof(buffer));
			printf("4\n");
			/**
			 * ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen);
			 *
			 */
			len = recvfrom(sockfd,buffer,sizeof(buffer),0,NULL,&len);
			printf("5\n");
			printf("ETHERTYPE_ARP:%d\n",ETHERTYPE_ARP);
			printf("parse->ether_type:%d\n",parse->ether_type);
			//htons(ETHERTYPE_ARP)
			//ntohs(parse->ether_type
			printf("htons(ETHERTYPE_ARP):%d\n",htons(ETHERTYPE_ARP));
			printf("ntohs(parse->ether_type):%d\n",ntohs(parse->ether_type));
			if ((ntohs(parse->ether_type) == ETHERTYPE_ARP) &&
					(ntohs(parse->ar_op) == ARPOP_REPLY)) {
				printf("6\n");
				parse_ether_package(parse);
			} else {
				printf("here recv packet is not arp!!!\n");
				int i;
				for (i = 0;i < sizeof(buffer);i++) {
					printf("%d,",buffer[i]);
				}
			}
		} else {
			printf("time is comeing here\n");
		}
	} else {
		printf("select is return < 0here!!!\n");
	}
	return 1;
}

int main () {
	unsigned char mac[7];
	unsigned char ip[5];

	memset(mac,0,sizeof(mac));
	memset(ip,0,sizeof(ip));

	if (GetLocalMac("eth1",mac,ip) == -1)
		printf("get address error\n");

	struct in_addr iaddr;
	memcpy(&iaddr.s_addr,ip,4);
	//char *inet_ntoa (struct in_addr)
	printf("local Mac=[%s] Ip=[%s]\n",mac_ntoa(mac),inet_ntoa(iaddr));

	char dest[16] = {0};
	memset(dest,0,sizeof(dest));
	sprintf(dest,"10.211.55.1");

	unsigned char broad_mac[7] = {0xff,0xff,0xff,0xff,0xff,0xff,0x00};

	sendpkg(mac,broad_mac,ip,dest);

	return 0;
}


//extern int register_chrdev_region(dev_t, unsigned, const char *);
