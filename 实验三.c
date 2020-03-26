/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define HAVE_REMOTE
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

 /* 4�ֽڵ�IP��ַ */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) +Internet header length(4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragmentoffset(13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;

typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* UDP �ײ�*/
typedef struct udp_header {
	u_short sport;          // Դ�˿�(Source port)
	u_short dport;          // Ŀ�Ķ˿�(Destination port)
	u_short len;            // UDP���ݰ�����(Datagram length)
	u_short crc;            // У���(Checksum)
}udp_header;

/* �ص�����ԭ�� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int count = 0;
struct timeval old_ts = { 0,0 };
time_t timep;
struct tm *p;
time_t oldtime;
int all_len = 0;
int old_time;
#define FROM_NIC

main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
#ifdef FROM_NIC
	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf  )
	//source �����ǡ�rpcap://������ʾ������������#define PCAP_SRC_IF_STRING ��rpcap://�� 
	//auth:ָ��pcap_rmtauth�ṹ��ָ�룬�����������ӵ�Զ����������Ȩ��Ϣ���ڲ�ѯ���ػ���ʱ���˲���ûʲô���壬����ΪNULL��
	//alldevs: ָ��pcap_if_t�ṹ��ָ�룬�˺�������ʱ����ָ�뱻����Ϊ����õ��豸�ӿ��б�ĵ�һ��Ԫ�أ��б��ÿһ��Ԫ�ض���Pcap_if_t�ṹ��
	//����ֵ���ɹ�����0��alldevs�����豸�б�alldevs����ΪNULL�����򷵻أ�1���Ǿ���˵ϵͳû���κνӿڿ����оٵġ��������Ϣ��errbuf���淵��

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}


	time(&timep);
	p = localtime(&timep); //�˺�����õ�tm�ṹ���ʱ�䣬���Ѿ����й�ʱ��ת��Ϊ����ʱ�� 
	oldtime = timep;
	old_time = time(&oldtime);
	//if (pcap_setmode(adhandle, MODE_STAT)<0)
	//{
	//	fprintf(stderr, "\nError setting the mode.\n");
	//	pcap_close(adhandle);
	//	/* �ͷ��豸�б� */
	//	return;
	//}


	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\Allen\\Desktop\\dns.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	mac_header *mh;
	ip_header *ih;
	time_t local_tv_sec;
	//time_t timep;
	//struct tm *p;
	time(&timep);
	p = localtime(&timep); //�˺�����õ�tm�ṹ���ʱ�䣬���Ѿ����й�ʱ��ת��Ϊ����ʱ�� 
	printf("%d-%d-%d ", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday);

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s  ", timestr);
	/* ��ӡ���ݰ��ĳ��� */
	printf("len:%d\n ", header->len);
	int length = sizeof(mac_header) + sizeof(ip_header); 
	for (int i = 0; i<length; i++) {
		printf("%02X ", pkt_data[i]); 
		if ((i & 0xF) == 0xF) printf("\n"); 
	}
	printf("\n");
	mh = (mac_header*)pkt_data; printf("mac_header:\n"); 
	printf("\tdest_addr: ");
	for (int i = 0; i<6; i++)
	{ 
		printf("%02X ", mh->dest_addr[i]); 
	} 
	printf("\n"); 
	printf("\tsrc_addr: "); 
	for (int i = 0; i<6; i++) 
	{ printf("%02X ", mh->src_addr[i]);
	
	}
	printf("\n"); 	
	printf("\ttype: %04X", ntohs(mh->type[6])); 
	printf("\n");
	ih = (ip_header *)(pkt_data + sizeof(mac_header)); //length of ethernet header
	
	printf("ip_header\n"); 
	printf("\t%-10s: %02X\n", "ver_ihl", ih->ver_ihl); 
	printf("\t%-10s: %02X\n", "tos", ih->tos);
	printf("\t%-10s: %04X\n", "tlen", ntohs(ih->tlen)); 
	printf("\t%-10s: %04X\n", "identification", ntohs(ih->identification));
	printf("\t%-10s: %04X\n", "flags_fo", ntohs(ih->flags_fo)); 
	printf("\t%-10s: %02X\n", "ttl", ih->ttl); 
	printf("\t%-10s: %02X\n", "proto", ih->proto); 
	printf("\t%-10s: %04X\n", "crc", ntohs(ih->crc)); 
	printf("\t%-10s: %08X\n", "op_pad", ntohs(ih->op_pad));
	printf("\t%-10s: ", "saddr:");
	for (int i = 0; i<4; i++) 
	{ 
		printf("%02X ", ih->saddr[i]); 
	} 
	printf(" "); 
	for (int i = 0; i<4; i++)
	{ 
		printf("%d.", ih->saddr[i]);
	}
	printf("\n"); 
	printf("\t%-10s: ", "daddr");
	for (int i = 0; i<4; i++) 
	{ 
		printf("%02X ", ih->daddr[i]); 
	} 
	printf(" "); 
	for (int i = 0; i<4; i++) 
	{ printf("%d.", ih->daddr[i]); } 
	printf("\n");

}