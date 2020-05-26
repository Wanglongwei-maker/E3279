
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#define  MAX_DATA_BLOCK_SIZE 8192
void error_exit(const char * msg, int val);
void send_file(const char * file_name, const char * ip, u_short port);
int main(int argc, char** argv) {
	u_short port;
	if (argc == 3) {
		send_file(argv[1], argv[2], 8888);
	}
	else if (argc == 4) {
		port = (u_short)atoi(argv[1]);
		if (port == 0) {
			error_exit("非法服务器端口", -1);
		}
		else {
			send_file(argv[1], argv[2], port);
		}
	}
	else {
		error_exit("参数错误", -1);
	}
	return 0;
}
void error_exit(const char* msg, int val) {
	if (msg) {
		printf("%s\n\n", msg);
	}
	printf("使用方式： ft_client<文件名><服务器IP地址>[服务器端口]\n");
	printf("服务器端口是可选参数，默认为8888\n\n");
	exit(val);
}
void send_file(const char* file_name, const char* ip, u_short port) {

	WSADATA wsaData;
	SOCKET s;
	FILE *fp;
	struct sockaddr_in server_addr;
	char data[MAX_DATA_BLOCK_SIZE];
	int i;
	int ret;
	fp = fopen(file_name, "rb");
	if (fp == NULL) {
		printf("无法打开文件\n");
		return;
	}
	WSAStartup(0x202, &wsaData);
	s = socket(AF_INET, SOCK_STREAM, 0);
	memset((void *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(port);
	if (connect(s, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
		printf("连接服务器失败\n");
		fclose(fp);
		closesocket(s);
		WSACleanup();
		return;
	}
	printf("发送文件名。。。\n");
	send(s, file_name, strlen(file_name), 0);
	send(s, "\0", 1, 0);
	printf("发送文件内容");
	for (;;) {
		memset((void *)data, 0, sizeof(data));
		i = fread(data, 1, sizeof(data), fp);
		if (i == 0) {
			printf("\n发送成功\n");
			break;
		}
		ret = send(s, data, i, 0);
		putchar('.');
		if (ret == SOCKET_ERROR) {
			printf("\n发送失败，文件可能不完整\n");
			break;
		}
	}
	fclose(fp);
	closesocket(s);
	WSACleanup();


}

