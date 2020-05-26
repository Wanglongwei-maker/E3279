
#include<stdio.h>

#include<string.h>

#include<Winsock2.h>

#pragma comment(lib,"ws2_32.lib")

int main()

{

	WSAData wsaData;

	int err = WSAStartup(WINSOCK_VERSION, &wsaData);

	if (0 != err)

	{

		return -1;

	}

	SOCKET sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (INVALID_SOCKET == sock)

	{

		printf("socket()Failed:%d\n", WSAGetLastError());

		WSACleanup();

		return -1;

	}



	char data[] = "Hello World!";

	char dest_ip[] = "222.196.201.224";      //Ŀ��IP

	unsigned short dest_port = 20000;//Ŀ�Ķ˿�



	sockaddr_in RemoteAddr;

	RemoteAddr.sin_family = AF_INET;

	RemoteAddr.sin_port = htons(dest_port);

	RemoteAddr.sin_addr.s_addr = inet_addr(dest_ip);





	char path[100] = { "0" };

	while (1)

	{

		printf("�������ļ�·��:  (����D:\\1.txt)\n");

		gets_s(path);

		FILE* fp = fopen(path, "rb"); // ��д�������ļ� �ǵ� ��  b



		if (!fp)

		{

			printf("error!");

			return 1;

		}



		else

		{

			printf("�ļ��Ѿ��򿪣��ȴ�����...\n");

		}



		char rbuf[1024] = { 0 };

		while (!feof(fp))

		{

			sendto(sock, path, strlen(path), 0, (sockaddr*)&RemoteAddr, sizeof(RemoteAddr));

			memset(rbuf, 0, 1024);

			fread(rbuf, 1, 1024, fp);

			int sByte = sendto(sock, rbuf, strlen(rbuf), 0, (sockaddr*)&RemoteAddr, sizeof(RemoteAddr));

			if (SOCKET_ERROR == sByte)

			{

				printf("sendto()Failed:%d\n", WSAGetLastError());

				closesocket(sock);

				WSACleanup();

				return -1;

			}

		}

		fclose(fp);

	}

	closesocket(sock);

	WSACleanup();

	return 0;

}
