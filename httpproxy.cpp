#define _CRT_SECURE_NO_WARNINGS
#include "httpproxy.h"
#include "plugin/sm4_impl.h"
#include <ctype.h>
#define u8 unsigned char
#define u32 unsigned long
int listen_port = 8899; string server_ip; bool flag;
int len = 0;
u8 key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };




bool AnalyzeClientRequest(string *client_request, client_request_summary *crs)
{
	int startPos = -1;
	int endPos = -1;
	endPos = client_request->find(" ht", 0);
	if (endPos == string::npos)
	{
		//	Msg("客户端请求头格式错误\r\n");
		return false;
	}

	startPos = 0;

	char *request_type = new char[endPos + 2];
	ZeroMemory(request_type, endPos + 2);
	memcpy(request_type, (char *)(*client_request).c_str(), endPos);

	crs->type = request_type;

	startPos = client_request->find("://", endPos) + 3;
	//这里还应该加入获取端口号的代码

	endPos = client_request->find("/", startPos);
	char *request_host = new char[endPos - startPos + 2];
	ZeroMemory(request_host, endPos - startPos + 2);
	memcpy(request_host, (char *)(*client_request).c_str() + startPos, endPos - startPos);

	crs->host = request_host;

	startPos = endPos;
	endPos = client_request->find(" HTTP/1", startPos);
	char *request_url = new char[endPos - startPos + 2];
	ZeroMemory(request_url, endPos - startPos + 2);
	memcpy(request_url, (char *)(*client_request).c_str() + startPos, endPos - startPos);

	crs->url = request_url;

	startPos = client_request->find("Range: ", endPos);
	if (startPos == string::npos)
	{
		delete[]request_host;
		delete[]request_type;
		delete[]request_url;
		return true;
	}
	startPos += 7;
	endPos = client_request->find("\r\n", startPos);
	char * request_range = new char[endPos - startPos + 2];
	ZeroMemory(request_range, endPos - startPos + 2);
	memcpy(request_range, (char *)(*client_request).c_str() + startPos, endPos - startPos);

	crs->range = request_range;

	delete[]request_host;
	delete[]request_type;
	delete[]request_url;
	delete[]request_range;
	return true;
}

void WorkThread(void *pvoid)//void WorkThread(void *pvoid, boolen flag, string 代理IP, string 代理port) flag区分客户端1与服务端0
{
	WORKPARAM *pWork = (WORKPARAM *)pvoid;
	unsigned long recvstatus = 0;
	string client_request, tmp;
	char temp[2049], c;
	u8 decode_Result[2049] = { 0 };
	ZeroMemory(temp, 2049);
	ZeroMemory(decode_Result, 2049);
	if (flag == true) {
		for (int header_len = 0; header_len < 2048; header_len++)
		{
			if (recv(pWork->sckClient, &c, 1, 0) == 0)
			{
				break;
			}
			temp[header_len] = c;
			if (temp[header_len] == '\n'&&
				temp[header_len - 1] == '\r'&&
				temp[header_len - 2] == '\n'&&
				temp[header_len - 3] == '\r')
			{
				break;
			}
			if (recvstatus == SOCKET_ERROR)
			{
				Msg("接收客户端请求头失败\r\n");
				break;
			}

		}
		client_request += temp;
	}
	else
	{
		if (recv(pWork->sckClient, temp, 2048, 0) == 0)
		{
			Msg("recv error\n");
		}


		cout << strlen(temp) << endl;
		if (temp[0] == 'G' && temp[1] == 'E' && temp[2] == 'T')
		{
			client_request += temp;
		}
		else
		{
			decode_fun(512+1024, key, (u8 *)(temp), decode_Result);
			cout << "decode result:" << decode_Result << endl;
			for (int header_len = 0; header_len < 2048; header_len++)
			{
				if (decode_Result[header_len] == '\n'&&
					decode_Result[header_len - 1] == '\r'&&
					decode_Result[header_len - 2] == '\n'&&
					decode_Result[header_len - 3] == '\r')
				{
					break;
				}
				if (recvstatus == SOCKET_ERROR)
				{
					Msg("接收客户端请求头失败\r\n");
					break;
				}

			}
			client_request += (char *)decode_Result;
		}

	}


	cout << "客户端的请求内容：" << endl << client_request << endl;
	client_request_summary crs;
	if (!AnalyzeClientRequest(&client_request, &crs))
	{
		return;
	}
	cout << "请求类型:" << crs.type << endl;
	cout << "请求主机:" << crs.host << endl;
	cout << "请求资源:" << crs.url << endl;
	if (!crs.range.empty())
	{
		cout << "请求Range:" << crs.range << endl;
	}
	//free crs flag=1
	SOCKET m_socket;
	struct protoent *pv;
	pv = getprotobyname("tcp");
	m_socket = socket(PF_INET, SOCK_STREAM, pv->p_proto);
	if (m_socket == INVALID_SOCKET)
	{
		Msg("创建套接字失败!\r\n");
		return;
	}
	//140 if flag=1时到代理ip 意思是flag=1时ip_addr=代理ip且将151行port从80->8899//140-147仅在flag=0时使用
	struct sockaddr_in destaddr;
	struct in_addr ip_addr;
	if (flag == true)
	{
		hostent *m_phostip = gethostbyname(server_ip.c_str());
		if (m_phostip == NULL)
		{
			Msg("所请求的域名解析失败!\r\n");
			return;
		}

		memcpy(&ip_addr, m_phostip->h_addr_list[0], 4);
		memset((void *)&destaddr, 0, sizeof(destaddr));
		destaddr.sin_family = AF_INET;
		destaddr.sin_port = htons(8899);
		destaddr.sin_addr = ip_addr;
	}
	else
	{
		hostent *m_phostip = gethostbyname(crs.host.c_str());
		if (m_phostip == NULL)
		{
			Msg("所请求的域名解析失败!\r\n");
			return;
		}
		memcpy(&ip_addr, m_phostip->h_addr_list[0], 4);
		memset((void *)&destaddr, 0, sizeof(destaddr));
		destaddr.sin_family = AF_INET;
		destaddr.sin_port = htons(80);
		destaddr.sin_addr = ip_addr;
	}
	if (connect(m_socket, (struct sockaddr*)&destaddr, sizeof(destaddr)) != 0)
	{
		/*	Msg("连接到目标服务器失败!\r\n");*/
		return;
	}

	long recvlength = 0;
	string m_RequestHeader; //160-180 仅在flag=0时使用，flag=1时 m_RequestHeader=client_request 并复用176-180
	if (flag == false)
	{
		m_RequestHeader = m_RequestHeader + crs.type + " " + crs.url + " HTTP/1.1\r\n";
		m_RequestHeader = m_RequestHeader + "Host: " + crs.host + "\r\n";
		m_RequestHeader = m_RequestHeader + "Connection: keep-alive\r\n";
		m_RequestHeader = m_RequestHeader + "User-Agent: Novasoft NetPlayer/4.0\r\n";
		/*	m_RequestHeader=m_RequestHeader+"Cache-Control: max-age=0\r\n";*/
		m_RequestHeader = m_RequestHeader + "Accept: */*\r\n";
		/*	m_RequestHeader=m_RequestHeader+"Origin:  http://222.73.105.196\r\n";*/
		/*	m_RequestHeader=m_RequestHeader+"Cookie: saeut=61.188.187.53.1323685584721318\r\n";*/
		if (!crs.range.empty())
		{
			m_RequestHeader = m_RequestHeader + "Range: " + crs.range + "\r\n";
		}
		m_RequestHeader += "\r\n";
	}
	else
	{

		u8 encode_Result[3000] = { 0 };
		u8 decode_Result[3000] = { 0 };
		u8* plain;
		plain = (u8 *)malloc(3000);
		len = client_request.length();
		cout << "len:" << len << endl;
		plain = (u8 *)(client_request.c_str());
		printf("%s", plain);
		encode_fun(strlen((char *)plain), key, plain, encode_Result);

		print_hex(encode_Result, len);

		decode_fun(512 + 1024, key, encode_Result, decode_Result);
		if (strlen((char *)encode_Result) < len && (strlen((char *)decode_Result) != len) && !valid((char *)decode_Result))

		{
			cout << "failed !" << strlen((char *)encode_Result) << ' ' << len << endl;
			m_RequestHeader += client_request;
		}

		else
		{
			cout << "decodeddddddddddddddddddddddd" <<decode_Result << endl;
			m_RequestHeader += (char *)encode_Result;
		}
	}

	if (send(m_socket, m_RequestHeader.c_str(), m_RequestHeader.length(), 0) == SOCKET_ERROR)
	{
		Msg("向服务器发送请求失败!\r\n");
		return;
	}
	char buffer[512001];
	string target_response;
	ZeroMemory(temp, 2049);
	unsigned int recv_sta = 0, send_sta = 0;


	for (int header_len = 0; header_len < 2048; header_len++)
	{
		if (recv(m_socket, &c, 1, 0) == 0)
		{
			break;
		}
		temp[header_len] = c;
		if (temp[header_len] == '\n'&&
			temp[header_len - 1] == '\r'&&
			temp[header_len - 2] == '\n'&&
			temp[header_len - 3] == '\r')
		{
			break;
		}
		if (recvstatus == SOCKET_ERROR)
		{
			Msg("接收目标服务器响应头失败\r\n");
			break;
		}
	}

	target_response = temp;

	cout << "目标服务器响应:" << target_response << endl;
	long content_len = GetContentLength(&target_response);
	long n_recvd = 0, n_sended = 0;

	send(pWork->sckClient, target_response.c_str(), target_response.length(), 0);
	while (1)
	{
		ZeroMemory(buffer, 512001);
		recv_sta = recv(m_socket, buffer, 512000, 0);
		if (recv_sta == 0 || recv_sta == SOCKET_ERROR)
		{
			break;
		}
		n_recvd += recv_sta;

		send_sta = send(pWork->sckClient, buffer, recv_sta, 0);
		if (SOCKET_ERROR == send_sta || send_sta == 0)
		{
			break;
		}
		n_sended += send_sta;
		if (n_recvd >= content_len || n_sended >= content_len)
		{
			break;
		}
		Sleep(100);
	}
	closesocket(pWork->sckClient);
	closesocket(m_socket);

	Msg("一个传输线程结束...\r\n");
	return;

}

void ListenThread(void *pvoid)
{
	int iRet = 0, addrLen = 0;
	sockaddr_in local_addr, accept_addr;
	SOCKET sckListen, sckAccept;
	int nErrCount;

	sckListen = socket(AF_INET, SOCK_STREAM, 0);
	if (sckListen == INVALID_SOCKET)
	{
		Msg("创建代理服务器的监听Socket失败\r\n");
		return;
	}
	hostent* pEnt = gethostbyname("");
	if (!pEnt)
	{
		Msg("创建代理服务器的gethostbyname()失败\r\n");
		return;
	}
	memcpy(&(local_addr.sin_addr), pEnt->h_addr, pEnt->h_length);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(listen_port);

	string strLocalAddr;
	strLocalAddr = inet_ntoa(local_addr.sin_addr);

	iRet = bind(sckListen, (const sockaddr*)&local_addr, sizeof(local_addr));
	if (iRet == SOCKET_ERROR)
	{
		Msg("创建代理服务器时绑定出错.\r\n");
		return;
	}

	nErrCount = 0;
	Msg("代理服务器:127.0.0.1 端口:8899\r\n");
	iRet = listen(sckListen, SOMAXCONN);
	if (iRet == SOCKET_ERROR)
	{
		Msg("代理服务器监听失败\r\n");
		nErrCount++;
		if (nErrCount >= 10)
		{
			Msg("nErrCount>=10, listening thread terminated.\r\n");
			return;
		}
	}
	nErrCount = 0;

	while (1)
	{
		addrLen = sizeof(accept_addr);
		sckAccept = accept(sckListen, (struct sockaddr*)&accept_addr, &addrLen);
		if (sckAccept == INVALID_SOCKET)
		{
			Msg("接受客户端连接失败\r\n");
			return;
		}
		Msg("创建一个传输线程...\r\n");
		/*		b_Proxy=true;*/
		WORKPARAM *pWorkParam = (WORKPARAM*)malloc(sizeof(WORKPARAM));
		pWorkParam->sckClient = sckAccept;
		pWorkParam->client_addr = accept_addr;
		_beginthread(WorkThread, 0, (void *)pWorkParam);
	}

	return;
}


int main(int argc, char **argv)
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		return false;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		return false;
	}


	if (argc == 1)//argc==1则为服务器，否则是客户端需要吸收ip；
	{
		flag = false;
		printf("以服务器模式启动\n");
	}
	else if (argc == 2)
	{
		flag = true;
		server_ip = argv[1];

		cout << "以代理模式启动，代理服务器ip为：" << server_ip << endl;
	}
	else
	{
		return false;
	}


	_beginthread(ListenThread, 0, NULL);
	while (true)
	{
		Sleep(10000000);
	}

}