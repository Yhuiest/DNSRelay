#include <iostream>
#include <WS2tcpip.h>
#include "DNSRelay.h"
#include "cache.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS


int main(int argc, char **argv)
{
	if (parseArgu(argc, argv))
	{
		init();
		fd_set fdread;
		while (true)
		{
			FD_ZERO(&fdread);
			FD_SET(clientSock, &fdread);
			FD_SET(servSock, &fdread);
			TIMEVAL tv; //设置超时等待时间
			tv.tv_sec = 0;
			tv.tv_usec = 500;
			int ret = select(0, &fdread, NULL, NULL, &tv);
			
			if (ret == SOCKET_ERROR)
			{
				printf("ERROR:select %d\n", WSAGetLastError());
			}
			if (ret > 0)
			{
				if (FD_ISSET(clientSock, &fdread))
				{
					clientReceive();
				//	printf("*");
				}
				if (FD_ISSET(servSock, &fdread));
				{
					serverReceive();
				}
			}
		}
		/*int nonBlock = 1;
		ioctlsocket(clientSock, FIONBIO, (u_long FAR *)&nonBlock);
		ioctlsocket(servSock, FIONBIO, (u_long FAR *)&nonBlock);
		while (1)
		{
			clientReceive();
			serverReceive();
		}*/
	}
	else
	{
		printf("argument error\n");
		printf("set debugLevel\t\t\t-d/-D(more 'd' for higher level)\n"
			"set log file name\t\t-l/-L <log file name>\n"
			"set domain file\t\t\t-f/-F <domain list file>\n"
			"set host address\t\t-h/-F <address in decimalism>");
	}
	closesocket(clientSock);
	closesocket(servSock);
	WSACleanup();
	return 0;
}

bool init()
{
	cacheTrie->tree;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	clientSock = socket(AF_INET, SOCK_DGRAM, 0);
	servSock = socket(AF_INET, SOCK_DGRAM, 0);

	if (clientSock == INVALID_SOCKET || servSock == INVALID_SOCKET)
	{
		printf("ERROR:socket open failed!\n");
		return false;
	}

	memset(&clientSockAddr, 0, sizeof(clientSockAddr));
	clientSockAddr.sin_family = AF_INET;
	clientSockAddr.sin_addr.s_addr = INADDR_ANY;
	clientSockAddr.sin_port = htons(53);

	memset(&servSockAddr, 0, sizeof(servSockAddr));
	servSockAddr.sin_family = AF_INET;
	servSockAddr.sin_addr.s_addr = inet_addr(sAddress);
	servSockAddr.sin_port = htons(53);

	int on = 1;
	setsockopt(clientSock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

	if (bind(clientSock, (SOCKADDR *)&clientSockAddr, addrLen) < 0)
	{
		printf("ERROR:Could not bind:%s\n", strerror(errno));
	}
	switch (dLevel)
	{
	case mid:
	case high:
		char tmp[20] = {0};
		inet_ntop(AF_INET, &sAddress, tmp, INET_ADDRSTRLEN);
		printf("DNS server :%s\n", sAddress);
		printf("Listening on port:53\n");
		break;
	}

	for (int i = 0; i < ID_TABLE_SIZE; i++)
	{
		idTable[i].cliId = 0;
		idTable[i].exprieTime = 0;
		memset(&(idTable[i].cliAddr), 0, sizeof(struct sockaddr_in));
	}

	logName = fopen(logFile, "a+");
	//printf("%s", domainList);
	domain = fopen(domainList, "a+");
	if (domain == NULL)
	{
		printf("ERROR:Domain list open failed\n");
		exit(0);
	}
	/*
	pair<string, string> tmp;
	char buf[128];
	char ip1[20];
	while (!feof(domain))
	{
		fscanf(domain, "%s", ip1);
		fscanf(domain, "%s", buf);
		unsigned len = strlen(buf);
		for (int i = 0; i < len; i++)
		{
			if (buf[i] >= 'A' && buf[i] <= 'Z')
			{
				buf[i] += 32;
			}
		}
		tmp.first = buf;
		tmp.second = ip1;
		list.push_back(tmp);
	}*/

	cacheTrie = (struct Trie *)malloc(sizeof(struct Trie));
	memset(cacheTrie->tree, 0, MAX_ROW * MAX_COL);
	tableTrie = (struct Trie *)malloc(sizeof(struct Trie));
	memset(tableTrie->tree, 0, MAX_ROW * MAX_COL);
	cacheTrie->totalNode = 0;
	tableTrie->totalNode = 0;
	cacheSize = 0;

	char domainName[MAX_STR] = { 0 };
	char ipAddr[MAX_STR] = { 0 };

	unsigned char ip[4];
	while (!feof(domain))
	{
		fscanf(domain, "%s", ipAddr);
		fscanf(domain, "%s", domainName);
		tranIp(ip, ipAddr);
		insertNode(tableTrie, domainName, ip);
	}

	head = (struct Node *)malloc(sizeof(struct Node));
	head->next = NULL;
	tail = head;

	for (int i = 0; i < ID_TABLE_SIZE; i++)
	{
		idTable[i].cliId = 0;
		idTable[i].exprieTime = 0;
		memset(&(idTable[i].cliAddr), 0, sizeof(struct sockaddr_in));
	}
	return true;
}

int search(Packet *pkt)
{
	struct source *s;
	struct question *q;
	int ret = -1;

	pkt->pktHead->QR = 1;
	pkt->pktHead->RA = 1;
	pkt->pktHead->rcode = 0;
	pkt->pktHead->ancount = 0;
	pkt->pktHead->nscount = 0;
	pkt->pktHead->arcount = 0;

	q = pkt->pktQuestion;
	printCache();
	while (q)
	{
		s = (struct source *)malloc(sizeof(struct source));
		memset(s, 0, sizeof(struct source));

		s->name = strdup(q->qName);
		s->type = q->qType;
		s->Class = q->qClass;
		s->TTL = 3600;

		if (q->qType == 1)
		{
			s->rData = (char *)malloc(4 * sizeof(char));
			s->rdLength = 4;
			if (findInCache((unsigned char *)s->rData, q->qName))
			{
				switch (dLevel)
				{
				case mid:
					printf("Find in Cache\n");
					break;
				case high:
					printf("Find in Cache %s\n", q->qName);
				}
				ret = 0;
			}
			else if (findInTable((unsigned char *)s->rData, q->qName))
			{
				switch (dLevel)
				{
				case mid:
					printf("Find in Table\n");
					break;
				case high:
					printf("Find in Table %s\n", q->qName);
				}
				ret = 0;
			}
			else
			{
				switch (dLevel)
				{
				case mid :
				case high:
					printf("Can't find in local\n");
				}
				ret = -1;
			}
			if (s->rData[0] == 0 && s->rData[1] == 0
				&& s->rData[2] == 0 && s->rData[3] == 0)
			{
				switch (dLevel)
				{
				case mid:
					printf("Blocked\n");
					break;
				case high:
					printf("Blocked %s", q->qName);
				}
				pkt->pktHead->rcode = 3;
			}
			if (ret == 0)
			{
				pkt->pktHead->ancount++;
				s->next = pkt->pktAnswer;
				pkt->pktAnswer = s;
			}
			else
			{
				free(s->name);
				free(s->rData);
				free(s);
			}
		}
		q = q->next;
	}
	return ret;
}

bool parseArgu(int argc, char **argv)
{
	int dNum = 0;
	int32_t tmp;
	int i = 1;
	while (i <= argc - 1)
	{
		switch (argv[i][1])
		{
		case 'd':
		case 'D':
			for (int j = 1; argv[i][j]; j++)
			{
				if (argv[i][j] == 'd' || argv[i][j] == 'D')
				{
					dNum++;
				}
				else
				{
					return false;
				}
			}
			std::cout << dNum;
			if (dNum > 3)
			{
				return false;
			}
			else
			{
				dLevel = (debugLevel)(dNum - 1);
				std::cout << dLevel;
			}
			i++;
			break;
		case 'l':
		case 'L':
			memcpy(logFile, argv[i+1], strlen(argv[i+1]));
			i += 2;
			break;
		case 'h':
		case 'H':
			if ((tmp = inet_addr(argv[i + 1])) > 0)
			{
				//std::cout << sizeof(uint32_t) << std::endl;
				//std::cout << std::hex << tmp << std::endl;
				memcpy(sAddress, argv[i + 1], strlen(argv[i + 1]) + 1);
			}
			else
			{
				return false;
			}
			i += 2;
			break;
		case 'f':
		case 'F':
			memcpy(domainList, argv[i+1], strlen(argv[i+1]));
			i += 2;
			break;
		}
	}
	return true;
}

void clientReceive()
{
	//printf("C\n");
	int pktLen = 0;
	unsigned char buff[BUFFER_SIZE];
	Packet pkt;
	memset(&pkt, 0, sizeof(pkt));

	pktLen = recvfrom(clientSock, (char*)buff, sizeof(buff),
		0, (struct sockaddr *)&clientSockAddr, &addrLen);

	if (pktLen < 0)
	{
		printf("ERROR:receive packet from client error\n");
		return;
	}
	else
	{

		switch (dLevel)
		{
		case low:
			printf("Receive a packet from client\n");
			break;
		case mid:
			printf("Receive a packet from client:%s port:%d packet length:%d\n"
				, inet_ntoa(clientSockAddr.sin_addr)
				, ntohs(clientSockAddr.sin_port)
				, pktLen);
			break;
		case high:
			printf("Receive a packet from client:%s port:%d packet length:%d\n"
				, inet_ntoa(clientSockAddr.sin_addr)
				, ntohs(clientSockAddr.sin_port)
				, pktLen);
			printInHex(buff, pktLen);
		}
	}
	
	//printf("c\n");
	if (!decodePkt(&pkt, (char *)buff, pktLen))
	{
		printf("ERROR: Unpack packet error!\n");
		//exit(0);
	}
	time_t t;
	struct tm *lt;
	time(&t);
	lt = localtime(&t);
	fprintf(logName, "Requsest:%d\n%d-%02d-%02d\n%02d:%02d:%02d\nclient %15s : %-5d\n%s\n\n"
		, requestCnt++, (1900 + lt->tm_year), (1 + lt->tm_mon), lt->tm_mday
		, lt->tm_hour, lt->tm_min, lt->tm_sec
		, inet_ntoa(clientSockAddr.sin_addr), ntohs(clientSockAddr.sin_port), pkt.pktQuestion->qName);
	if (search(&pkt) != -1)
	{

		unsigned pktLen;
		if (!(pktLen = encodePkt(&pkt,(char*)buff)))
		{
			printf("ERROR:Encode packet error\n");
		}
		else
		{
			switch (dLevel)
			{
			case low:
				printf("Send to client\n");
				break;
			case mid:
				printf("Send to client:%s port:%d\n"
					, inet_ntoa(clientSockAddr.sin_addr)
					, ntohs(clientSockAddr.sin_port));
				break;
			case high:
				printf("Send to client:%s port:%d\n"
					, inet_ntoa(clientSockAddr.sin_addr)
					, ntohs(clientSockAddr.sin_port));
				printInHex(buff, pktLen);
				break;
			}
			time(&t);
			lt = localtime(&t);
			fprintf(logName, "Response:%d\n%d-%02d-%02d\n%02d:%02d:%02d\nclient %15s : %-5d\n Q:%s A:%s\n\n"
				, requestCnt++, (1900 + lt->tm_year), (1 + lt->tm_mon), lt->tm_mday
				, lt->tm_hour, lt->tm_min, lt->tm_sec
				, inet_ntoa(clientSockAddr.sin_addr), ntohs(clientSockAddr.sin_port), pkt.pktQuestion->qName
				,pkt.pktAnswer->rData);
			sendto(clientSock, (char *)buff, pktLen, 0, (struct sockaddr*)&clientSockAddr, addrLen);
		}
	}
	else
	{
		uint16_t i;
		for (i = 0; i < ID_TABLE_SIZE; i++)
		{
			if (idTable[i].exprieTime < time(NULL))
			{
				break;
			}
		}
		if (i == ID_TABLE_SIZE)
		{
			printf("ERROR: idTable is full");
			exit(0);
		}
		uint16_t servId = htons(i);
		idTable[i].cliAddr = clientSockAddr;
		idTable[i].cliId = pkt.pktHead->ID;
		idTable[i].exprieTime = time(NULL) + TIMEOUT;

		
		memcpy(buff, &servId, sizeof(uint16_t));
		switch (dLevel)
		{
		case low:
			printf("Send to server\n");
			break;
		case mid:
			printf("Send to server:%s port:%d id:%d len:%d\n"
			,servSockAddr.sin_addr,servSockAddr.sin_port,i,pktLen);
			break;
		case high:
			printf("Send to server:%s port:%d id:%d len:%d\n"
				, inet_ntoa(servSockAddr.sin_addr), ntohs(servSockAddr.sin_port), servId, pktLen);
			printInHex(buff, pktLen);
		}
		time(&t);
		lt = localtime(&t);
		fprintf(logName, "Relay:%d\n%d-%02d-%02d\n%02d:%02d:%02d\nserver %15s : %-5d\n Q:%s\n\n"
			, requestCnt++, (1900 + lt->tm_year), (1 + lt->tm_mon), lt->tm_mday
			, lt->tm_hour, lt->tm_min, lt->tm_sec
			, inet_ntoa(servSockAddr.sin_addr), ntohs(servSockAddr.sin_port), pkt.pktQuestion->qName);
		sendto(servSock, (char*)buff, pktLen, 0, (struct sockaddr*)&servSockAddr, sizeof(servSockAddr));
	}
	freePkt(&pkt);
}

void serverReceive()
{
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (setsockopt(servSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		printf("socket option  SO_RCVTIMEO not support\n");
		return;
	}

	int len = 0;
	char buf[BUFFER_SIZE];
	Packet pkt;
	memset(&pkt, 0, sizeof(struct packet));

	len = recvfrom(servSock, buf, sizeof(buf), 0, (struct sockaddr *)&servSockAddr, &addrLen);
	if (len > 0)
		printInHex((unsigned char*)buf, len);

	//printInHex((unsigned char*)buf, len);
	if (len == EWOULDBLOCK || len == EAGAIN)
	{
		printf("server timeout\n");
		return;
	}
	//printf("s\n");
	if (len < 0 || !decodePkt(&pkt, buf, len))
	{
		printf("Error:Receive from server error\n");
		return;
	}
	switch (dLevel)
	{
	case low:
		printf("Receive from server\n");
		break;
	case mid:
		printf("Receive from server:%s port:%d id:%d len:%d\n"
			, inet_ntoa(servSockAddr.sin_addr), ntohs(servSockAddr.sin_port), pkt.pktHead->ID, len);
		break;
	case high:
		printf("Receive from server:%s port:%d id:%d len:%d\n"
			, inet_ntoa(servSockAddr.sin_addr), ntohs(servSockAddr.sin_port), pkt.pktHead->ID, len);
		printInHex((unsigned char*)buf, len);
	}

	time_t t;
	struct tm *lt;
	time(&t);
	lt = localtime(&t);
	fprintf(logName, "Receive:%d\n%d-%02d-%02d\n%02d:%02d:%02d\nserver %15s : %-5d\n Q:%s\n\n"
		, requestCnt++, (1900 + lt->tm_year), (1 + lt->tm_mon), lt->tm_mday
		, lt->tm_hour, lt->tm_min, lt->tm_sec
		, inet_ntoa(servSockAddr.sin_addr), ntohs(servSockAddr.sin_port), pkt.pktQuestion->qName);
	uint16_t nId = pkt.pktHead->ID;
	uint16_t clientId = htons(idTable[nId].cliId);
	memcpy(buf, &clientId, sizeof(uint16_t));

	struct sockaddr_in ca = idTable[nId].cliAddr;

	//idTable[nId].exprieTime = 0;
	time(&t);
	lt = localtime(&t);
	fprintf(logName, "Reponse:%d\n%d-%02d-%02d\n%02d:%02d:%02d\nclient %15s : %-5d\n Q:%s\n\n"
		, requestCnt++, (1900 + lt->tm_year), (1 + lt->tm_mon), lt->tm_mday
		, lt->tm_hour, lt->tm_min, lt->tm_sec
		, inet_ntoa(clientSockAddr.sin_addr), ntohs(clientSockAddr.sin_port), pkt.pktQuestion->qName);
	sendto(clientSock, buf, len, 0, (struct sockaddr *)&ca, sizeof(ca));

	if (pkt.pktHead->ancount)
	{
		struct source *s = pkt.pktAnswer;
		while (s)
		{
			if (s->type == 1)
			{
				char *domainName = s->name;
				unsigned char *address = (unsigned char *)s->rData;
				updateCache(address, domainName);
				printCache();
			}
			s = s->next;
		}
	}
	freePkt(&pkt);
}

void printInHex(unsigned char *buff, unsigned len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%02x ", buff[i]);

		if (i % 16 == 15)
		{
			printf("\n");
		}
	}
	printf("\n");
}

//bool searchInList(Packet *pkt)
//{
//	Question *q = pkt->pktQuestion;
//	Source *r = (struct source*)malloc(sizeof(struct source));
//	while (q)
//	{
//		int i;
//		for (i = 0; i < list.size(); i++)
//		{
//			if (list[i].first == q->qName)
//			{
//				if (list[i].second != "0.0.0.0")
//				{
//					r->name = strdup(q->qName);
//					r->type = q->qType;
//					r->Class = q->qClass;
//					r->rdLength = 4;
//					r->TTL = 3600;
//					r->rData = (char *)malloc(r->rdLength * (sizeof(char)));
//					unsigned long tmp = inet_addr(list[i].second.c_str());
//					memcpy(r->rData, &tmp, 4);
//					r->next = pkt->pktAnswer;
//					pkt->pktAnswer = r;
//					(pkt->pktHead->ancount)++;
//				}
//				switch (dLevel)
//				{
//				case mid:
//					printf("Find in local file\n");
//					break;
//				case high:
//					printf("Find in local file,line:%d domain:%s ip:%s\n"
//						, i,list[i].first.c_str(),list[i].second.c_str());
//				}
//				return true;
//			}
//		}
//		if (i == list.size())
//		{
//			switch (dLevel)
//			{
//			case mid:
//				printf("Not find in local file\n");
//				break;
//			case high:
//				printf("Not find in local file domain:%s\n", q->qName);
//			}
//			return false;
//		}
//		q = q->next;
//	}
//	return true;
//}

bool decodePkt(Packet *pkt, char *buff, unsigned int len)
{
	//printf("*");
	pkt->pktHead = (struct header*)malloc(sizeof(struct header));
	/*pkt->pktQuestion = (struct question*)malloc(sizeof(struct question));
	pkt->pktQuestion->next = NULL;*/
	char *rawBuf = buff;
	getHeader(pkt->pktHead,buff);
	Header * head = pkt->pktHead;
	switch (dLevel)
	{
	case mid:
		printf("Header decode\n");
		break;
	case high:
		printf("Header decode id:%d qr:%d opcode:%d AA:%d TC:%d RD:%d \n\
			RA:%d rcode:%d qdcount:%d ancount:%d nscount:%d arcount:%d\n"
			, head->ID, head->QR, head->opcode, head->AA, head->TC, head->RD
			,head->RA,head->rcode,head->qdcount,head->ancount,head->nscount
			,head->arcount);
	}
	decodeQuestion(pkt, &buff);
	for (int i = 0; i < pkt->pktHead->ancount; i++)
	{
		if (i == 0)
		{
			pkt->pktAnswer = (struct source*)malloc(sizeof(struct source));
			pkt->pktAnswer->next = NULL;
		}
		else
		{
			Source *tmp = (struct source*)malloc(sizeof(struct source));
			tmp->next = pkt->pktAnswer;
			pkt->pktAnswer = tmp;
		}

		decodeSource(pkt->pktAnswer, &buff, rawBuf);
		switch (dLevel)
		{
		case mid:
			printf("Decode answer\n");
			break;
		case high:
			printf("Decode answer name:%s type:%d class:%d ttl:%d rdLength:%d \n"
			,pkt->pktAnswer->name,pkt->pktAnswer->type,pkt->pktAnswer->Class,pkt->pktAnswer->TTL
				,pkt->pktAnswer->rdLength);
		}
	}
	for (int i = 0; i < pkt->pktHead->nscount; i++)
	{
		if (i == 0)
		{
			pkt->pktAuthority = (struct source*)malloc(sizeof(struct source));
			pkt->pktAuthority->next = NULL;
		}
		else
		{
			Source *tmp = (struct source*)malloc(sizeof(struct source));
			tmp->next = pkt->pktAuthority;
			pkt->pktAuthority= tmp;
		}
		char * tmploc = rawBuf;
		decodeSource(pkt->pktAuthority, &buff, rawBuf);
		switch (dLevel)
		{
		case mid:
			printf("Decode authority\n");
			break;
		case high:
			printf("Decode authority name:%s type:%d class:%d ttl:%d rdLength:%d \n"
				, pkt->pktAuthority->name, pkt->pktAuthority->type, pkt->pktAuthority->Class, pkt->pktAuthority->TTL
				, pkt->pktAuthority->rdLength);
		}
	}
	return true;
}

bool decodeSource(Source *s, char **buf, char *raw)
{
	char *name = decodeDomain(buf,raw );
	s->name = name;
	if (!name)
	{
		printf("Error:Decode Source domain name failed\n");
		return false;
	}
	s->type = get16bit(buf);
	s->Class = get16bit(buf);
	s->TTL = get32bit(buf);
	s->rdLength = get16bit(buf);
	s->rData = (char *)malloc(sizeof(char)*(s->rdLength + 1));
	memcpy(s->rData, *buf , s->rdLength + 1);
	(*buf) += s->rdLength;
}

bool decodeQuestion(Packet *pkt, char **buf)
{
	char *rawBuf = *buf;
	(*buf) += 12;
	int num = pkt->pktHead->qdcount;
	for (int i = 0; i < num; i++)
	{
		if (i == 0)
		{
			pkt->pktQuestion = (struct question*)malloc(sizeof(struct question));
			pkt->pktQuestion->next = NULL;
		}
		else
		{
			Question * newQ;
			newQ = (struct question*)malloc(sizeof(struct question));
			newQ->next = pkt->pktQuestion;
			pkt->pktQuestion = newQ;
		}

		pkt->pktQuestion->qName = decodeDomain(buf, rawBuf);
		pkt->pktQuestion->qType = get16bit(buf);
		pkt->pktQuestion->qClass = get16bit(buf);

		switch (dLevel)
		{
		case mid:
			printf("Decode question %d\n", i);
			break;
		case high:
			printf("Decode question %d qName:%s qType:%d qClass:%d\n", i
				, pkt->pktQuestion->qName, pkt->pktQuestion->qType, pkt->pktQuestion->qClass);
		}
	}
	return true;
}

char * decodeDomain(char **buf, char *raw)
{
	if (**buf == '\0')
	{
		(*buf)++;
		return strdup("\0");
	}
	//char *rawBuf = *buf;
	unsigned char len = 0;
	uint16_t offset = 0;
	//(*buf) += loc;
	char * reVal;
	char name[254] = {0};
	unsigned nameLen = 0;
	while ((len = (char)**buf)!=0)
	{
		if (len >= 0xc0)
		{
			(**buf) = (**buf) & (~COMPRESSMUSK);
			offset = get16bit(buf);
			*((*buf) - 2) = *((*buf) - 2) | COMPRESSMUSK;
			char *newLoc = raw + offset;
			char * tmp = decodeDomain(&newLoc,raw);
			if (!tmp)
			{
				return NULL;
			}
			memcpy(name + strlen(name), tmp, strlen(tmp)+1);
			reVal = (char*)malloc((strlen(name)+1) * sizeof(char));
			memcpy(reVal, name, strlen(name)+1);
			return reVal;
 		}
		else
		{
			(*buf)++;
			for (int i = 0; i < len; i++,nameLen++)
			{
				name[nameLen] = get8bit(buf);
			}
			name[nameLen] = '.';
			nameLen++;
		}
	}
	name[nameLen - 1] = '\0';
	reVal = (char*)malloc((strlen(name)+1) * sizeof(char));
	memset(reVal, 0, strlen(name)+1);
	memcpy(reVal, name, strlen(name)+1);
	if (get8bit(buf))
	{
		return NULL;
	}
	return reVal;
}

void getHeader(Header *head, char *buff)
{
	head->ID = get16bit(&buff);
	uint32_t tmp;
	tmp = get16bit(&buff);
	head->QR = (tmp & QRMUSK) >> 15;
	head->opcode = (tmp & OPCODEMUSK) >> 11;
	head->AA = (tmp & AAMUSK) >> 10;
	head->TC = (tmp & TCMUSK) >> 9;
	head->RD = (tmp & RDMUSK) >> 8;
	head->RA = (tmp & RAMUSK) >> 7;
	head->rcode = tmp & RCODEMUSK;

	head->qdcount = get16bit(&buff);
	head->ancount = get16bit(&buff);
	head->nscount = get16bit(&buff);
	head->arcount = get16bit(&buff);
}

unsigned encodePkt(Packet *pkt, char *buff)
{
	char *rawBuf = buff;
	//pkt->pktHead = (struct header*)malloc(sizeof(struct header));

	setHeader(pkt->pktHead, buff);

	buff += 12;

	for (int i = 0; i < pkt->pktHead->qdcount; i++)
	{
		/*if (i == 0)
		{
			pkt->pktQuestion = (struct question *)malloc(sizeof(struct question));
		}
		else
		{
			Question *tmp;
			tmp = (struct question *)malloc(sizeof(struct question));
			tmp->next = pkt->pktQuestion;
			pkt->pktQuestion = tmp;
		}*/
		encodeQuestion(pkt->pktQuestion, &buff);
	}

	for (int i = 0; i < pkt->pktHead->ancount; i++)
	{
		encodeSource(pkt->pktAnswer, &buff);
	}
	return buff - rawBuf;
} 

void encodeDomain(char *name, char **buf)
{
	int labLen[10];
	int labCount = 0;
	int len = 0;
	int nameLoc = 0;
	for (int i = 0; i < strlen(name); i++, len++)
	{
		if (name[i] == '.')
		{
			labLen[labCount] = len;
			len = -1;
			labCount++;
		}
	}
	labLen[labCount] = len;
	labCount++;
	for (int i = 0; i < labCount; i++)
	{
		set8bit(buf, (uint8_t)labLen[i]);
		if (i != 0)
		{
			nameLoc++;
		}
		for (int j = 0; j < labLen[i]; j++)
		{
			set8bit(buf, (uint8_t)name[nameLoc]);
			nameLoc++;
		}
	}
}

unsigned  encodeQuestion(Question *q, char **buf)
{
	char **rawBuf = buf;
	encodeDomain(q->qName, buf);
	set8bit(buf, 0);

	set16bit(buf, q->qType);
	set16bit(buf, q->qClass);
	return (*buf) - (*rawBuf);
}

unsigned encodeSource(Source *s, char **buf)
{
	char *rawBuf = *buf;
	encodeDomain(s->name, buf);
	set8bit(buf, 0);
	set16bit(buf, s->type);
	set16bit(buf, s->Class);
	set32bit(buf, s->TTL);
	set16bit(buf, s->rdLength);
	memcpy(*buf, s->rData, s->rdLength);
	(*buf) += 4;
	return (*buf) - rawBuf;
}

void setHeader(Header *head, char *buf)
{
	set16bit(&buf, head->ID);

	uint32_t tmp = 0;
	tmp |= ((head->QR) << 15);
	tmp |= ((head->opcode) << 11);
	tmp |= ((head->AA) << 10);
	tmp |= ((head->TC) << 9);
	tmp |= ((head->RD) << 8);
	tmp |= ((head->RA) << 7);
	tmp |= (head->rcode);

	set16bit(&buf, (uint16_t)tmp);
	set16bit(&buf, head->qdcount);
	set16bit(&buf, head->ancount);
	set16bit(&buf, head->nscount);
	set16bit(&buf, head->arcount);
}

uint8_t get8bit(char **buff)
{
	uint8_t t;
	memcpy(&t, *buff, 1);
	(*buff)++;
	return t;
}

uint16_t get16bit(char **buff)
{
	uint16_t t;
	memcpy(&t, *buff, 2);
	(*buff) += 2;
	return ntohs(t);
}

uint32_t get32bit(char **buff)
{
	uint32_t t;
	memcpy(&t, *buff, 4);
	(*buff) += 4;
	return ntohl(t);
}

void set8bit(char **buf, uint8_t t)
{
	memcpy(*buf, &t, 1);
	(*buf)++;
}

void set16bit(char **buf, uint16_t t)
{
	t = htons(t);
	memcpy(*buf, &t, 2);
	(*buf) += 2;
}

void set32bit(char **buf, uint32_t t)
{
	t = htonl(t);
	memcpy(*buf, &t, 4);
	(*buf) += 4;
}

void freePkt(Packet *pkt)
{
	free(pkt->pktHead);
	Question * q;
	while (pkt->pktQuestion)
	{
		free(pkt->pktQuestion->qName);
		q = pkt->pktQuestion->next;
		free(pkt->pktQuestion);
		pkt->pktQuestion = q;
	}
	Source *sAn;
	while (pkt->pktAnswer)
	{
		free(pkt->pktAnswer->name);
		sAn = pkt->pktAnswer->next;
		free(pkt->pktAnswer);
		pkt->pktAnswer = sAn;
	}
	Source *sAu;
	while (pkt->pktAuthority)
	{
		free(pkt->pktAuthority->name);
		sAu = pkt->pktAuthority->next;
		free(pkt->pktAuthority);
		pkt->pktAuthority = sAu;
	}
}