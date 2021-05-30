#pragma once
#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <errno.h>
#include <vector>
#pragma comment(lib,"ws2_32.lib")
#define ID_TABLE_SIZE 1000
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define MODE 1
#define BUFFER_SIZE 2000
#define TIMEOUT 5
using namespace std;
enum debugLevel {low,mid,high};
debugLevel dLevel = high;
char logFile[100] = "DNSRelayLog.txt";
char domainList[100] = "DNS_relay.txt";
FILE *logName;
FILE *domain;
char sAddress[16] = "10.3.9.44";
WSADATA wsaData;
SOCKET servSock;
SOCKET clientSock;
sockaddr_in servSockAddr;
sockaddr_in clientSockAddr;
vector< pair<string, string>> list;
int addrLen = sizeof(struct sockaddr_in);
int requestCnt = 0;

const uint16_t QRMUSK = 0x8000;
const uint16_t OPCODEMUSK = 0x7800;
const uint16_t AAMUSK = 0x0400;
const uint16_t TCMUSK = 0x0200;
const uint16_t RDMUSK = 0x0100;
const uint16_t RAMUSK = 0x0080;
const uint16_t RCODEMUSK = 0x000F;
const uint8_t COMPRESSMUSK = 0xc0;

typedef struct header
{
	uint16_t ID;
	char QR;
	uint8_t opcode;
	char AA;
	char TC;
	char RD;
	char RA;
	uint8_t rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
}Header;

typedef struct question
{
	char * qName;
	uint16_t qType;
	uint16_t qClass;
	struct question *next;
}Question;

typedef struct source
{
	char *name;
	uint16_t type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t rdLength;
	char *rData;
	struct source *next;
}Source;

typedef struct packet
{
	Header *pktHead;
	Question *pktQuestion;
	Source *pktAnswer;
	Source *pktAuthority;
	Source *pktAdditional;
}Packet;

typedef struct
{
	uint16_t cliId;
	unsigned exprieTime;
	struct sockaddr_in cliAddr;
}converId;

converId idTable[ID_TABLE_SIZE];
