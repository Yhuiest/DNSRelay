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

enum debugLevel {low,mid,high};		//设置调试等级
debugLevel dLevel = low;			//默认调试等级为低
char logFile[100] = "DNSRelayLog.txt";	//默认日志输出文件名
char domainList[100] = "DNS_relay.txt";	//默认本地域名列表文件名
FILE *logName;						//日志文件指针
FILE *domain;						//域名列表文件指针
char sAddress[16] = "10.3.9.44";	//默认server ip地址
WSADATA wsaData;					//
SOCKET servSock;					//   
SOCKET clientSock;					//     网络套接字
sockaddr_in servSockAddr;			//
sockaddr_in clientSockAddr;			//
int addrLen = sizeof(struct sockaddr_in);
int requestCnt = 0;					//申请数用于计算id

//拆解网络包用到的相关掩码
const uint16_t QRMUSK = 0x8000;
const uint16_t OPCODEMUSK = 0x7800;
const uint16_t AAMUSK = 0x0400;
const uint16_t TCMUSK = 0x0200;
const uint16_t RDMUSK = 0x0100;
const uint16_t RAMUSK = 0x0080;
const uint16_t RCODEMUSK = 0x000F;
const uint8_t COMPRESSMUSK = 0xc0;

//网络包头部结构体
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

//Question部分结构体
typedef struct question
{
	char * qName;
	uint16_t qType;
	uint16_t qClass;
	struct question *next;
}Question;

//资源部分结构体，包括Answer，以及Authority
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

//DNS包结构体
typedef struct packet
{
	Header *pktHead;
	Question *pktQuestion;
	Source *pktAnswer;
	Source *pktAuthority;
	Source *pktAdditional;
}Packet;

//用于记录每个client的id与server id的对应关系
typedef struct
{
	uint16_t cliId;
	unsigned exprieTime;
	struct sockaddr_in cliAddr;
}converId;

//id表
converId idTable[ID_TABLE_SIZE];

//字典树结构体
struct Trie *cacheTrie;
struct Trie *tableTrie;
struct Node *head;
struct Node *tail;
int cacheSize;

//所调用的所有函数
bool parseArgu(int argc, char **argv);	//处理程序的参数
bool init();			//程序初始化
void clientReceive();	//从client方接受DNS包，并处理
void serverReceive();	//从server方接受DNS包，并处理
void getHeader(Header *haed, char *buff);//从得到的包中拆解出头部信息
void setHeader(Header *head, char *buff);//将已生成的头部信息生成网络包
bool decodeQuestion(Packet *pkt, char **buf);//拆解Question
unsigned encodeQuestion(Question *q, char **buf);//打包Question
bool decodeSource(Source *s, char **buf, char *raw);//拆解资源部份
unsigned encodeSource(Source *s, char **buf);		//打包资源部分
char * decodeDomain(char **buf, char *raw);			//拆解域名
void encodeDomain(char *name, char **buf);			//封装域名
bool decodePkt(Packet *pkt, char *buff, unsigned int len);//拆解网络包
unsigned encodePkt(Packet *pkt, char *buff);			//封装网络包
void printInHex(unsigned char *buff, unsigned len);		//将数据以16进制形式打印出 用于Debug
//bool searchInList(Packet *pkt);
uint8_t get8bit(char **buff);		//将一个char类型的数据形成一个8位无符号返回
uint16_t get16bit(char **buff);		//将两个char类型的数据形成一个16位无符号返回
uint32_t get32bit(char **buff);		//将四个char类型的数据形成一个32位无符号返回
void set8bit(char **buf, uint8_t t);	//将一个8位无符号形成一个char类型
void set16bit(char **buf, uint16_t t);	//将一个16位无符号形成两个char类型
void set32bit(char **buf, uint32_t t);	//将一个32位无符号形成四个char类型
void freePkt(Packet *pkt);			//释放包占用的内存
int search(Packet *pkt);			//在缓存中搜索域名