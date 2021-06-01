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

enum debugLevel {low,mid,high};		//���õ��Եȼ�
debugLevel dLevel = low;			//Ĭ�ϵ��Եȼ�Ϊ��
char logFile[100] = "DNSRelayLog.txt";	//Ĭ����־����ļ���
char domainList[100] = "DNS_relay.txt";	//Ĭ�ϱ��������б��ļ���
FILE *logName;						//��־�ļ�ָ��
FILE *domain;						//�����б��ļ�ָ��
char sAddress[16] = "10.3.9.44";	//Ĭ��server ip��ַ
WSADATA wsaData;					//
SOCKET servSock;					//   
SOCKET clientSock;					//     �����׽���
sockaddr_in servSockAddr;			//
sockaddr_in clientSockAddr;			//
int addrLen = sizeof(struct sockaddr_in);
int requestCnt = 0;					//���������ڼ���id

//���������õ����������
const uint16_t QRMUSK = 0x8000;
const uint16_t OPCODEMUSK = 0x7800;
const uint16_t AAMUSK = 0x0400;
const uint16_t TCMUSK = 0x0200;
const uint16_t RDMUSK = 0x0100;
const uint16_t RAMUSK = 0x0080;
const uint16_t RCODEMUSK = 0x000F;
const uint8_t COMPRESSMUSK = 0xc0;

//�����ͷ���ṹ��
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

//Question���ֽṹ��
typedef struct question
{
	char * qName;
	uint16_t qType;
	uint16_t qClass;
	struct question *next;
}Question;

//��Դ���ֽṹ�壬����Answer���Լ�Authority
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

//DNS���ṹ��
typedef struct packet
{
	Header *pktHead;
	Question *pktQuestion;
	Source *pktAnswer;
	Source *pktAuthority;
	Source *pktAdditional;
}Packet;

//���ڼ�¼ÿ��client��id��server id�Ķ�Ӧ��ϵ
typedef struct
{
	uint16_t cliId;
	unsigned exprieTime;
	struct sockaddr_in cliAddr;
}converId;

//id��
converId idTable[ID_TABLE_SIZE];

//�ֵ����ṹ��
struct Trie *cacheTrie;
struct Trie *tableTrie;
struct Node *head;
struct Node *tail;
int cacheSize;

//�����õ����к���
bool parseArgu(int argc, char **argv);	//�������Ĳ���
bool init();			//�����ʼ��
void clientReceive();	//��client������DNS����������
void serverReceive();	//��server������DNS����������
void getHeader(Header *haed, char *buff);//�ӵõ��İ��в���ͷ����Ϣ
void setHeader(Header *head, char *buff);//�������ɵ�ͷ����Ϣ���������
bool decodeQuestion(Packet *pkt, char **buf);//���Question
unsigned encodeQuestion(Question *q, char **buf);//���Question
bool decodeSource(Source *s, char **buf, char *raw);//�����Դ����
unsigned encodeSource(Source *s, char **buf);		//�����Դ����
char * decodeDomain(char **buf, char *raw);			//�������
void encodeDomain(char *name, char **buf);			//��װ����
bool decodePkt(Packet *pkt, char *buff, unsigned int len);//��������
unsigned encodePkt(Packet *pkt, char *buff);			//��װ�����
void printInHex(unsigned char *buff, unsigned len);		//��������16������ʽ��ӡ�� ����Debug
//bool searchInList(Packet *pkt);
uint8_t get8bit(char **buff);		//��һ��char���͵������γ�һ��8λ�޷��ŷ���
uint16_t get16bit(char **buff);		//������char���͵������γ�һ��16λ�޷��ŷ���
uint32_t get32bit(char **buff);		//���ĸ�char���͵������γ�һ��32λ�޷��ŷ���
void set8bit(char **buf, uint8_t t);	//��һ��8λ�޷����γ�һ��char����
void set16bit(char **buf, uint16_t t);	//��һ��16λ�޷����γ�����char����
void set32bit(char **buf, uint32_t t);	//��һ��32λ�޷����γ��ĸ�char����
void freePkt(Packet *pkt);			//�ͷŰ�ռ�õ��ڴ�
int search(Packet *pkt);			//�ڻ�������������