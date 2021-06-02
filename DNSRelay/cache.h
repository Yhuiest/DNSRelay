#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_ROW 1000001	//最大节点个数
#define MAX_COL 38  //a~z + 0~9 + '-'
#define MAX_STR 1001 //域名最大长度
#define MAX_SIZE 100	//缓存最大长度


//字典树数据结构
struct Trie
{
	int tree[MAX_ROW][MAX_COL]; //字典树矩阵
	int faNode[MAX_ROW];		//双亲结点
	bool endFlag[MAX_ROW];		//判断节点是否为叶子节点
	int totalNode;				//总结点数
	unsigned char ipAddress[MAX_ROW][4];//每个节点代表的IP地址
};

struct Node				//用链表缓存数据
{
	char domain[264];
	struct Node *next;
};

void printCache();		//输出cache中内容
bool findInCache(unsigned char ipAdderss[4], const char *domain);//在
bool findInTable(unsigned char ipAddress[4], const char *domain);
void updateCache(unsigned char *ipAddress, const char *domain);
void strToLow(char *str);
void insertNode(struct Trie *trie, const char *str, unsigned char ipAddress[4]);
void deleteNode(struct Trie *trie, char *str);
int findNode(struct Trie *trie, const char *str);
void tranIp(unsigned char ip[4], char *rawIp);
