#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_ROW 1000001
#define MAX_COL 38  //a~z + 0~9 + '-'
#define MAX_STR 1001
#define MAX_SIZE 100

struct Trie
{
	int tree[MAX_ROW][MAX_COL];
	int faNode[MAX_ROW];
	bool endFlag[MAX_ROW];
	int totalNode;
	unsigned char ipAddress[MAX_ROW][4];
};

struct Node
{
	char domain[264];
	struct Node *next;
};

void printCache();
bool findInCache(unsigned char ipAdderss[4], const char *domain);
bool findInTable(unsigned char ipAddress[4], const char *domain);
void updateCache(unsigned char *ipAddress, const char *domain);
void strToLow(char *str);
void insertNode(struct Trie *trie, const char *str, unsigned char ipAddress[4]);
void deleteNode(struct Trie *trie, char *str);
int findNode(struct Trie *trie, const char *str);
void tranIp(unsigned char ip[4], char *rawIp);
