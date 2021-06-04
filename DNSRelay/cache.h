#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_ROW 1000001	//���ڵ����
#define MAX_COL 38  //a~z + 0~9 + '-'
#define MAX_STR 1001 //������󳤶�
#define MAX_SIZE 100	//������󳤶�


//�ֵ������ݽṹ
struct Trie
{
	int tree[MAX_ROW][MAX_COL]; //�ֵ�������
	int faNode[MAX_ROW];		//˫�׽��
	bool endFlag[MAX_ROW];		//�жϽڵ��Ƿ�ΪҶ�ӽڵ�
	int totalNode;				//�ܽ����
	unsigned char ipAddress[MAX_ROW][4];//ÿ���ڵ�����IP��ַ
};

struct Node				//������������
{
	char domain[264];
	struct Node *next;
};

void printCache();		//���cache������
bool findInCache(unsigned char ipAdderss[4], const char *domain);//��cache�в�������
bool findInTable(unsigned char ipAddress[4], const char *domain);//�������б��в���
void updateCache(unsigned char *ipAddress, const char *domain);//����cache�е�����
void strToLow(char *str);					//���ַ����ĳ�Сд
void insertNode(struct Trie *trie, const char *str, unsigned char ipAddress[4]);//����ڵ�
void deleteNode(struct Trie *trie, char *str);		//ɾ���ڵ�
int findNode(struct Trie *trie, const char *str);	//���ֵ����в��ҽ��
void tranIp(unsigned char ip[4], char *rawIp);		//��IP��ַ��10�����ַ�����ʽ��Ϊ������
