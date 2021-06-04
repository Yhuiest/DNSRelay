#pragma once
#include "cache.h"
extern struct Trie *cacheTrie;
extern struct Trie *tableTrie;
extern struct Node *head;
extern struct Node *tail;
extern int cacheSize;

//逐字符检查，将大写字母转换为小写字母
void strToLow(char *str)
{
	int len = strlen(str);
	char name[264];
	int nLen = 0;
	for (int i = 0; i < len; i++)
	{
		if (str[i] >= 'A' && str[i] <= 'Z')
		{
			name[nLen++] = str[i] + 32;
		}
		else
		{
			name[nLen++] = str[i];
		}
	}
}

//插入节点，遍历所有节点，如果节点已存在，则忽略他，如果没有则创建节点直到字符串结束
//每一行空间分配 0-25 --》‘a’-‘z’ 26-35 --》‘0’-‘9’36--》‘-’ 37--》‘.’
void insertNode(struct Trie *trie, const char *str, unsigned char ipAddress[4])
{
	if (str[0] == 0)
		return;
	char name[264] = {0};
	int len = strlen(str);
	memcpy(name, str, len + 1);
	strToLow(name);
	int root = 0;
	for (int i = 0; i < len; i++)
	{
		int col;
		if (name[i] >= 'a' && name[i] <= 'z')
		{
			col = name[i] - 'a';
		}
		else if (name[i] >= '0' && name[i] <= '9')
		{
			col = 26 + name[i] - '0';
		}
		else if (name[i] == '-')
		{
			col = 36;
		}
		else
		{
			col = 37;
		}

		if (!trie->tree[root][col])
		{
			trie->tree[root][col] = ++(trie->totalNode);
		}
		trie->faNode[trie->tree[root][col]] = root;
		root = trie->tree[root][col];
	}

	memcpy(trie->ipAddress[root], ipAddress, 4 * sizeof(char));
	trie->endFlag[root] = true;
}

//查找字符串，在字典树中从根节点查找域名，查找到返回节点下表
int findNode(struct Trie *trie, const char *str)
{
	if (str[0] == 0)
	{
		return 0;
	}
	char name[264];
	int len = strlen(str);
	int root = 0;
	memcpy(name, str, len + 1);
	strToLow(name);

	for (int i = 0; i < len; i++)
	{
		int col;

		if (name[i] >= 'a' && name[i] <= 'z')
		{
			col = name[i] - 'a';
		}
		else if (name[i] >= '0' && name[i] <= '9')
		{
			col = 26 + name[i] - '0';
		}
		else if (name[i] == '-')
		{
			col = 36;
		}
		else
		{
			col = 37;
		}

		if (!trie->tree[root][col])
		{
			return 0;
		}
		root = trie->tree[root][col];
	}
	if (trie->endFlag[root] == false)
	{
		return 0;
	}
	return root;
}

//删除节点，从字符串的末尾开始删除，如果该节点有两个以上的孩子节点（即删除到该节点时，他不是叶子节点）
//证明该节点是共用的不能删除，如果是叶子节点，则删除该节点
void deleteNode(struct Trie *trie, char *str)
{
	if (str[0] == 0)
	{
		return;
	}
	char name[264];
	memcpy(name, str, strlen(str) + 1);
	strToLow(name);
	int root = findNode(trie, name);
	if (!root)
	{
		return;
	}
	trie->endFlag[root] = false;
	int strNum = strlen(name) - 1;
	while (root)
	{
		int col;

		if (name[strNum] >= 'a' && name[strNum] <= 'z')
		{
			col = name[strNum] - 'a';
		}
		else if (name[strNum] >= '0' && name[strNum] <= '9')
		{
			col = 26 + name[strNum] - '0';
		}
		else if (name[strNum] == '-')
		{
			col = 36;
		}
		else
		{
			col = 37;
		}

		bool notLeave = false;
		for (int i = 0; i < MAX_COL; i++)
		{
			if (trie->tree[root][i] != 0)
			{
				notLeave = true;
				break;
			}
		}
		if (notLeave)
		{
			break;
		}
		trie->tree[trie->faNode[root]][strNum] = 0;
		int tmp = trie->faNode[root];
		trie->faNode[root] = 0;
		root = tmp;
		strNum--;
	}
}

//将10进制的字符串转换为2进制
void tranIp(unsigned char ip[4], char *rawIp)
{
	int count = 0;
	int ipLen = strlen(rawIp);
	unsigned num = 0;
	for (int i = 0; i <= ipLen; i++)
	{
		if (rawIp[i] == '.' || i == ipLen)
		{
			ip[count++] = num;
			num = 0;
		}
		else
		{
			num = num * 10 + rawIp[i] - '0';
		}
	}
}

//输出缓存
void printCache()
{
	struct Node *p = head->next;
	int cacheCount = 0;
	while (p)
	{
		int node = findNode(cacheTrie, p->domain);
		printf("%d: %s", cacheCount++, p->domain);
		unsigned char ip[4];
		memcpy(ip, cacheTrie->ipAddress[node], sizeof(ip));
		printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
		p = p->next;
	}
}

//更新缓存，查看域名是否在缓存中
//若在将其更新到队伍末尾（利用率最高）
//若不在查看缓存是否已满，若没满则直接添加
//若满了将域名插入缓存并将链表头部节点删除（利用率最低）
void updateCache(unsigned char *ipAddress, const char *domain)
{
	int node = findNode(cacheTrie, domain);
	if (node)
	{
		struct Node *p1, *p2;
		p1 = head;
		while (p1->next)
		{
			if (!memcmp(p1->next->domain, domain, strlen(domain)))
			{
				p2 = p1->next;
				if (!(p2->next))
				{
					break;
				}
				p1->next = p2->next;
				p2->next = NULL;
				tail->next = p2;
				tail = p2;
				break;
			}
			p1 = p1->next;
		}
	}
	else
	{
		struct Node *p = (struct Node *)malloc(sizeof(struct Node));
		memcpy(p->domain, domain, sizeof(p->domain));
		if (cacheSize < MAX_SIZE)
		{
			insertNode(cacheTrie, domain, ipAddress);
			cacheSize++;
			p->next = NULL;
			tail->next = p;
			tail = p;
		}
		else
		{
			insertNode(cacheTrie, domain, ipAddress);
			p->next = NULL;
			tail->next = p;
			tail = p;
			p = head->next;
			head->next = p->next;
			deleteNode(cacheTrie, p->domain);
			free(p);
		}
	}
}

//在缓存中查找域名，并更新缓存
bool findInCache(unsigned char ipAdderss[4], const char *domain)
{
	int node;
	if (!(node = findNode(cacheTrie, domain)))
	{
		return false;
	}
	memcpy(ipAdderss, cacheTrie->ipAddress[node], 4 * sizeof(unsigned char));
	updateCache(ipAdderss, domain);
	return true;
}

//在域名列表中查找
bool findInTable(unsigned char ipAddress[4], const char *domain)
{
	int node;
	if (!(node = findNode(tableTrie, domain)))
	{
		return false;
	}
	memcpy(ipAddress, tableTrie->ipAddress[node], 4 * sizeof(char));
	return true;
}