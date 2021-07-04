#include <time.h>
#define MAX_PORTS 1000
#define MAX_TABLES 10
#define PORT_BASE 10000
#define CON_TIME 60

typedef struct
{
    unsigned char ori_host;
    unsigned short ori_port;
} OInfo;

typedef struct
{
    unsigned short src;
    unsigned short tra;
    time_t last_time;
} Port;

typedef struct
{
    unsigned char host;
    union
    {
        struct
        {
            int tcp_len, udp_len;
        };
        int len[2];
    };

    union
    {
        struct
        {
            Port tcp[MAX_PORTS];
            Port udp[MAX_PORTS];
        };
        Port xp[2 * MAX_PORTS];
    };
    union
    {
        struct
        {
            Port *ptcp[MAX_PORTS];
            Port *pudp[MAX_PORTS];
        };
        Port *pxp[2 * MAX_PORTS];
    };

} Table;

Table nat_tables[MAX_TABLES];
int new_host = 0;

Table *hosts[256];

void init()
{
    for (int i = 0; i < 256; i++)
    {
        hosts[i] = 0;
    }
    for (int i = 0; i < MAX_TABLES; i++)
    {
        nat_tables[i].host = 0;
        nat_tables[i].tcp_len = 0;
        nat_tables[i].udp_len = 0;
        for (int j = 0; j < MAX_PORTS; j++)
        {
            nat_tables[i].ptcp[j] = nat_tables[i].tcp + j;
            nat_tables[i].pudp[j] = nat_tables[i].udp + j;
            nat_tables[i].tcp[j].src = 0;
            nat_tables[i].tcp[j].last_time = 0;
            nat_tables[i].tcp[j].tra = PORT_BASE + i * MAX_PORTS + j;
            nat_tables[i].udp[j].src = 0;
            nat_tables[i].udp[j].last_time = 0;
            nat_tables[i].udp[j].tra = PORT_BASE + i * MAX_PORTS + j;
        }
    }
}

int logfind(unsigned char host, unsigned short src, int type)
{
    int a = 0, b;
    b = hosts[host]->len[type] - 1;
    Port **now;
    now = hosts[host]->pxp + type * MAX_PORTS;
    while (a <= b)
    {
        if (now[(a + b) / 2]->src == src)
            return (a + b) / 2;
        else if (now[(a + b) / 2]->src < src)
            a = (a + b) / 2 + 1;
        else
            b = (a + b) / 2 - 1;
    }
    return -1;
}

unsigned short get_tra(unsigned char host, unsigned short src, int type)
{ //0:TCP,1:UDP
    int ret, i;
    time_t t_now;
    Port **now;
    Port *tmp;
st:
    if (hosts[host] != 0)
    {
        now = hosts[host]->pxp + type * MAX_PORTS;
        ret = logfind(host, src, type);
        //找到了存在的映射项
        if (ret != -1)
        {
            now[ret]->last_time = time(0);
            return now[ret]->tra;
        }
        //未找到
        if (hosts[host]->len[type] < MAX_PORTS)
        { //表项未满
            for (i = 0; (i < hosts[host]->len[type]) && now[i]->src < src; i++)
                ;
            tmp = now[hosts[host]->len[type]];
            for (int j = hosts[host]->len[type]; j > i; j--)
                now[j] = now[j - 1];
            now[i] = tmp;
            hosts[host]->len[type]++;
            now[i]->src = src;
            now[i]->last_time = time(0);
            return now[i]->tra;
        }
        //表项已满
        t_now = time(0);
        for (i = 0; i < MAX_PORTS; i++)
        {
            if (t_now - now[i]->last_time >= CON_TIME)
            { //寻找超过保留时间未使用的映射
                //替换表项并重新排序
                now[i]->last_time = t_now;
                now[i]->src = src;
                for (; i < MAX_PORTS - 1 && src > now[i + 1]->src; i++)
                {
                    tmp = now[i];
                    now[i] = now[i + 1];
                    now[i + 1] = tmp;
                }
                for (; i > 0 && src < now[i - 1]->src; i--)
                {
                    tmp = now[i];
                    now[i] = now[i - 1];
                    now[i - 1] = tmp;
                }
                return now[i]->tra;
            }
        }
        //所有表项均未超过保留时间
        return -1;
    }
    //该主机第一次申请映射
    hosts[host] = nat_tables + new_host;
    new_host = (new_host + 1) % MAX_TABLES;
    //如果映射表已满，直接替换掉最早的主机
    hosts[host]->tcp_len = 0;
    hosts[host]->udp_len = 0;
    hosts[hosts[host]->host] = 0; //清除原主机的记录
    hosts[host]->host = host;     //记录新主机
    goto st;
}

int get_src(unsigned short tra, int type, OInfo *ori_info)
{
    if (tra < PORT_BASE || tra >= PORT_BASE + MAX_PORTS * MAX_TABLES)
        return -1; //超出映射边界
    ori_info->ori_host = nat_tables[(tra - PORT_BASE) / MAX_PORTS].host;
    ori_info->ori_port = nat_tables[(tra - PORT_BASE) / MAX_PORTS].xp[(tra - PORT_BASE) % MAX_PORTS + type * MAX_PORTS].src;
    nat_tables[(tra - PORT_BASE) / MAX_PORTS].xp[(tra - PORT_BASE) % MAX_PORTS + type * MAX_PORTS].last_time = time(0);
    return 0;
}

unsigned short get_word(unsigned char *data)
{
    return data[0] * 256 + data[1];
}

unsigned short update_checksum(unsigned short checksum, int delta)
{
    int sum;
    sum = checksum + delta + 1;
    sum = (sum & 0xffff) + (sum >> 16) - 1;
    return sum;
}