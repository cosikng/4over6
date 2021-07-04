//natHandler.c
typedef struct
{
    unsigned char ori_host;
    unsigned short ori_port;
} OInfo;
unsigned short get_tra(unsigned char host, unsigned short src, int type);
int get_src(unsigned short tra, int type, OInfo *ori_info);
void init(void);
unsigned short get_word(unsigned char *data);
unsigned short update_checksum(unsigned short checksum, int delta);
#define TCP 0
#define UDP 1