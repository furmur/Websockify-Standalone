#include "acl.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>

#define SAv4(addr) ((struct sockaddr_in*)addr)
#define SAv6(addr) ((struct sockaddr_in6*)addr)
#define SA_len(addr) \
    ((addr)->ss_family == AF_INET ? \
    sizeof(sockaddr_in) : sizeof(sockaddr_in6))
#define SAv4_addr(v) (SAv4(&v)->sin_addr.s_addr)
#define SAv6_addr(v) (*(uint64_t*)(SAv6(&v)->sin6_addr.s6_addr))

#define TYP_INIT 0 
#define TYP_SMLE 1 
#define TYP_BIGE 2
static unsigned long long htonll(unsigned long long src) { 
      static int typ = TYP_INIT; 
    unsigned char c; 
    union { 
        unsigned long long ull; 
        unsigned char c[8]; 
    } x; 
    if (typ == TYP_INIT) { 
        x.ull = 0x01; 
        typ = (x.c[7] == 0x01ULL) ? TYP_BIGE : TYP_SMLE; 
    }
    if (typ == TYP_BIGE) 
        return src; 
     x.ull = src; 
     c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c; 
     c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c; 
     c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c; 
     c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c; 
    return x.ull; 
}

static int parse_addr(struct acl_t *acl, const char *str, int len)
{
    char addr_str[NI_MAXHOST];

    if(!str || !len || len > NI_MAXHOST-1) return 1;

    memcpy(addr_str,str,len);
    addr_str[len] = '\0';

    struct sockaddr_in *sin = SAv4(&acl->addr);
    struct sockaddr_in6 *sin6 = SAv6(&acl->addr);

    if(inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) > 0) {
        acl->addr.ss_family = AF_INET6;
#ifdef SIN6_LEN
        sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
        return 0;
    }

    if((inet_pton(AF_INET, addr_str, &sin->sin_addr) > 0)) {
        acl->addr.ss_family = AF_INET;
        return 0;
    }

    //printf("failed to parse addr: %.*s\n",len,str);
    return 1;
}

static int parse_apply_mask(struct acl_t *acl, const char *str, int len)
{
    if(str && len) {
        char mask_str[4];
        if(len > 3) return 1;
        memcpy(mask_str, str, len);
        mask_str[len] = '\0';
        acl->mask_len = atoi(mask_str);
        if(acl->mask_len < 1)
            return 1;
        if(acl->mask_len > (acl->addr.ss_family == AF_INET ? 32 : 128)) {
            return 1;
        }
    } else {
        acl->mask_len = acl->addr.ss_family == AF_INET ? 32 : 128;
    }

    acl->mask.ss_family = acl->addr.ss_family;
    acl->network.ss_family = acl->network.ss_family;

    if(acl->addr.ss_family == AF_INET) {
        SAv4_addr(acl->mask) = htonl((~0UL) << (32-acl->mask_len));
        SAv4_addr(acl->network) = SAv4_addr(acl->addr) & SAv4_addr(acl->mask);
    } else {
        SAv6_addr(acl->mask) = htonll((~0ULL) << (128-acl->mask_len));
        SAv6_addr(acl->network) = SAv6_addr(acl->addr) & SAv6_addr(acl->mask);
    }

    return 0;
}

static int parse_cidr(struct acl_t *acl, const char *str, int len)
{
    int addr_len = 0;
    char *slash_pos = memchr(str, '/', len);\
    if(slash_pos) {
        addr_len = slash_pos - str;
        slash_pos++;
    } else {
        addr_len = len;
    }

    if(parse_addr(acl, str, addr_len))
        return 1;

    if(parse_apply_mask(acl, slash_pos, len - addr_len))
        return 1;

    return 0;
}

int acl_parse(struct acl_t **acl_ptr, const char *str)
{
    int i = 0;
    struct acl_t *acl;
    char *c;

    if(!str) return 0;

    acl = *acl_ptr = malloc(sizeof(struct acl_t));
    while((c = strchr(str, ','))!=NULL) {
        if(parse_cidr(acl, str, c-str))
            return 1;
        str = c+1;
        acl->next = malloc(sizeof(struct acl_t));
        acl = acl->next;
    }
    //tail
    if(parse_cidr(acl, str, strlen(str)))
        return 1;
    acl->next = NULL;

    return 0;
}

int acl_match_ipv4(struct acl_t *acl, struct in_addr *addr)
{
    if(!acl) return 0;

    while(acl) {
        if(acl->addr.ss_family != AF_INET)
            continue;
        if(SAv4_addr(acl->network) == (addr->s_addr & SAv4_addr(acl->mask))) {
            return 0;
        }
        acl = acl->next;
    }

    return 1;
}

static const char *addr_to_str(struct sockaddr_storage addr, char *buf)
{
    if(addr.ss_family == AF_INET) {
        inet_ntop(addr.ss_family, &SAv4_addr(addr), buf, NI_MAXHOST);
    } else {
        inet_ntop(addr.ss_family, &SAv6_addr(addr), buf, NI_MAXHOST);
    }
    return buf;
}

void acl_print(struct acl_t *acl, const char *prefix)
{
    char buf[NI_MAXHOST] = "";

    printf("%s:\n",prefix);
    if(!acl) {
        printf("  empty\n");
        return;
    }
    while(acl) {
        printf("  * %s/%u\n", addr_to_str(acl->addr,buf), acl->mask_len);
        acl = acl->next;
    }
}

struct acl_t *acl_clone(struct acl_t *acl)
{
    struct acl_t *ret = NULL;
    while(acl) {
        if(ret) {
            ret->next = malloc(sizeof(struct acl_t));
            ret = ret->next;
        } else {
            ret = malloc(sizeof(struct acl_t));
        }

        memcpy(ret, acl, sizeof(struct acl_t));
        acl = acl->next;
    }
    return ret;
}

void acl_free(struct acl_t *acl)
{
    struct acl_t *next;
    while(acl) {
        next = acl->next;
        free(acl);
        acl = next;
    }
}
