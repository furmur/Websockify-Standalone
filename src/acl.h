#pragma once

#include <sys/socket.h>
#include <netinet/in.h>

struct acl_t {
    struct sockaddr_storage addr;
    struct sockaddr_storage mask;
    struct sockaddr_storage network;
    unsigned int mask_len;
    struct acl_t *next;
};

/* parse ACL definition from str to the acl_t struct
 * format: comma-separated networks list in CIDR notation
 * if netmask ommited it wil be set to 32 (match exact IP)
 * @return: 0 on success */
int acl_parse(struct acl_t **acl, const char *str);

/* march addr against ACL list pointed by acl
 * consider matched if acl is NULL
 * @return: 0 if matched */
int acl_match_ipv4(struct acl_t *acl, struct in_addr *addr);

/* prints acl list to stdout */
void acl_print(struct acl_t *acl, const char *prefix);

struct acl_t *acl_clone(struct acl_t *acl);

void acl_free(struct acl_t *acl);
