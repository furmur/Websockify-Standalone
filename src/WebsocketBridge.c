#include "WebsocketBridge.h"
/*
 * A WebSocket to TCP socket proxy with support for "wss://" encryption.
 * Copyright 2010 Joel Martin
 * Licensed under LGPL version 3 (see docs/LICENSE.LGPL-3)
 *
 * You can make a cert/key with openssl using:
 * openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem
 * as taken from http://docs.python.org/dev/library/ssl.html#certificates
 */
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "websocket.h"

char traffic_legend[] = "\n\
Traffic Legend:\n\
}  - Client receive\n\
}. - Client receive partial\n\
{  - Target receive\n\
\n\
>  - Target send\n\
>. - Target send partial\n\
<  - Client send\n\
<. - Client send partial\n\
";

char USAGE[] = "Usage: [options] " \
"[source_addr:]source_port target_addr:target_port\n\n" \
"  --verbose|-v       verbose messages and per frame traffic\n" \
"  --daemon|-D        become a daemon (background process)\n" \
"  --run-once         handle a single WebSocket connection and exit\n" \
"  --cert CERT        SSL certificate file\n" \
"  --key KEY          SSL key file (if separate from cert)\n" \
"  --ssl-only         disallow non-encrypted connections";

#define usage(fmt, args...) \
fprintf(stderr, "%s\n\n", USAGE); \
fprintf(stderr, fmt , ## args); \
exit(1);

extern int pipe_error;
extern settings_t settings;

void do_proxy(ws_ctx_t *ws_ctx, int target) {
    fd_set rlist, wlist, elist;
    struct timeval tv, start_time, end_time, duration;
    int i, maxfd, client = ws_ctx->sockfd;
    unsigned int opcode, left, ret;
    unsigned int tout_start, tout_end, cout_start, cout_end;
    unsigned int tin_start, tin_end;
    ssize_t len, bytes;
    size_t ws_rcvd = 0, ws_snt = 0, tcp_rcvd= 0, tcp_snt = 0;

    tout_start = tout_end = cout_start = cout_end;
    tin_start = tin_end = 0;
    maxfd = client > target ? client+1 : target+1;

    connection_msg("connected\n");

    gettimeofday(&start_time, NULL);

    while (1) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        FD_ZERO(&rlist);
        FD_ZERO(&wlist);
        FD_ZERO(&elist);
        
        FD_SET(client, &elist);
        FD_SET(target, &elist);
        
        if (tout_end == tout_start) {
            // Nothing queued for target, so read from client
            FD_SET(client, &rlist);
        } else {
            // Data queued for target, so write to it
            FD_SET(target, &wlist);
        }
        if (cout_end == cout_start) {
            // Nothing queued for client, so read from target
            FD_SET(target, &rlist);
        } else {
            // Data queued for client, so write to it
            FD_SET(client, &wlist);
        }
        
        ret = select(maxfd, &rlist, &wlist, &elist, &tv);
        if (pipe_error) { break; }
        
        if (FD_ISSET(target, &elist)) {
            connection_msg("target exception\n");
            break;
        }
        if (FD_ISSET(client, &elist)) {
            connection_msg("client exception\n");
            break;
        }
        
        if (ret == -1) {
            handler_emsg("select(): %s\n", strerror(errno));
            break;
        } else if (ret == 0) {
            //handler_emsg("select timeout\n");
            continue;
        }
        
        if (FD_ISSET(target, &wlist)) {
            len = tout_end-tout_start;
            bytes = send(target, ws_ctx->tout_buf + tout_start, len, 0);
            if (pipe_error) { break; }
            if (bytes < 0) {
                connection_msg("target connection error: %s\n",
                             strerror(errno));
                break;
            }
            tcp_snt += bytes;
            tout_start += bytes;
            if (tout_start >= tout_end) {
                tout_start = tout_end = 0;
                traffic(">");
            } else {
                traffic(">.");
            }
        }
        
        if (FD_ISSET(client, &wlist)) {
            len = cout_end-cout_start;
            bytes = ws_send(ws_ctx, ws_ctx->cout_buf + cout_start, len);
            if (pipe_error) { break; }
            if (len < 3) {
                connection_msg("len: %d, bytes: %d: %d\n",
                             (int) len, (int) bytes,
                             (int) *(ws_ctx->cout_buf + cout_start));
            }
            ws_snt += bytes;
            cout_start += bytes;
            if (cout_start >= cout_end) {
                cout_start = cout_end = 0;
                traffic("<");
            } else {
                traffic("<.");
            }
        }
        
        if (FD_ISSET(target, &rlist)) {
            bytes = recv(target, ws_ctx->cin_buf, DBUFSIZE , 0);
            if (pipe_error) { break; }
            if (bytes <= 0) {
                connection_msg("connection closed by target\n");
                break;
            }
            cout_start = 0;
            tcp_rcvd += bytes;
            if (ws_ctx->hybi) {
                cout_end = encode_hybi(ws_ctx->cin_buf, bytes,
                                       ws_ctx->cout_buf, BUFSIZE, ws_ctx->opcode);
            } else {
                cout_end = encode_hixie(ws_ctx->cin_buf, bytes,
                                        ws_ctx->cout_buf, BUFSIZE);
            }
            /*
             printf("encoded: ");
             for (i=0; i< cout_end; i++) {
             printf("%u,", (unsigned char) *(ws_ctx->cout_buf+i));
             }
             printf("\n");
             */
            if (cout_end < 0) {
                connection_msg("encoding error\n");
                break;
            }
            traffic("{");
        }
        
        if (FD_ISSET(client, &rlist)) {
            bytes = ws_recv(ws_ctx, ws_ctx->tin_buf + tin_end, BUFSIZE-1);
            if (pipe_error) { break; }
            if (bytes <= 0) {
                connection_msg("connection closed by client\n");
                break;
            }
            ws_rcvd += bytes;
            tin_end += bytes;
            /*
             printf("before decode: ");
             for (i=0; i< bytes; i++) {
             printf("%u,", (unsigned char) *(ws_ctx->tin_buf+i));
             }
             printf("\n");
             */
            if (ws_ctx->hybi) {
                len = decode_hybi(ws_ctx->tin_buf + tin_start,
                                  tin_end-tin_start,
                                  ws_ctx->tout_buf, BUFSIZE-1,
                                  &opcode, &left);
            } else {
                len = decode_hixie(ws_ctx->tin_buf + tin_start,
                                   tin_end-tin_start,
                                   ws_ctx->tout_buf, BUFSIZE-1,
                                   &opcode, &left);
            }
            
            if (opcode == 8) {
                connection_msg("closing frame from client\n");
                break;
            }
            
            /*
             printf("decoded: ");
             for (i=0; i< len; i++) {
             printf("%u,", (unsigned char) *(ws_ctx->tout_buf+i));
             }
             printf("\n");
             */
            if (len < 0) {
                connection_msg("decoding error\n");
                break;
            }
            if (left) {
                tin_start = tin_end - left;
                //printf("partial frame from client");
            } else {
                tin_start = 0;
                tin_end = 0;
            }
            
            traffic("}");
            tout_start = 0;
            tout_end = len;
        }
    }

    gettimeofday(&end_time, NULL);
    timersub(&end_time, &start_time, &duration);

    connection_msg("closed. ws rcvd/tcp sent: (%lu/%lu), tcp rcvd/ws sent: (%lu/%lu), duration:%lu.%03lu\n",
                   ws_rcvd,  tcp_snt, tcp_rcvd, ws_snt,
                   duration.tv_sec, duration.tv_usec/1000);
}

void proxy_handler(ws_ctx_t *ws_ctx) {
    int tsock = 0;

    //handler_msg("connecting to: %s:%d\n", ws_ctx->target_host, ws_ctx->target_port);

    bzero((char *) &settings.tcp_server_addr, sizeof(settings.tcp_server_addr));
    settings.tcp_server_addr.sin_family = AF_INET;
    settings.tcp_server_addr.sin_port = htons(ws_ctx->target_port);

    /* Resolve target address */
    if (resolve_host(&settings.tcp_server_addr.sin_addr, ws_ctx->target_host) == -1) {
        handler_emsg("Could not resolve target address: %s\n", ws_ctx->target_host);
        return;
    }

    if(acl_match_ipv4(settings.dst_whitelist, &settings.tcp_server_addr.sin_addr)) {
        handler_emsg("target addr %s not matched with dst_whitelist\n",
                    ws_ctx->target_host);
        return;
    }

    snprintf(settings.tcp_endpoint, 256, "%s:%u",
             inet_ntoa(settings.tcp_server_addr.sin_addr),
             settings.tcp_server_addr.sin_port);

    tsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tsock < 0) {
        connection_msg("could not create target socket: %s\n",
                     strerror(errno));
        return;
    }

    if (connect(tsock, (struct sockaddr *) &settings.tcp_server_addr, sizeof(settings.tcp_server_addr)) < 0) {
        connection_msg("failed to connect TCP endpoint: %s\n", strerror(errno));
        close(tsock);
        return;
    }

    if ((settings.verbose) && (! settings.daemon)) {
        printf("%s", traffic_legend);
    }

    do_proxy(ws_ctx, tsock);

    shutdown(tsock, SHUT_RDWR);
    close(tsock);
}

void start()
{
    if (!settings.cert) {
        /* Make sure it's always set to something */
        settings.cert = "self.pem";
    }
    settings.key = "";

    settings.verbose      = 0;
    settings.ssl_only     = 0;
    settings.daemon       = 0;
    settings.run_once     = 0;

    settings.handler = proxy_handler;
    start_server();
}
