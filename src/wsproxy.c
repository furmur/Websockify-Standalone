#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "websocket.h"
#include "WebsocketBridge.h"
#include "version.h"

const char* progname = NULL;

extern settings_t settings; //allocated in websocket.c

void usage(int exit_code)
{
    printf(
    "version: " APP_VERSION "\n"
    "Usage: virtualizm-wsproxy [-h] [-i listen_ip] [-p port]\n"
    "\n"
    "Options:\n"
    "  -i listen_ip  : IP adddress for WS socket\n"
    "  -p port       : port for WS socket\n"
    "  -h            : this help\n"
    "\n"
    "  -s, --src-whitelist list_def  : restrict allowed source IP addresses for incoming WebSocket connections\n"
    "                                  comma-separated networks list in CIDR notation\n"
    "\n"
    "  -d, --dst-whitelist list_def  : restrict allowed destination IP addresses for outgoing TCP connections\n"
    "                                  comma-separated networks list in CIDR notation\n"
    "\n");
    exit(exit_code);
}

int main(int argc, char **argv)
{
    int opt, opt_index;

    progname = strrchr(argv[0], '/');
    progname = (progname == NULL ? argv[0] : progname + 1);

    static const char* opts = "hi:p:s:d:";
    static struct option long_options[] = {
        {"src-whitelist", required_argument, NULL, 's'},
        {"dst-whitelist", required_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };

    settings.src_whitelist = NULL;
    settings.dst_whitelist = NULL;
    settings.listen_host[0] = '\0';
    settings.listen_port = 52525;

    while (-1!=(opt = getopt_long(argc, argv, opts, long_options, &opt_index))) {
        switch (opt) {
        case '?':
            fprintf(stderr, "%s: unknown option '-%c'\n", progname, optopt);
            usage(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "%s: missing argument for option '-%c'\n", progname, optopt);
            usage(EXIT_FAILURE);
        case 'h':
            usage(EXIT_SUCCESS);
        case 'i':
            strcpy(settings.listen_host, optarg);
            break;
        case 'p':
            settings.listen_port = atoi(optarg);
            if(!settings.listen_port ||
               settings.listen_port <= 0 ||
               settings.listen_port > 0xffff)
            {
                fprintf(stderr, "%s: wrong port value: %s\n", progname, optarg);
                usage(EXIT_FAILURE);
            }
            break;
        case 's':
            //source whitelist
            if(acl_parse(&settings.src_whitelist, optarg)) {
                fprintf(stderr, "%s: failed to parse src_whitelist: '%s'\n", progname, optarg);
                usage(EXIT_FAILURE);
            }
            break;
        case 'd':
            //destination whitelist
            if(acl_parse(&settings.dst_whitelist, optarg)) {
                fprintf(stderr, "%s: failed to parse dst_whitelist: '%s'\n", progname, optarg);
                usage(EXIT_FAILURE);
            }
            break;
        default:
            break;
        }
    }

    if(!strlen(settings.listen_host)) {
        strcpy(settings.listen_host, "127.0.0.1");
    }

    acl_print(settings.src_whitelist, "src_whitelist");
    acl_print(settings.dst_whitelist, "dst_whitelist");

    start();

    return EXIT_SUCCESS;
}

