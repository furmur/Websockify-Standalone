#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "WebsocketBridge.h"
#include "version.h"

const char* progname = NULL;

void usage(int exit_code)
{
    printf(
    "version: " APP_VERSION "\n"
    "Usage: virtualizm-wsproxy [-h] [-i listen_ip] [-p port]\n"
    "\n"
    "Options:\n"
    "  -i listen_ip : IP adddress for WS socket\n"
    "  -p port      : port for WS socket\n"
    "  -h           : this help\n\n");
    exit(exit_code);
}

int main(int argc, char **argv)
{
    char *listen_host = "127.0.0.1";
    int listen_port = 52525;

    progname = strrchr(argv[0], '/');
    progname = (progname == NULL ? argv[0] : progname + 1);

    static const char* opts = "hi:p:";
    int opt;
    while (-1!=(opt = getopt(argc, argv, opts))) {
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
            listen_host = optarg;
            break;
        case 'p':
            listen_port = atoi(optarg);
            if(!listen_port || listen_port <= 0 || listen_port > 0xffff) {
                fprintf(stderr, "%s: wrong port value: %s\n", progname, optarg);
                usage(EXIT_FAILURE);
            }
            break;
        default:
            break;
        }
    }

    start(listen_host, listen_port);

    return EXIT_SUCCESS;
}
