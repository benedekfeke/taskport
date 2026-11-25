#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <windows.h>

#include "app.h"
#include "netinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog) {
    printf("taskport - Windows Terminal TUI for active ports & processes\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  --dump               Print table once to stdout and exit\n");
    printf("  --listen             Show only listening/bound sockets\n");
    printf("  --sort <col>         Initial sort column (proto,port,pid,process,state,\n");
    printf("                       local,remote,rport,mem,user,path)\n");
    printf("  --desc               Sort descending\n");
    printf("  --hide <c1,c2,...>   Comma-separated columns to hide initially\n");
    printf("  -h, --help           Show this help message\n\n");
    printf("TUI Keys:\n");
    printf("  Up/Down, PgUp/PgDn, Mouse Wheel/Click : Navigate\n");
    printf("  k / Delete                            : Kill selected process\n");
    printf("  s / [ / ] / o / Click Header          : Sort & flip ASC/DESC\n");
    printf("  c                                     : Toggle column visibility\n");
    printf("  /                                     : Live filter\n");
    printf("  l                                     : Toggle listening-only\n");
    printf("  r / p                                 : Refresh / Pause auto-refresh\n");
    printf("  ? / q / Ctrl+C                        : Help / Quit\n");
}

static bool parse_hide_list(AppConfig *cfg, const char *arg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", arg);
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        int col = netinfo_column_from_name(tok);
        if (col < 0) {
            fprintf(stderr, "Unknown column name in --hide: '%s'\n", tok);
            return false;
        }
        cfg->col_visible[col] = false;
        tok = strtok(NULL, ",");
    }

    int vis = 0;
    for (int i = 0; i < COL_COUNT; i++) {
        if (cfg->col_visible[i]) vis++;
    }
    if (vis == 0) {
        fprintf(stderr, "Error: cannot hide all columns.\n");
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    AppConfig cfg;
    app_config_default(&cfg);
    bool dump_mode = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(arg, "--dump") == 0) {
            dump_mode = true;
        } else if (strcmp(arg, "--listen") == 0) {
            cfg.listen_only = true;
        } else if (strcmp(arg, "--desc") == 0) {
            cfg.sort_desc = true;
        } else if (strcmp(arg, "--sort") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for --sort\n");
                return 1;
            }
            int col = netinfo_column_from_name(argv[++i]);
            if (col < 0) {
                fprintf(stderr, "Unknown sort column: '%s'\n", argv[i]);
                return 1;
            }
            cfg.sort_col = (ColumnId)col;
        } else if (strcmp(arg, "--hide") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for --hide\n");
                return 1;
            }
            if (!parse_hide_list(&cfg, argv[++i])) {
                return 1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s (use --help)\n", arg);
            return 1;
        }
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    int rc = dump_mode ? app_dump(&cfg) : app_run(&cfg);

    WSACleanup();
    return rc;
}
