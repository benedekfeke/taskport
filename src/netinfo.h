#ifndef NETINFO_H
#define NETINFO_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    COL_PROTO = 0,
    COL_PORT,
    COL_PID,
    COL_PROCESS,
    COL_STATE,
    COL_LOCAL_ADDR,
    COL_REMOTE_ADDR,
    COL_REMOTE_PORT,
    COL_MEM,
    COL_USER,
    COL_PATH,
    COL_COUNT
} ColumnId;

typedef struct {
    ColumnId id;
    const char *title;
    const char *cli_name;
    int width;
    bool right_align;
    bool flex;
    bool default_visible;
} ColumnMeta;

typedef struct {
    char proto[8];
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t pid;
    char local_addr[64];
    char remote_addr[64];
    char state[16];
    bool is_listening;
    char process_name[128];
    char user[128];
    char exe_path[512];
    uint64_t mem_bytes;
    bool has_mem;
} PortEntry;

typedef struct {
    PortEntry *items;
    size_t count;
    size_t capacity;
} PortList;

void port_list_init(PortList *list);
void port_list_free(PortList *list);
void port_list_clear(PortList *list);

const ColumnMeta *netinfo_column_meta(ColumnId col);
int netinfo_column_from_name(const char *name);

bool netinfo_collect(PortList *list, char *err_buf, size_t err_cap);
void netinfo_sort(PortList *list, ColumnId col, bool desc);
bool netinfo_kill_process(uint32_t pid, char *err_buf, size_t err_cap);

#endif /* NETINFO_H */
