#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "netinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const ColumnMeta COLUMN_METAS[COL_COUNT] = {
    { COL_PROTO,       "PROTO",       "proto",  5,  false, false, true },
    { COL_PORT,        "PORT",        "port",   6,  true,  false, true },
    { COL_PID,         "PID",         "pid",    7,  true,  false, true },
    { COL_PROCESS,     "PROCESS",     "process",20, false, false, true },
    { COL_STATE,       "STATE",       "state",  11, false, false, true },
    { COL_LOCAL_ADDR,  "LOCAL ADDR",  "local",  16, false, false, true },
    { COL_REMOTE_ADDR, "REMOTE ADDR", "remote", 16, false, false, true },
    { COL_REMOTE_PORT, "RPORT",       "rport",  6,  true,  false, true },
    { COL_MEM,         "MEM (MB)",    "mem",    9,  true,  false, true },
    { COL_USER,        "USER",        "user",   16, false, false, true },
    { COL_PATH,        "PATH",        "path",   24, false, true,  true }
};

void port_list_init(PortList *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void port_list_free(PortList *list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void port_list_clear(PortList *list) {
    list->count = 0;
}

static bool port_list_push(PortList *list, const PortEntry *entry) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity == 0 ? 128 : list->capacity * 2;
        PortEntry *new_items = (PortEntry *)realloc(list->items, new_cap * sizeof(PortEntry));
        if (!new_items) return false;
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *entry;
    return true;
}

const ColumnMeta *netinfo_column_meta(ColumnId col) {
    if (col < 0 || col >= COL_COUNT) return NULL;
    return &COLUMN_METAS[col];
}

int netinfo_column_from_name(const char *name) {
    if (!name || !*name) return -1;
    if (_stricmp(name, "proto") == 0 || _stricmp(name, "protocol") == 0) return COL_PROTO;
    if (_stricmp(name, "port") == 0) return COL_PORT;
    if (_stricmp(name, "pid") == 0) return COL_PID;
    if (_stricmp(name, "process") == 0 || _stricmp(name, "name") == 0) return COL_PROCESS;
    if (_stricmp(name, "state") == 0) return COL_STATE;
    if (_stricmp(name, "local") == 0 || _stricmp(name, "local_addr") == 0) return COL_LOCAL_ADDR;
    if (_stricmp(name, "remote") == 0 || _stricmp(name, "remote_addr") == 0) return COL_REMOTE_ADDR;
    if (_stricmp(name, "rport") == 0 || _stricmp(name, "remote_port") == 0) return COL_REMOTE_PORT;
    if (_stricmp(name, "mem") == 0 || _stricmp(name, "memory") == 0) return COL_MEM;
    if (_stricmp(name, "user") == 0) return COL_USER;
    if (_stricmp(name, "path") == 0) return COL_PATH;
    return -1;
}

static void copy_str(char *dst, size_t dst_cap, const char *src) {
    if (!dst || dst_cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_cap, "%s", src);
}

static const char *tcp_state_str(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTAB";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

typedef struct {
    uint32_t pid;
    char process_name[128];
    char user[128];
    char exe_path[512];
    uint64_t mem_bytes;
    bool has_mem;
    bool queried_details;
} PidCacheEntry;

typedef struct {
    PidCacheEntry *items;
    size_t count;
    size_t capacity;
} PidCache;

static void pid_cache_init(PidCache *cache) {
    cache->items = NULL;
    cache->count = 0;
    cache->capacity = 0;
}

static void pid_cache_free(PidCache *cache) {
    free(cache->items);
    cache->items = NULL;
    cache->count = 0;
    cache->capacity = 0;
}

static PidCacheEntry *pid_cache_find(PidCache *cache, uint32_t pid) {
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->items[i].pid == pid) {
            return &cache->items[i];
        }
    }
    return NULL;
}

static PidCacheEntry *pid_cache_get_or_add(PidCache *cache, uint32_t pid) {
    PidCacheEntry *existing = pid_cache_find(cache, pid);
    if (existing) return existing;

    if (cache->count >= cache->capacity) {
        size_t new_cap = cache->capacity == 0 ? 128 : cache->capacity * 2;
        PidCacheEntry *new_items = (PidCacheEntry *)realloc(cache->items, new_cap * sizeof(PidCacheEntry));
        if (!new_items) return NULL;
        cache->items = new_items;
        cache->capacity = new_cap;
    }

    PidCacheEntry *e = &cache->items[cache->count++];
    memset(e, 0, sizeof(*e));
    e->pid = pid;
    copy_str(e->process_name, sizeof(e->process_name), "-");
    copy_str(e->user, sizeof(e->user), "-");
    copy_str(e->exe_path, sizeof(e->exe_path), "-");
    return e;
}

static void populate_snapshot_names(PidCache *cache) {
    PidCacheEntry *idle = pid_cache_get_or_add(cache, 0);
    if (idle) {
        copy_str(idle->process_name, sizeof(idle->process_name), "System Idle Process");
        copy_str(idle->user, sizeof(idle->user), "NT AUTHORITY\\SYSTEM");
        idle->queried_details = true;
    }
    PidCacheEntry *sys = pid_cache_get_or_add(cache, 4);
    if (sys) {
        copy_str(sys->process_name, sizeof(sys->process_name), "System");
        copy_str(sys->user, sizeof(sys->user), "NT AUTHORITY\\SYSTEM");
        sys->queried_details = true;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            PidCacheEntry *entry = pid_cache_get_or_add(cache, (uint32_t)pe.th32ProcessID);
            if (entry && pe.szExeFile[0] != '\0') {
                copy_str(entry->process_name, sizeof(entry->process_name), pe.szExeFile);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static void query_pid_details(PidCacheEntry *entry) {
    if (!entry || entry->queried_details) return;
    entry->queried_details = true;

    if (entry->pid == 0 || entry->pid == 4) return;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, entry->pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry->pid);
    }
    if (!hProc) return;

    /* Memory */
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
        entry->mem_bytes = (uint64_t)pmc.WorkingSetSize;
        entry->has_mem = true;
    }

    /* Full executable path */
    DWORD path_len = (DWORD)sizeof(entry->exe_path);
    char path_buf[512];
    if (QueryFullProcessImageNameA(hProc, 0, path_buf, &path_len) && path_len > 0) {
        copy_str(entry->exe_path, sizeof(entry->exe_path), path_buf);
        if (strcmp(entry->process_name, "-") == 0) {
            const char *slash = strrchr(path_buf, '\\');
            copy_str(entry->process_name, sizeof(entry->process_name), slash ? slash + 1 : path_buf);
        }
    }

    /* User account */
    HANDLE hTok = NULL;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
        DWORD tok_len = 0;
        GetTokenInformation(hTok, TokenUser, NULL, 0, &tok_len);
        if (tok_len > 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            BYTE *buf = (BYTE *)malloc(tok_len);
            if (buf) {
                if (GetTokenInformation(hTok, TokenUser, buf, tok_len, &tok_len)) {
                    TOKEN_USER *tu = (TOKEN_USER *)buf;
                    char name[64] = {0};
                    char domain[64] = {0};
                    DWORD name_len = sizeof(name);
                    DWORD domain_len = sizeof(domain);
                    SID_NAME_USE snu;
                    if (LookupAccountSidA(NULL, tu->User.Sid, name, &name_len, domain, &domain_len, &snu)) {
                        if (domain[0] != '\0') {
                            snprintf(entry->user, sizeof(entry->user), "%s\\%s", domain, name);
                        } else {
                            copy_str(entry->user, sizeof(entry->user), name);
                        }
                    }
                }
                free(buf);
            }
        }
        CloseHandle(hTok);
    }

    CloseHandle(hProc);
}

static void fill_pid_metadata(PidCache *cache, PortEntry *e) {
    PidCacheEntry *pc = pid_cache_get_or_add(cache, e->pid);
    if (!pc) {
        copy_str(e->process_name, sizeof(e->process_name), "-");
        copy_str(e->user, sizeof(e->user), "-");
        copy_str(e->exe_path, sizeof(e->exe_path), "-");
        e->mem_bytes = 0;
        e->has_mem = false;
        return;
    }
    query_pid_details(pc);
    copy_str(e->process_name, sizeof(e->process_name), pc->process_name);
    copy_str(e->user, sizeof(e->user), pc->user);
    copy_str(e->exe_path, sizeof(e->exe_path), pc->exe_path);
    e->mem_bytes = pc->mem_bytes;
    e->has_mem = pc->has_mem;
}

static void format_ipv4(DWORD addr, char *buf, size_t cap) {
    struct in_addr in;
    in.S_un.S_addr = addr;
    if (!InetNtopA(AF_INET, &in, buf, (socklen_t)cap)) {
        copy_str(buf, cap, "?");
    }
}

static void format_ipv6(const UCHAR addr[16], char *buf, size_t cap) {
    struct in6_addr in6;
    memcpy(&in6, addr, 16);
    if (!InetNtopA(AF_INET6, &in6, buf, (socklen_t)cap)) {
        copy_str(buf, cap, "?");
    }
}

static void *fetch_tcp_table(ULONG af, DWORD *out_err) {
    DWORD size = 16384;
    for (int attempt = 0; attempt < 4; attempt++) {
        void *buf = malloc(size);
        if (!buf) {
            if (out_err) *out_err = ERROR_OUTOFMEMORY;
            return NULL;
        }
        DWORD ret = GetExtendedTcpTable(buf, &size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR) {
            if (out_err) *out_err = NO_ERROR;
            return buf;
        }
        free(buf);
        if (ret != ERROR_INSUFFICIENT_BUFFER) {
            if (out_err) *out_err = ret;
            return NULL;
        }
        size += 4096;
    }
    if (out_err) *out_err = ERROR_INSUFFICIENT_BUFFER;
    return NULL;
}

static void *fetch_udp_table(ULONG af, DWORD *out_err) {
    DWORD size = 16384;
    for (int attempt = 0; attempt < 4; attempt++) {
        void *buf = malloc(size);
        if (!buf) {
            if (out_err) *out_err = ERROR_OUTOFMEMORY;
            return NULL;
        }
        DWORD ret = GetExtendedUdpTable(buf, &size, FALSE, af, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR) {
            if (out_err) *out_err = NO_ERROR;
            return buf;
        }
        free(buf);
        if (ret != ERROR_INSUFFICIENT_BUFFER) {
            if (out_err) *out_err = ret;
            return NULL;
        }
        size += 4096;
    }
    if (out_err) *out_err = ERROR_INSUFFICIENT_BUFFER;
    return NULL;
}

bool netinfo_collect(PortList *list, char *err_buf, size_t err_cap) {
    port_list_clear(list);

    PidCache cache;
    pid_cache_init(&cache);
    populate_snapshot_names(&cache);

    DWORD err = NO_ERROR;
    int tables_ok = 0;

    /* TCP v4 */
    MIB_TCPTABLE_OWNER_PID *tcp4 = (MIB_TCPTABLE_OWNER_PID *)fetch_tcp_table(AF_INET, &err);
    if (tcp4) {
        tables_ok++;
        for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
            const MIB_TCPROW_OWNER_PID *r = &tcp4->table[i];
            PortEntry e;
            memset(&e, 0, sizeof(e));
            copy_str(e.proto, sizeof(e.proto), "TCP");
            e.local_port = ntohs((u_short)r->dwLocalPort);
            e.remote_port = (r->dwState == MIB_TCP_STATE_LISTEN) ? 0 : ntohs((u_short)r->dwRemotePort);
            e.pid = (uint32_t)r->dwOwningPid;
            format_ipv4(r->dwLocalAddr, e.local_addr, sizeof(e.local_addr));
            if (r->dwState == MIB_TCP_STATE_LISTEN) {
                copy_str(e.remote_addr, sizeof(e.remote_addr), "*");
            } else {
                format_ipv4(r->dwRemoteAddr, e.remote_addr, sizeof(e.remote_addr));
            }
            copy_str(e.state, sizeof(e.state), tcp_state_str(r->dwState));
            e.is_listening = (r->dwState == MIB_TCP_STATE_LISTEN);
            fill_pid_metadata(&cache, &e);
            port_list_push(list, &e);
        }
        free(tcp4);
    }

    /* TCP v6 */
    MIB_TCP6TABLE_OWNER_PID *tcp6 = (MIB_TCP6TABLE_OWNER_PID *)fetch_tcp_table(AF_INET6, &err);
    if (tcp6) {
        tables_ok++;
        for (DWORD i = 0; i < tcp6->dwNumEntries; i++) {
            const MIB_TCP6ROW_OWNER_PID *r = &tcp6->table[i];
            PortEntry e;
            memset(&e, 0, sizeof(e));
            copy_str(e.proto, sizeof(e.proto), "TCP6");
            e.local_port = ntohs((u_short)r->dwLocalPort);
            e.remote_port = (r->dwState == MIB_TCP_STATE_LISTEN) ? 0 : ntohs((u_short)r->dwRemotePort);
            e.pid = (uint32_t)r->dwOwningPid;
            format_ipv6(r->ucLocalAddr, e.local_addr, sizeof(e.local_addr));
            if (r->dwState == MIB_TCP_STATE_LISTEN) {
                copy_str(e.remote_addr, sizeof(e.remote_addr), "*");
            } else {
                format_ipv6(r->ucRemoteAddr, e.remote_addr, sizeof(e.remote_addr));
            }
            copy_str(e.state, sizeof(e.state), tcp_state_str(r->dwState));
            e.is_listening = (r->dwState == MIB_TCP_STATE_LISTEN);
            fill_pid_metadata(&cache, &e);
            port_list_push(list, &e);
        }
        free(tcp6);
    }

    /* UDP v4 */
    MIB_UDPTABLE_OWNER_PID *udp4 = (MIB_UDPTABLE_OWNER_PID *)fetch_udp_table(AF_INET, &err);
    if (udp4) {
        tables_ok++;
        for (DWORD i = 0; i < udp4->dwNumEntries; i++) {
            const MIB_UDPROW_OWNER_PID *r = &udp4->table[i];
            PortEntry e;
            memset(&e, 0, sizeof(e));
            copy_str(e.proto, sizeof(e.proto), "UDP");
            e.local_port = ntohs((u_short)r->dwLocalPort);
            e.remote_port = 0;
            e.pid = (uint32_t)r->dwOwningPid;
            format_ipv4(r->dwLocalAddr, e.local_addr, sizeof(e.local_addr));
            copy_str(e.remote_addr, sizeof(e.remote_addr), "*");
            copy_str(e.state, sizeof(e.state), "-");
            e.is_listening = true;
            fill_pid_metadata(&cache, &e);
            port_list_push(list, &e);
        }
        free(udp4);
    }

    /* UDP v6 */
    MIB_UDP6TABLE_OWNER_PID *udp6 = (MIB_UDP6TABLE_OWNER_PID *)fetch_udp_table(AF_INET6, &err);
    if (udp6) {
        tables_ok++;
        for (DWORD i = 0; i < udp6->dwNumEntries; i++) {
            const MIB_UDP6ROW_OWNER_PID *r = &udp6->table[i];
            PortEntry e;
            memset(&e, 0, sizeof(e));
            copy_str(e.proto, sizeof(e.proto), "UDP6");
            e.local_port = ntohs((u_short)r->dwLocalPort);
            e.remote_port = 0;
            e.pid = (uint32_t)r->dwOwningPid;
            format_ipv6(r->ucLocalAddr, e.local_addr, sizeof(e.local_addr));
            copy_str(e.remote_addr, sizeof(e.remote_addr), "*");
            copy_str(e.state, sizeof(e.state), "-");
            e.is_listening = true;
            fill_pid_metadata(&cache, &e);
            port_list_push(list, &e);
        }
        free(udp6);
    }

    pid_cache_free(&cache);

    if (tables_ok == 0) {
        if (err_buf && err_cap > 0) {
            snprintf(err_buf, err_cap, "Failed to query network tables (Win32 error %lu)", (unsigned long)err);
        }
        return false;
    }
    return true;
}

static ColumnId g_sort_col = COL_PORT;
static bool g_sort_desc = false;

static int cmp_u64(uint64_t a, uint64_t b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

static int compare_port_entries(const void *pa, const void *pb) {
    const PortEntry *a = (const PortEntry *)pa;
    const PortEntry *b = (const PortEntry *)pb;
    int cmp = 0;

    switch (g_sort_col) {
        case COL_PROTO:       cmp = _stricmp(a->proto, b->proto); break;
        case COL_PORT:        cmp = cmp_u64(a->local_port, b->local_port); break;
        case COL_PID:         cmp = cmp_u64(a->pid, b->pid); break;
        case COL_PROCESS:     cmp = _stricmp(a->process_name, b->process_name); break;
        case COL_STATE:       cmp = _stricmp(a->state, b->state); break;
        case COL_LOCAL_ADDR:  cmp = _stricmp(a->local_addr, b->local_addr); break;
        case COL_REMOTE_ADDR: cmp = _stricmp(a->remote_addr, b->remote_addr); break;
        case COL_REMOTE_PORT: cmp = cmp_u64(a->remote_port, b->remote_port); break;
        case COL_MEM: {
            uint64_t ma = a->has_mem ? a->mem_bytes : 0;
            uint64_t mb = b->has_mem ? b->mem_bytes : 0;
            cmp = cmp_u64(ma, mb);
            break;
        }
        case COL_USER:        cmp = _stricmp(a->user, b->user); break;
        case COL_PATH:        cmp = _stricmp(a->exe_path, b->exe_path); break;
        default:              cmp = 0; break;
    }

    if (cmp != 0) {
        return g_sort_desc ? -cmp : cmp;
    }

    /* Stable tie-breakers */
    cmp = cmp_u64(a->local_port, b->local_port);
    if (cmp != 0) return cmp;
    cmp = cmp_u64(a->pid, b->pid);
    if (cmp != 0) return cmp;
    cmp = _stricmp(a->proto, b->proto);
    if (cmp != 0) return cmp;
    return cmp_u64(a->remote_port, b->remote_port);
}

void netinfo_sort(PortList *list, ColumnId col, bool desc) {
    if (!list || list->count < 2) return;
    g_sort_col = col;
    g_sort_desc = desc;
    qsort(list->items, list->count, sizeof(PortEntry), compare_port_entries);
}

bool netinfo_kill_process(uint32_t pid, char *err_buf, size_t err_cap) {
    if (pid == 0 || pid == 4) {
        if (err_buf && err_cap > 0) {
            snprintf(err_buf, err_cap, "Refusing to terminate protected system PID %u", pid);
        }
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        if (err_buf && err_cap > 0) {
            if (err == ERROR_ACCESS_DENIED) {
                snprintf(err_buf, err_cap, "Access denied killing PID %u (try running as Administrator)", pid);
            } else if (err == ERROR_INVALID_PARAMETER) {
                snprintf(err_buf, err_cap, "PID %u no longer exists", pid);
            } else {
                char msg[192] = {0};
                FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL, err, 0, msg, sizeof(msg), NULL);
                /* Strip trailing CR/LF */
                size_t len = strlen(msg);
                while (len > 0 && (msg[len - 1] == '\r' || msg[len - 1] == '\n')) {
                    msg[--len] = '\0';
                }
                snprintf(err_buf, err_cap, "OpenProcess(%u) failed: %s", pid, msg[0] ? msg : "unknown error");
            }
        }
        return false;
    }

    BOOL ok = TerminateProcess(hProc, 1);
    DWORD term_err = ok ? 0 : GetLastError();
    CloseHandle(hProc);

    if (!ok) {
        if (err_buf && err_cap > 0) {
            if (term_err == ERROR_ACCESS_DENIED) {
                snprintf(err_buf, err_cap, "Access denied terminating PID %u (try running as Administrator)", pid);
            } else {
                snprintf(err_buf, err_cap, "TerminateProcess(%u) failed (error %lu)", pid, (unsigned long)term_err);
            }
        }
        return false;
    }
    return true;
}
