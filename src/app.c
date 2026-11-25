#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include "app.h"
#include "tui.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    MODAL_NONE = 0,
    MODAL_KILL,
    MODAL_COLUMNS,
    MODAL_SORT,
    MODAL_HELP
} ModalType;

typedef struct {
    ColumnId id;
    int x_start;
    int width;
} ColLayout;

typedef struct {
    PortList all;
    size_t *filtered;
    size_t filtered_count;
    size_t filtered_cap;

    int selected;
    int scroll_offset;

    ColumnId sort_col;
    bool sort_desc;
    bool col_visible[COL_COUNT];

    bool listen_only;
    bool paused;
    bool filter_editing;
    char filter_text[128];

    ModalType modal;
    int modal_cursor;
    PortEntry kill_target;
    int kill_target_port_count;

    char status_msg[256];
    int status_level; /* 0=info, 1=ok, 2=err */
    ULONGLONG status_until;

    ULONGLONG last_refresh_ms;

    ColLayout layout[COL_COUNT];
    int layout_count;
    int header_row_y;
    int data_start_y;
    int data_rows;
} AppState;

void app_config_default(AppConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->sort_col = COL_PORT;
    cfg->sort_desc = false;
    cfg->listen_only = false;
    for (int i = 0; i < COL_COUNT; i++) {
        const ColumnMeta *m = netinfo_column_meta((ColumnId)i);
        cfg->col_visible[i] = m ? m->default_visible : true;
    }
}

static void set_status(AppState *st, int level, const char *msg) {
    st->status_level = level;
    snprintf(st->status_msg, sizeof(st->status_msg), "%s", msg ? msg : "");
    st->status_until = GetTickCount64() + 4500ULL;
}

static bool contains_icase(const char *haystack, const char *needle) {
    if (!needle || !*needle) return true;
    if (!haystack || !*haystack) return false;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    if (nlen > hlen) return false;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (_strnicmp(haystack + i, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

static bool entry_matches_filter(const PortEntry *e, const char *filter) {
    if (!filter || !*filter) return true;
    char port_buf[16];
    char rport_buf[16];
    char pid_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%u", e->local_port);
    snprintf(rport_buf, sizeof(rport_buf), "%u", e->remote_port);
    snprintf(pid_buf, sizeof(pid_buf), "%u", e->pid);

    return contains_icase(e->process_name, filter) ||
           contains_icase(pid_buf, filter) ||
           contains_icase(port_buf, filter) ||
           contains_icase(rport_buf, filter) ||
           contains_icase(e->proto, filter) ||
           contains_icase(e->state, filter) ||
           contains_icase(e->local_addr, filter) ||
           contains_icase(e->remote_addr, filter) ||
           contains_icase(e->user, filter) ||
           contains_icase(e->exe_path, filter);
}

static void rebuild_filtered(AppState *st) {
    st->filtered_count = 0;
    if (st->all.count > st->filtered_cap) {
        size_t new_cap = st->all.count + 32;
        size_t *new_buf = (size_t *)realloc(st->filtered, new_cap * sizeof(size_t));
        if (!new_buf) return;
        st->filtered = new_buf;
        st->filtered_cap = new_cap;
    }

    for (size_t i = 0; i < st->all.count; i++) {
        const PortEntry *e = &st->all.items[i];
        if (st->listen_only && !e->is_listening) continue;
        if (!entry_matches_filter(e, st->filter_text)) continue;
        st->filtered[st->filtered_count++] = i;
    }

    if (st->filtered_count == 0) {
        st->selected = 0;
        st->scroll_offset = 0;
    } else if (st->selected >= (int)st->filtered_count) {
        st->selected = (int)st->filtered_count - 1;
    } else if (st->selected < 0) {
        st->selected = 0;
    }
}

static void refresh_data(AppState *st) {
    bool has_prev = false;
    PortEntry prev;
    if (st->filtered_count > 0 && st->selected >= 0 && st->selected < (int)st->filtered_count) {
        prev = st->all.items[st->filtered[st->selected]];
        has_prev = true;
    }

    char err[256] = {0};
    if (!netinfo_collect(&st->all, err, sizeof(err))) {
        set_status(st, 2, err[0] ? err : "Failed to collect port information");
        return;
    }

    netinfo_sort(&st->all, st->sort_col, st->sort_desc);
    rebuild_filtered(st);

    if (has_prev && st->filtered_count > 0) {
        for (size_t i = 0; i < st->filtered_count; i++) {
            const PortEntry *e = &st->all.items[st->filtered[i]];
            if (e->pid == prev.pid &&
                e->local_port == prev.local_port &&
                e->remote_port == prev.remote_port &&
                strcmp(e->proto, prev.proto) == 0 &&
                strcmp(e->local_addr, prev.local_addr) == 0) {
                st->selected = (int)i;
                break;
            }
        }
    }

    st->last_refresh_ms = GetTickCount64();
}

static void format_cell(const PortEntry *e, ColumnId col, char *buf, size_t cap) {
    switch (col) {
        case COL_PROTO:
            snprintf(buf, cap, "%s", e->proto);
            break;
        case COL_PORT:
            snprintf(buf, cap, "%u", e->local_port);
            break;
        case COL_PID:
            snprintf(buf, cap, "%u", e->pid);
            break;
        case COL_PROCESS:
            snprintf(buf, cap, "%s", e->process_name);
            break;
        case COL_STATE:
            snprintf(buf, cap, "%s", e->state);
            break;
        case COL_LOCAL_ADDR:
            snprintf(buf, cap, "%s", e->local_addr);
            break;
        case COL_REMOTE_ADDR:
            snprintf(buf, cap, "%s", e->remote_addr);
            break;
        case COL_REMOTE_PORT:
            if (e->remote_port == 0) snprintf(buf, cap, "-");
            else snprintf(buf, cap, "%u", e->remote_port);
            break;
        case COL_MEM:
            if (!e->has_mem) snprintf(buf, cap, "-");
            else snprintf(buf, cap, "%.1f", (double)e->mem_bytes / (1024.0 * 1024.0));
            break;
        case COL_USER:
            snprintf(buf, cap, "%s", e->user);
            break;
        case COL_PATH:
            snprintf(buf, cap, "%s", e->exe_path);
            break;
        default:
            snprintf(buf, cap, "-");
            break;
    }
}

static void fit_cell_text(const char *src, int width, bool right_align, char *out, size_t out_cap) {
    if (width <= 0 || out_cap == 0) {
        if (out_cap > 0) out[0] = '\0';
        return;
    }
    int len = (int)strlen(src);
    char tmp[512];
    if (len > width) {
        if (width >= 4) {
            memcpy(tmp, src, (size_t)(width - 3));
            memcpy(tmp + width - 3, "...", 3);
            tmp[width] = '\0';
        } else {
            memcpy(tmp, src, (size_t)width);
            tmp[width] = '\0';
        }
    } else {
        snprintf(tmp, sizeof(tmp), "%s", src);
    }

    int tlen = (int)strlen(tmp);
    int pad = width - tlen;
    if (pad < 0) pad = 0;

    if ((size_t)width + 1 > out_cap) {
        width = (int)out_cap - 1;
    }

    if (right_align) {
        memset(out, ' ', (size_t)pad);
        memcpy(out + pad, tmp, (size_t)tlen);
        out[width] = '\0';
    } else {
        memcpy(out, tmp, (size_t)tlen);
        memset(out + tlen, ' ', (size_t)pad);
        out[width] = '\0';
    }
}

static void compute_layout(AppState *st, int term_cols) {
    st->layout_count = 0;
    int used = 1; /* leading 1-char margin */
    int flex_idx = -1;

    for (int i = 0; i < COL_COUNT; i++) {
        if (!st->col_visible[i]) continue;
        const ColumnMeta *m = netinfo_column_meta((ColumnId)i);
        if (!m) continue;

        int min_need = m->width;
        if (st->layout_count > 0 && used + 1 + 4 > term_cols) {
            break; /* no room for more columns */
        }

        int w = min_need;
        if (used + w + 1 > term_cols) {
            w = term_cols - used - 1;
            if (w < 4) break;
        }

        st->layout[st->layout_count].id = (ColumnId)i;
        st->layout[st->layout_count].x_start = used;
        st->layout[st->layout_count].width = w;
        if (m->flex) flex_idx = st->layout_count;
        used += w + 1;
        st->layout_count++;
    }

    /* Distribute remaining space to flex column (or last visible column) */
    if (st->layout_count > 0 && used < term_cols) {
        int extra = term_cols - used;
        int target = (flex_idx >= 0) ? flex_idx : (st->layout_count - 1);
        st->layout[target].width += extra;
        for (int k = target + 1; k < st->layout_count; k++) {
            st->layout[k].x_start += extra;
        }
    }
}

static void ensure_visible_selection(AppState *st) {
    if (st->data_rows <= 0) return;
    if (st->selected < st->scroll_offset) {
        st->scroll_offset = st->selected;
    } else if (st->selected >= st->scroll_offset + st->data_rows) {
        st->scroll_offset = st->selected - st->data_rows + 1;
    }
    if (st->scroll_offset < 0) st->scroll_offset = 0;
}

static void draw_box(FrameBuf *fb, int top_y, int left_x, int box_w, int box_h, const char *title) {
    /* Top border */
    fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;117m\xe2\x94\x8c", top_y + 1, left_x + 1);
    int inner_w = box_w - 2;
    int tlen = title ? (int)strlen(title) : 0;
    if (tlen > 0 && tlen + 4 <= inner_w) {
        fb_append(fb, "\xe2\x94\x80 ");
        fb_appendf(fb, "\x1b[1m%s\x1b[22m ", title);
        for (int i = tlen + 3; i < inner_w; i++) fb_append(fb, "\xe2\x94\x80");
    } else {
        for (int i = 0; i < inner_w; i++) fb_append(fb, "\xe2\x94\x80");
    }
    fb_append(fb, "\xe2\x94\x90");

    /* Interior rows */
    for (int r = 1; r < box_h - 1; r++) {
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;117m\xe2\x94\x82\x1b[38;5;252m", top_y + r + 1, left_x + 1);
        for (int c = 0; c < inner_w; c++) fb_append(fb, " ");
        fb_append(fb, "\x1b[38;5;117m\xe2\x94\x82");
    }

    /* Bottom border */
    fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;117m\xe2\x94\x94", top_y + box_h, left_x + 1);
    for (int i = 0; i < inner_w; i++) fb_append(fb, "\xe2\x94\x80");
    fb_append(fb, "\xe2\x94\x98\x1b[0m");
}

static void render_modals(FrameBuf *fb, const AppState *st, int cols, int rows) {
    if (st->modal == MODAL_NONE) return;

    if (st->modal == MODAL_KILL) {
        int bw = (cols < 64) ? cols - 4 : 62;
        int bh = 11;
        int bx = (cols - bw) / 2;
        int by = (rows - bh) / 2;
        if (bx < 0) bx = 0;
        if (by < 0) by = 0;

        draw_box(fb, by, bx, bw, bh, "Confirm Kill Process");
        int tx = bx + 3;
        int max_val = bw - 16;
        if (max_val < 10) max_val = 10;

        char tmp[512];
        fit_cell_text(st->kill_target.process_name, max_val, false, tmp, sizeof(tmp));
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;250mProcess : \x1b[1;38;5;255m%s\x1b[0m", by + 3, tx, tmp);

        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;250mPID     : \x1b[1;38;5;221m%u\x1b[0m", by + 4, tx, st->kill_target.pid);

        char ep[64];
        snprintf(ep, sizeof(ep), "%s %s:%u", st->kill_target.proto, st->kill_target.local_addr, st->kill_target.local_port);
        fit_cell_text(ep, max_val, false, tmp, sizeof(tmp));
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;250mEndpoint: \x1b[38;5;252m%s\x1b[0m", by + 5, tx, tmp);

        fit_cell_text(st->kill_target.exe_path, max_val, false, tmp, sizeof(tmp));
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;250mPath    : \x1b[38;5;245m%s\x1b[0m", by + 6, tx, tmp);

        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;210mThis PID owns %d socket(s)/port(s).\x1b[0m",
                   by + 7, tx, st->kill_target_port_count);

        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;255mPress \x1b[1;38;5;196m[Y / Enter]\x1b[22;38;5;255m to KILL, \x1b[1;38;5;117m[N / Esc]\x1b[22;38;5;255m to Cancel\x1b[0m",
                   by + 9, tx);
    } else if (st->modal == MODAL_COLUMNS) {
        int bw = (cols < 46) ? cols - 4 : 44;
        int bh = COL_COUNT + 6;
        int bx = (cols - bw) / 2;
        int by = (rows - bh) / 2;
        if (bx < 0) bx = 0;
        if (by < 0) by = 0;

        draw_box(fb, by, bx, bw, bh, "Toggle Columns");
        for (int i = 0; i < COL_COUNT; i++) {
            const ColumnMeta *m = netinfo_column_meta((ColumnId)i);
            bool sel = (i == st->modal_cursor);
            bool vis = st->col_visible[i];
            fb_appendf(fb, "\x1b[%d;%dH%s[%c] %-14s (%s)\x1b[0m",
                       by + 3 + i, bx + 3,
                       sel ? "\x1b[48;5;24;38;5;255;1m" : "\x1b[48;5;236;38;5;252m",
                       vis ? 'x' : ' ',
                       m->title,
                       m->cli_name);
        }
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;246mSpace:Toggle  a:All  d:Default  Esc:Close\x1b[0m",
                   by + bh - 2, bx + 2);
    } else if (st->modal == MODAL_SORT) {
        int bw = (cols < 46) ? cols - 4 : 44;
        int bh = COL_COUNT + 6;
        int bx = (cols - bw) / 2;
        int by = (rows - bh) / 2;
        if (bx < 0) bx = 0;
        if (by < 0) by = 0;

        draw_box(fb, by, bx, bw, bh, "Sort Column");
        for (int i = 0; i < COL_COUNT; i++) {
            const ColumnMeta *m = netinfo_column_meta((ColumnId)i);
            bool sel = (i == st->modal_cursor);
            bool active = ((ColumnId)i == st->sort_col);
            const char *dir = active ? (st->sort_desc ? "DESC" : "ASC ") : "    ";
            fb_appendf(fb, "\x1b[%d;%dH%s%c %-15s %s\x1b[0m",
                       by + 3 + i, bx + 3,
                       sel ? "\x1b[48;5;24;38;5;255;1m" : "\x1b[48;5;236;38;5;252m",
                       active ? '*' : ' ',
                       m->title,
                       dir);
        }
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;246mEnter:Sort  o:Flip ASC/DESC  Esc:Close\x1b[0m",
                   by + bh - 2, bx + 2);
    } else if (st->modal == MODAL_HELP) {
        int bw = (cols < 64) ? cols - 4 : 62;
        int bh = 16;
        int bx = (cols - bw) / 2;
        int by = (rows - bh) / 2;
        if (bx < 0) bx = 0;
        if (by < 0) by = 0;

        draw_box(fb, by, bx, bw, bh, "taskport Help");
        const char *lines[] = {
            "Up/Down, Wheel, Click : Select row",
            "PgUp/PgDn, Home/End   : Page / Jump",
            "k / Delete            : Kill selected process (confirm)",
            "s / [ / ]             : Sort menu / cycle sort column",
            "o / Click Header      : Toggle ASC/DESC or sort column",
            "c                     : Show/hide columns",
            "/                     : Live filter (Esc clears)",
            "l                     : Toggle Listening-only mode",
            "r / p                 : Refresh now / Pause 2s auto-refresh",
            "q / Ctrl+C            : Quit"
        };
        int nlines = (int)(sizeof(lines) / sizeof(lines[0]));
        for (int i = 0; i < nlines; i++) {
            fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;252m%s\x1b[0m", by + 3 + i, bx + 3, lines[i]);
        }
        fb_appendf(fb, "\x1b[%d;%dH\x1b[48;5;236;38;5;117mPress Esc, ? or Enter to close\x1b[0m",
                   by + bh - 2, bx + 3);
    }
}

static void render_frame(AppState *st) {
    int cols = 80, rows = 24;
    tui_get_size(&cols, &rows);
    if (cols < 20) cols = 20;
    if (rows < 8) rows = 8;

    compute_layout(st, cols);
    st->header_row_y = 2;
    st->data_start_y = 3;
    st->data_rows = rows - 5;
    if (st->data_rows < 1) st->data_rows = 1;
    ensure_visible_selection(st);

    FrameBuf fb;
    fb_init(&fb);

    /* Top bar (row 1) */
    const ColumnMeta *sort_meta = netinfo_column_meta(st->sort_col);
    char top_left[256];
    snprintf(top_left, sizeof(top_left),
             " taskport | Rows: %zu/%zu | Sort: %s %s | %s%s",
             st->filtered_count,
             st->all.count,
             sort_meta ? sort_meta->title : "?",
             st->sort_desc ? "DESC" : "ASC",
             st->listen_only ? "[LISTEN ONLY]" : "[ALL STATES]",
             st->paused ? " [PAUSED]" : "");

    char top_fit[512];
    fit_cell_text(top_left, cols, false, top_fit, sizeof(top_fit));
    fb_appendf(&fb, "\x1b[1;1H\x1b[48;5;24;38;5;255;1m%s\x1b[0m", top_fit);

    /* Filter / info bar (row 2) */
    char filter_line[512];
    if (st->filter_editing) {
        snprintf(filter_line, sizeof(filter_line), " Filter: %s_  (Enter: keep, Esc: clear)", st->filter_text);
    } else if (st->filter_text[0] != '\0') {
        snprintf(filter_line, sizeof(filter_line), " Filter: \"%s\"  (/: edit, Esc: clear)", st->filter_text);
    } else {
        snprintf(filter_line, sizeof(filter_line), " Press / to filter | Click column header to sort | ? for help");
    }
    char filter_fit[512];
    fit_cell_text(filter_line, cols, false, filter_fit, sizeof(filter_fit));
    fb_appendf(&fb, "\x1b[2;1H\x1b[48;5;235;38;5;%dm%s\x1b[0m",
               st->filter_editing ? 221 : 249, filter_fit);

    /* Header row (row 3) */
    fb_append(&fb, "\x1b[3;1H\x1b[48;5;237;38;5;159;1m ");
    int cur_x = 1;
    for (int i = 0; i < st->layout_count; i++) {
        const ColumnMeta *m = netinfo_column_meta(st->layout[i].id);
        int w = st->layout[i].width;
        char hdr[64];
        if (st->layout[i].id == st->sort_col) {
            snprintf(hdr, sizeof(hdr), "%s %s", m->title, st->sort_desc ? "v" : "^");
        } else {
            snprintf(hdr, sizeof(hdr), "%s", m->title);
        }
        char cell[256];
        fit_cell_text(hdr, w, m->right_align, cell, sizeof(cell));
        fb_append(&fb, cell);
        cur_x += w;
        if (i + 1 < st->layout_count && cur_x < cols) {
            fb_append(&fb, " ");
            cur_x++;
        }
    }
    while (cur_x < cols) {
        fb_append(&fb, " ");
        cur_x++;
    }
    fb_append(&fb, "\x1b[0m");

    /* Data rows */
    for (int r = 0; r < st->data_rows; r++) {
        int y = st->data_start_y + r + 1;
        int idx = st->scroll_offset + r;
        fb_appendf(&fb, "\x1b[%d;1H", y);

        if (idx >= (int)st->filtered_count) {
            fb_append(&fb, "\x1b[2K");
            continue;
        }

        const PortEntry *e = &st->all.items[st->filtered[idx]];
        bool is_sel = (idx == st->selected);

        if (is_sel) {
            fb_append(&fb, "\x1b[48;5;25;38;5;255;1m ");
        } else {
            int fg = 252;
            if (strcmp(e->state, "LISTEN") == 0) fg = 114;
            else if (strcmp(e->state, "ESTAB") == 0) fg = 117;
            else if (strcmp(e->state, "TIME_WAIT") == 0 || strcmp(e->state, "CLOSE_WAIT") == 0) fg = 221;
            else if (strncmp(e->proto, "UDP", 3) == 0) fg = 183;
            fb_appendf(&fb, "\x1b[49;38;5;%dm ", fg);
        }

        int cx = 1;
        for (int c = 0; c < st->layout_count; c++) {
            ColumnId cid = st->layout[c].id;
            const ColumnMeta *m = netinfo_column_meta(cid);
            int w = st->layout[c].width;
            char raw[512];
            char cell[512];
            format_cell(e, cid, raw, sizeof(raw));
            fit_cell_text(raw, w, m->right_align, cell, sizeof(cell));
            fb_append(&fb, cell);
            cx += w;
            if (c + 1 < st->layout_count && cx < cols) {
                fb_append(&fb, " ");
                cx++;
            }
        }
        while (cx < cols) {
            fb_append(&fb, " ");
            cx++;
        }
        fb_append(&fb, "\x1b[0m");
    }

    /* Status line (rows - 1) */
    ULONGLONG now = GetTickCount64();
    char st_fit[512];
    if (st->status_msg[0] != '\0' && now <= st->status_until) {
        fit_cell_text(st->status_msg, cols, false, st_fit, sizeof(st_fit));
        int bg = (st->status_level == 2) ? 52 : (st->status_level == 1 ? 22 : 236);
        int fg = (st->status_level == 2) ? 217 : (st->status_level == 1 ? 156 : 252);
        fb_appendf(&fb, "\x1b[%d;1H\x1b[48;5;%d;38;5;%dm%s\x1b[0m", rows - 1, bg, fg, st_fit);
    } else {
        char nav[128];
        if (st->filtered_count > 0) {
            const PortEntry *sel = &st->all.items[st->filtered[st->selected]];
            snprintf(nav, sizeof(nav), " Selected: %s (PID %u) %s:%u  [%d/%zu]",
                     sel->process_name, sel->pid, sel->local_addr, sel->local_port,
                     st->selected + 1, st->filtered_count);
        } else {
            snprintf(nav, sizeof(nav), " No matching ports/processes");
        }
        fit_cell_text(nav, cols, false, st_fit, sizeof(st_fit));
        fb_appendf(&fb, "\x1b[%d;1H\x1b[48;5;235;38;5;248m%s\x1b[0m", rows - 1, st_fit);
    }

    /* Bottom keybindings bar (rows) */
    const char *keys = " k:Kill  s:Sort  o:Order  c:Cols  /:Filter  l:Listen  r:Refresh  p:Pause  ?:Help  q:Quit";
    char keys_fit[512];
    fit_cell_text(keys, cols, false, keys_fit, sizeof(keys_fit));
    fb_appendf(&fb, "\x1b[%d;1H\x1b[48;5;237;38;5;252m%s\x1b[0m", rows, keys_fit);

    render_modals(&fb, st, cols, rows);

    fb_flush(&fb);
    fb_free(&fb);
}

static void open_kill_modal(AppState *st) {
    if (st->filtered_count == 0) {
        set_status(st, 0, "No process selected");
        return;
    }
    const PortEntry *sel = &st->all.items[st->filtered[st->selected]];
    if (sel->pid == 0 || sel->pid == 4) {
        set_status(st, 2, "Refusing to kill protected Windows system process (PID 0/4)");
        return;
    }
    st->kill_target = *sel;
    int cnt = 0;
    for (size_t i = 0; i < st->all.count; i++) {
        if (st->all.items[i].pid == sel->pid) cnt++;
    }
    st->kill_target_port_count = cnt;
    st->modal = MODAL_KILL;
}

static void cycle_sort_column(AppState *st, int dir) {
    int cur = -1;
    for (int i = 0; i < st->layout_count; i++) {
        if (st->layout[i].id == st->sort_col) {
            cur = i;
            break;
        }
    }
    if (st->layout_count == 0) return;
    if (cur < 0) cur = 0;
    else cur = (cur + dir + st->layout_count) % st->layout_count;
    st->sort_col = st->layout[cur].id;
    netinfo_sort(&st->all, st->sort_col, st->sort_desc);
    rebuild_filtered(st);
}

static int count_visible_columns(const AppState *st) {
    int c = 0;
    for (int i = 0; i < COL_COUNT; i++) {
        if (st->col_visible[i]) c++;
    }
    return c;
}

static bool handle_event(AppState *st, const TuiEvent *ev) {
    if (ev->type == EV_QUIT) return false;
    if (ev->type == EV_RESIZE) return true;

    if (st->modal == MODAL_KILL) {
        if (ev->type == EV_KEY) {
            if (ev->key == KEY_ESC || (ev->key == KEY_CHAR && (ev->ch == 'n' || ev->ch == 'N'))) {
                st->modal = MODAL_NONE;
                set_status(st, 0, "Kill cancelled");
            } else if (ev->key == KEY_ENTER || (ev->key == KEY_CHAR && (ev->ch == 'y' || ev->ch == 'Y'))) {
                char err[256] = {0};
                if (netinfo_kill_process(st->kill_target.pid, err, sizeof(err))) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Terminated %s (PID %u)", st->kill_target.process_name, st->kill_target.pid);
                    st->modal = MODAL_NONE;
                    set_status(st, 1, msg);
                    Sleep(150);
                    refresh_data(st);
                } else {
                    st->modal = MODAL_NONE;
                    set_status(st, 2, err[0] ? err : "Failed to terminate process");
                }
            }
        }
        return true;
    }

    if (st->modal == MODAL_COLUMNS) {
        if (ev->type == EV_KEY) {
            if (ev->key == KEY_ESC || (ev->key == KEY_CHAR && (ev->ch == 'c' || ev->ch == 'C'))) {
                st->modal = MODAL_NONE;
            } else if (ev->key == KEY_UP) {
                st->modal_cursor = (st->modal_cursor - 1 + COL_COUNT) % COL_COUNT;
            } else if (ev->key == KEY_DOWN) {
                st->modal_cursor = (st->modal_cursor + 1) % COL_COUNT;
            } else if (ev->key == KEY_ENTER || (ev->key == KEY_CHAR && ev->ch == ' ')) {
                if (st->col_visible[st->modal_cursor] && count_visible_columns(st) <= 1) {
                    set_status(st, 2, "At least one column must remain visible");
                } else {
                    st->col_visible[st->modal_cursor] = !st->col_visible[st->modal_cursor];
                }
            } else if (ev->key == KEY_CHAR && (ev->ch == 'a' || ev->ch == 'A')) {
                for (int i = 0; i < COL_COUNT; i++) st->col_visible[i] = true;
            } else if (ev->key == KEY_CHAR && (ev->ch == 'd' || ev->ch == 'D')) {
                for (int i = 0; i < COL_COUNT; i++) {
                    const ColumnMeta *m = netinfo_column_meta((ColumnId)i);
                    st->col_visible[i] = m ? m->default_visible : true;
                }
            }
        }
        return true;
    }

    if (st->modal == MODAL_SORT) {
        if (ev->type == EV_KEY) {
            if (ev->key == KEY_ESC || (ev->key == KEY_CHAR && (ev->ch == 's' || ev->ch == 'S'))) {
                st->modal = MODAL_NONE;
            } else if (ev->key == KEY_UP) {
                st->modal_cursor = (st->modal_cursor - 1 + COL_COUNT) % COL_COUNT;
            } else if (ev->key == KEY_DOWN) {
                st->modal_cursor = (st->modal_cursor + 1) % COL_COUNT;
            } else if (ev->key == KEY_CHAR && (ev->ch == 'o' || ev->ch == 'O' || ev->ch == ' ')) {
                st->sort_desc = !st->sort_desc;
                netinfo_sort(&st->all, st->sort_col, st->sort_desc);
                rebuild_filtered(st);
            } else if (ev->key == KEY_ENTER) {
                if ((ColumnId)st->modal_cursor == st->sort_col) {
                    st->sort_desc = !st->sort_desc;
                } else {
                    st->sort_col = (ColumnId)st->modal_cursor;
                    st->sort_desc = false;
                }
                netinfo_sort(&st->all, st->sort_col, st->sort_desc);
                rebuild_filtered(st);
                st->modal = MODAL_NONE;
            }
        }
        return true;
    }

    if (st->modal == MODAL_HELP) {
        if (ev->type == EV_KEY) {
            if (ev->key == KEY_ESC || ev->key == KEY_ENTER ||
                (ev->key == KEY_CHAR && (ev->ch == '?' || ev->ch == 'h' || ev->ch == 'q'))) {
                st->modal = MODAL_NONE;
            }
        }
        return true;
    }

    /* Filter editing mode */
    if (st->filter_editing) {
        if (ev->type == EV_KEY) {
            if (ev->key == KEY_ENTER) {
                st->filter_editing = false;
            } else if (ev->key == KEY_ESC) {
                st->filter_text[0] = '\0';
                st->filter_editing = false;
                rebuild_filtered(st);
            } else if (ev->key == KEY_BACKSPACE) {
                size_t len = strlen(st->filter_text);
                if (len > 0) {
                    st->filter_text[len - 1] = '\0';
                    rebuild_filtered(st);
                }
            } else if (ev->key == KEY_CHAR) {
                size_t len = strlen(st->filter_text);
                if (len + 1 < sizeof(st->filter_text)) {
                    st->filter_text[len] = ev->ch;
                    st->filter_text[len + 1] = '\0';
                    rebuild_filtered(st);
                }
            }
            return true;
        }
    }

    /* Normal mode */
    if (ev->type == EV_MOUSE_WHEEL) {
        if (st->filtered_count > 0) {
            st->selected -= ev->wheel_delta * 3;
            if (st->selected < 0) st->selected = 0;
            if (st->selected >= (int)st->filtered_count) st->selected = (int)st->filtered_count - 1;
        }
        return true;
    }

    if (ev->type == EV_MOUSE_CLICK) {
        if (ev->mouse_y == st->header_row_y) {
            for (int i = 0; i < st->layout_count; i++) {
                if (ev->mouse_x >= st->layout[i].x_start &&
                    ev->mouse_x < st->layout[i].x_start + st->layout[i].width) {
                    if (st->sort_col == st->layout[i].id) {
                        st->sort_desc = !st->sort_desc;
                    } else {
                        st->sort_col = st->layout[i].id;
                        st->sort_desc = false;
                    }
                    netinfo_sort(&st->all, st->sort_col, st->sort_desc);
                    rebuild_filtered(st);
                    break;
                }
            }
        } else if (ev->mouse_y >= st->data_start_y && ev->mouse_y < st->data_start_y + st->data_rows) {
            int clicked = st->scroll_offset + (ev->mouse_y - st->data_start_y);
            if (clicked >= 0 && clicked < (int)st->filtered_count) {
                st->selected = clicked;
            }
        }
        return true;
    }

    if (ev->type == EV_KEY) {
        switch (ev->key) {
            case KEY_UP:
                if (st->selected > 0) st->selected--;
                break;
            case KEY_DOWN:
                if (st->selected + 1 < (int)st->filtered_count) st->selected++;
                break;
            case KEY_PGUP:
                st->selected -= st->data_rows;
                if (st->selected < 0) st->selected = 0;
                break;
            case KEY_PGDN:
                if (st->filtered_count > 0) {
                    st->selected += st->data_rows;
                    if (st->selected >= (int)st->filtered_count) st->selected = (int)st->filtered_count - 1;
                }
                break;
            case KEY_HOME:
                st->selected = 0;
                break;
            case KEY_END:
                if (st->filtered_count > 0) st->selected = (int)st->filtered_count - 1;
                break;
            case KEY_DELETE:
                open_kill_modal(st);
                break;
            case KEY_ESC:
                if (st->filter_text[0] != '\0') {
                    st->filter_text[0] = '\0';
                    rebuild_filtered(st);
                }
                break;
            case KEY_CHAR:
                switch (ev->ch) {
                    case 'q':
                    case 'Q':
                        return false;
                    case 'k':
                    case 'K':
                        open_kill_modal(st);
                        break;
                    case 's':
                    case 'S':
                        st->modal_cursor = (int)st->sort_col;
                        st->modal = MODAL_SORT;
                        break;
                    case '[':
                        cycle_sort_column(st, -1);
                        break;
                    case ']':
                        cycle_sort_column(st, 1);
                        break;
                    case 'o':
                    case 'O':
                        st->sort_desc = !st->sort_desc;
                        netinfo_sort(&st->all, st->sort_col, st->sort_desc);
                        rebuild_filtered(st);
                        break;
                    case 'c':
                    case 'C':
                        st->modal_cursor = 0;
                        st->modal = MODAL_COLUMNS;
                        break;
                    case '/':
                        st->filter_editing = true;
                        break;
                    case 'l':
                    case 'L':
                        st->listen_only = !st->listen_only;
                        rebuild_filtered(st);
                        break;
                    case 'r':
                    case 'R':
                        refresh_data(st);
                        set_status(st, 0, "Refreshed");
                        break;
                    case 'p':
                    case 'P':
                        st->paused = !st->paused;
                        set_status(st, 0, st->paused ? "Auto-refresh paused" : "Auto-refresh resumed");
                        break;
                    case '?':
                    case 'h':
                    case 'H':
                        st->modal = MODAL_HELP;
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
    return true;
}

int app_run(const AppConfig *cfg) {
    AppState st;
    memset(&st, 0, sizeof(st));
    port_list_init(&st.all);
    st.sort_col = cfg->sort_col;
    st.sort_desc = cfg->sort_desc;
    st.listen_only = cfg->listen_only;
    memcpy(st.col_visible, cfg->col_visible, sizeof(st.col_visible));

    if (!tui_init()) {
        fprintf(stderr, "Error: Failed to initialize Windows Console VT100 TUI.\n");
        port_list_free(&st.all);
        return 1;
    }

    refresh_data(&st);
    render_frame(&st);

    bool running = true;
    while (running && !tui_should_quit()) {
        TuiEvent ev;
        if (tui_poll_event(&ev, 200)) {
            running = handle_event(&st, &ev);
            if (!running) break;
            render_frame(&st);
        } else {
            ULONGLONG now = GetTickCount64();
            if (!st.paused && st.modal == MODAL_NONE && now - st.last_refresh_ms >= 2000ULL) {
                refresh_data(&st);
                render_frame(&st);
            }
        }
    }

    tui_shutdown();
    free(st.filtered);
    port_list_free(&st.all);
    return 0;
}

int app_dump(const AppConfig *cfg) {
    PortList list;
    port_list_init(&list);

    char err[256] = {0};
    if (!netinfo_collect(&list, err, sizeof(err))) {
        fprintf(stderr, "Error: %s\n", err[0] ? err : "failed to collect network info");
        port_list_free(&list);
        return 1;
    }

    netinfo_sort(&list, cfg->sort_col, cfg->sort_desc);

    ColumnId cols[COL_COUNT];
    int col_count = 0;
    for (int i = 0; i < COL_COUNT; i++) {
        if (cfg->col_visible[i]) {
            cols[col_count++] = (ColumnId)i;
        }
    }

    /* Header */
    for (int c = 0; c < col_count; c++) {
        const ColumnMeta *m = netinfo_column_meta(cols[c]);
        char cell[256];
        fit_cell_text(m->title, m->width, m->right_align, cell, sizeof(cell));
        printf("%s%s", cell, (c + 1 < col_count) ? " " : "\n");
    }

    /* Separator */
    for (int c = 0; c < col_count; c++) {
        const ColumnMeta *m = netinfo_column_meta(cols[c]);
        for (int k = 0; k < m->width; k++) putchar('-');
        putchar((c + 1 < col_count) ? ' ' : '\n');
    }

    size_t shown = 0;
    for (size_t i = 0; i < list.count; i++) {
        const PortEntry *e = &list.items[i];
        if (cfg->listen_only && !e->is_listening) continue;
        shown++;
        for (int c = 0; c < col_count; c++) {
            const ColumnMeta *m = netinfo_column_meta(cols[c]);
            char raw[512];
            char cell[512];
            format_cell(e, cols[c], raw, sizeof(raw));
            if (cols[c] == COL_PATH && c == col_count - 1) {
                printf("%s\n", raw);
            } else {
                fit_cell_text(raw, m->width, m->right_align, cell, sizeof(cell));
                printf("%s%s", cell, (c + 1 < col_count) ? " " : "\n");
            }
        }
    }

    printf("\nTotal: %zu row(s) shown (%zu collected)\n", shown, list.count);
    port_list_free(&list);
    return 0;
}
