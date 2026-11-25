#include "tui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE g_hIn = INVALID_HANDLE_VALUE;
static HANDLE g_hOut = INVALID_HANDLE_VALUE;
static DWORD g_orig_in_mode = 0;
static DWORD g_orig_out_mode = 0;
static UINT g_orig_in_cp = 0;
static UINT g_orig_out_cp = 0;
static bool g_tui_active = false;
static volatile sig_atomic_t g_quit_flag = 0;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            g_quit_flag = 1;
            return TRUE;
        default:
            return FALSE;
    }
}

void fb_init(FrameBuf *fb) {
    fb->cap = 32768;
    fb->data = (char *)malloc(fb->cap);
    fb->len = 0;
    if (fb->data) fb->data[0] = '\0';
}

void fb_free(FrameBuf *fb) {
    free(fb->data);
    fb->data = NULL;
    fb->len = 0;
    fb->cap = 0;
}

void fb_clear(FrameBuf *fb) {
    fb->len = 0;
    if (fb->data) fb->data[0] = '\0';
}

static void fb_ensure(FrameBuf *fb, size_t extra) {
    if (fb->len + extra + 1 <= fb->cap) return;
    size_t new_cap = fb->cap ? fb->cap : 4096;
    while (new_cap < fb->len + extra + 1) {
        new_cap *= 2;
    }
    char *new_data = (char *)realloc(fb->data, new_cap);
    if (!new_data) return;
    fb->data = new_data;
    fb->cap = new_cap;
}

void fb_append_n(FrameBuf *fb, const char *s, size_t n) {
    if (!s || n == 0) return;
    fb_ensure(fb, n);
    if (!fb->data || fb->len + n + 1 > fb->cap) return;
    memcpy(fb->data + fb->len, s, n);
    fb->len += n;
    fb->data[fb->len] = '\0';
}

void fb_append(FrameBuf *fb, const char *s) {
    if (!s) return;
    fb_append_n(fb, s, strlen(s));
}

void fb_appendf(FrameBuf *fb, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if ((size_t)n < sizeof(tmp)) {
        fb_append_n(fb, tmp, (size_t)n);
    } else {
        char *dyn = (char *)malloc((size_t)n + 1);
        if (!dyn) return;
        va_start(ap, fmt);
        vsnprintf(dyn, (size_t)n + 1, fmt, ap);
        va_end(ap);
        fb_append_n(fb, dyn, (size_t)n);
        free(dyn);
    }
}

void fb_flush(const FrameBuf *fb) {
    if (!fb || !fb->data || fb->len == 0) return;
    HANDLE out = (g_hOut != INVALID_HANDLE_VALUE) ? g_hOut : GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(out, fb->data, (DWORD)fb->len, &written, NULL);
}

bool tui_init(void) {
    g_hIn = GetStdHandle(STD_INPUT_HANDLE);
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hIn == INVALID_HANDLE_VALUE || g_hOut == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (!GetConsoleMode(g_hIn, &g_orig_in_mode) ||
        !GetConsoleMode(g_hOut, &g_orig_out_mode)) {
        return false;
    }

    g_orig_in_cp = GetConsoleCP();
    g_orig_out_cp = GetConsoleOutputCP();

    DWORD out_mode = g_orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    if (!SetConsoleMode(g_hOut, out_mode)) {
        /* Fallback without DISABLE_NEWLINE_AUTO_RETURN */
        out_mode = g_orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (!SetConsoleMode(g_hOut, out_mode)) {
            return false;
        }
    }

    DWORD in_mode = g_orig_in_mode;
    in_mode |= ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS;
    in_mode &= ~(ENABLE_QUICK_EDIT_MODE | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
    SetConsoleMode(g_hIn, in_mode);

    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    g_quit_flag = 0;
    g_tui_active = true;

    const char *init_seq = "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H";
    DWORD written = 0;
    WriteFile(g_hOut, init_seq, (DWORD)strlen(init_seq), &written, NULL);
    return true;
}

void tui_shutdown(void) {
    if (!g_tui_active) return;
    g_tui_active = false;

    const char *exit_seq = "\x1b[0m\x1b[?25h\x1b[?1049l";
    DWORD written = 0;
    WriteFile(g_hOut, exit_seq, (DWORD)strlen(exit_seq), &written, NULL);

    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    SetConsoleMode(g_hIn, g_orig_in_mode);
    SetConsoleMode(g_hOut, g_orig_out_mode);
    if (g_orig_in_cp) SetConsoleCP(g_orig_in_cp);
    if (g_orig_out_cp) SetConsoleOutputCP(g_orig_out_cp);
}

void tui_get_size(int *cols, int *rows) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hOut, &csbi)) {
        int c = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        int r = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        if (cols) *cols = (c > 0) ? c : 80;
        if (rows) *rows = (r > 0) ? r : 24;
    } else {
        if (cols) *cols = 80;
        if (rows) *rows = 24;
    }
}

bool tui_should_quit(void) {
    return g_quit_flag != 0;
}

bool tui_poll_event(TuiEvent *ev, DWORD timeout_ms) {
    memset(ev, 0, sizeof(*ev));
    ev->type = EV_NONE;

    if (g_quit_flag) {
        ev->type = EV_QUIT;
        return true;
    }

    DWORD wait_res = WaitForSingleObject(g_hIn, timeout_ms);
    if (g_quit_flag) {
        ev->type = EV_QUIT;
        return true;
    }
    if (wait_res != WAIT_OBJECT_0) {
        return false;
    }

    INPUT_RECORD rec;
    DWORD read_cnt = 0;
    if (!ReadConsoleInputW(g_hIn, &rec, 1, &read_cnt) || read_cnt == 0) {
        return false;
    }

    if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT) {
        ev->type = EV_RESIZE;
        return true;
    }

    if (rec.EventType == MOUSE_EVENT) {
        const MOUSE_EVENT_RECORD *m = &rec.Event.MouseEvent;
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        int win_left = 0, win_top = 0;
        if (GetConsoleScreenBufferInfo(g_hOut, &csbi)) {
            win_left = csbi.srWindow.Left;
            win_top = csbi.srWindow.Top;
        }
        int vx = m->dwMousePosition.X - win_left;
        int vy = m->dwMousePosition.Y - win_top;

        if (m->dwEventFlags == MOUSE_WHEELED) {
            short delta = (short)HIWORD(m->dwButtonState);
            ev->type = EV_MOUSE_WHEEL;
            ev->wheel_delta = (delta > 0) ? 1 : -1;
            ev->mouse_x = vx;
            ev->mouse_y = vy;
            return true;
        }

        if (m->dwEventFlags == 0 && (m->dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED)) {
            ev->type = EV_MOUSE_CLICK;
            ev->mouse_x = vx;
            ev->mouse_y = vy;
            return true;
        }
        return false;
    }

    if (rec.EventType == KEY_EVENT) {
        const KEY_EVENT_RECORD *k = &rec.Event.KeyEvent;
        if (!k->bKeyDown) return false;

        bool ctrl = (k->dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
        ev->ctrl = ctrl;

        if (ctrl && (k->wVirtualKeyCode == 'C' || k->uChar.AsciiChar == 3)) {
            ev->type = EV_QUIT;
            return true;
        }

        ev->type = EV_KEY;
        switch (k->wVirtualKeyCode) {
            case VK_UP:     ev->key = KEY_UP; return true;
            case VK_DOWN:   ev->key = KEY_DOWN; return true;
            case VK_LEFT:   ev->key = KEY_LEFT; return true;
            case VK_RIGHT:  ev->key = KEY_RIGHT; return true;
            case VK_PRIOR:  ev->key = KEY_PGUP; return true;
            case VK_NEXT:   ev->key = KEY_PGDN; return true;
            case VK_HOME:   ev->key = KEY_HOME; return true;
            case VK_END:    ev->key = KEY_END; return true;
            case VK_RETURN: ev->key = KEY_ENTER; return true;
            case VK_ESCAPE: ev->key = KEY_ESC; return true;
            case VK_BACK:   ev->key = KEY_BACKSPACE; return true;
            case VK_DELETE: ev->key = KEY_DELETE; return true;
            case VK_TAB:    ev->key = KEY_TAB; return true;
            default: break;
        }

        WCHAR wch = k->uChar.UnicodeChar;
        if (wch >= 32 && wch < 127) {
            ev->key = KEY_CHAR;
            ev->ch = (char)wch;
            return true;
        }
        return false;
    }

    return false;
}
