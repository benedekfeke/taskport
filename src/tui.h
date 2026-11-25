#ifndef TUI_H
#define TUI_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} FrameBuf;

typedef enum {
    EV_NONE = 0,
    EV_KEY,
    EV_MOUSE_CLICK,
    EV_MOUSE_WHEEL,
    EV_RESIZE,
    EV_QUIT
} EventType;

typedef enum {
    KEY_NONE = 0,
    KEY_CHAR,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_PGUP,
    KEY_PGDN,
    KEY_HOME,
    KEY_END,
    KEY_ENTER,
    KEY_ESC,
    KEY_BACKSPACE,
    KEY_DELETE,
    KEY_TAB
} KeyCode;

typedef struct {
    EventType type;
    KeyCode key;
    char ch;        /* ASCII char for KEY_CHAR (or UTF-8 single byte) */
    bool ctrl;
    int mouse_x;    /* 0-based column in viewport */
    int mouse_y;    /* 0-based row in viewport */
    int wheel_delta;/* +1 for up, -1 for down */
} TuiEvent;

void fb_init(FrameBuf *fb);
void fb_free(FrameBuf *fb);
void fb_clear(FrameBuf *fb);
void fb_append(FrameBuf *fb, const char *s);
void fb_append_n(FrameBuf *fb, const char *s, size_t n);
void fb_appendf(FrameBuf *fb, const char *fmt, ...);
void fb_flush(const FrameBuf *fb);

bool tui_init(void);
void tui_shutdown(void);
void tui_get_size(int *cols, int *rows);
bool tui_poll_event(TuiEvent *ev, DWORD timeout_ms);
bool tui_should_quit(void);

#endif /* TUI_H */
