# taskport

A zero-dependency pure C (C11) TUI application for Windows Terminal / PowerShell that displays active network ports and owning processes, with interactive sorting, column hiding, live filtering, and process termination.

## Features

- **Full Port & Process Visibility**: Queries TCPv4, TCPv6, UDPv4, and UDPv6 endpoints via `GetExtendedTcpTable` / `GetExtendedUdpTable` and enriches each PID with process name, working-set memory (MB), user account, and full executable path.
- **Interactive TUI**: Flicker-free VT100/ANSI rendering over the Win32 Console API with alternate screen buffer, mouse wheel & click support, and automatic 2-second refresh.
- **Sorting**: Sort ascending or descending by any column (`PROTO`, `PORT`, `PID`, `PROCESS`, `STATE`, `LOCAL ADDR`, `REMOTE ADDR`, `RPORT`, `MEM (MB)`, `USER`, `PATH`) via the sort modal (`s`), `[` / `]`, `o`, or by clicking a column header.
- **Column Hiding**: Toggle any column on/off in the Columns modal (`c`) or via `--hide` on the command line.
- **Process Termination**: Kill the selected process (`k` or `Delete`) with a confirmation dialog showing process name, PID, endpoint, path, and total sockets owned by that PID.
- **Live Filtering & Listen-Only Mode**: Press `/` to filter across all fields in real time, or `l` to toggle listening/bound sockets only.

## Building

Requires MinGW-w64 `gcc` (C11):

```powershell
make
```

Or compile directly:

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Isrc src/main.c src/netinfo.c src/tui.c src/app.c -o taskport.exe -liphlpapi -lws2_32 -lpsapi -ladvapi32
```

## Usage

Run interactively in Windows Terminal / PowerShell:

```powershell
.\taskport.exe
```

CLI options:

```powershell
.\taskport.exe --help
.\taskport.exe --dump
.\taskport.exe --dump --listen --sort port --hide user,path
.\taskport.exe --dump --sort mem --desc
```

## Keybindings

| Key / Input | Action |
|---|---|
| `↑` / `↓`, `PgUp` / `PgDn`, `Home` / `End` | Navigate rows |
| Mouse Wheel / Click Row | Scroll / Select row |
| Click Column Header | Sort by column (click again to flip ASC/DESC) |
| `k` / `Delete` | Kill selected process (with confirmation) |
| `s` | Open Sort column menu |
| `[` / `]` | Cycle sort column left / right |
| `o` | Toggle sort order (`ASC` / `DESC`) |
| `c` | Open Columns visibility menu |
| `/` | Live filter (`Enter` keeps filter, `Esc` clears) |
| `l` | Toggle listening-only mode |
| `r` | Refresh immediately |
| `p` | Pause / resume 2s auto-refresh |
| `?` / `h` | Toggle help modal |
| `q` / `Ctrl+C` | Quit |
