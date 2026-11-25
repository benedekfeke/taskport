#ifndef APP_H
#define APP_H

#include "netinfo.h"
#include <stdbool.h>

typedef struct {
    ColumnId sort_col;
    bool sort_desc;
    bool col_visible[COL_COUNT];
    bool listen_only;
} AppConfig;

void app_config_default(AppConfig *cfg);
int app_run(const AppConfig *cfg);
int app_dump(const AppConfig *cfg);

#endif /* APP_H */
