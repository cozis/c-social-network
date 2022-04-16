#include "xhttp.h"

typedef struct {
    char *name, *value;
    int name_len, value_len;
} xh_param;

typedef struct {
    int count, ignored;
    xh_param list[];
} xh_params;

typedef struct {
    char *name, *value;
    unsigned int name_len;
    unsigned int value_len;
} xh_cookie;

typedef struct {
    int count, ignored;
    xh_cookie list[];
} xh_cookies;

xh_cookies *xh_cookie_parse(xh_request *req, const char **erro, _Bool *inte);
void        xh_cookie_free(xh_cookies *cook);
xh_params  *xh_params_decode(const char *str, int len, const char **err, _Bool *inte);
void        xh_params_free(xh_params *params);
const char *xh_params_get(xh_params *params, const char *name, int *len);