#include <stdio.h>
#include "3p/xhttp.h"
#include "3p/xh_utils.h"
#include "3p/sqlite3.h"
#include "util/buffer.h"

#define PASSW_MIN 6
#define PASSW_MAX 64

#define USERN_MIN 3
#define USERN_MAX 32

#define GNAME_MAX 64
#define GINTR_MAX 128
#define PTITL_MAX 512

typedef struct {
    char usern[USERN_MAX+1];
    int sess_id;
} session_t;

typedef struct {
    session_t   *sess;
    int      sess_num, 
             sess_max;
    int  next_sess_id;
    sqlite3 *database;
    buffer_t   buffer;
} isolate_t;

const char *session_find  (isolate_t *isol, int sess_id);
int         session_create(isolate_t *isol, const char *usern);
_Bool       session_delete(isolate_t *isol, const char *usern);

_Bool account_create(isolate_t *isol, const char *usern, const char *passw);
int   account_exists(isolate_t *isol, const char *usern, const char *passw);

void route_api_login (isolate_t *isol, xh_request *req, xh_response *res, const char *usern);
void route_api_logout(isolate_t *isol, xh_request *req, xh_response *res, const char *usern);
void route_api_signup(isolate_t *isol, xh_request *req, xh_response *res, const char *usern);
void route_login     (isolate_t *isol, xh_request *req, xh_response *res, const char *usern);
void route_signup    (isolate_t *isol, xh_request *req, xh_response *res, const char *usern);
void route_all       (isolate_t *isol, xh_request *req, xh_response *res, const char *usern);

#ifdef DEBUG
#define debugf(fmt, ...) fprintf(stderr, "DEBUG: " fmt, ## __VA_ARGS__ )
#else
#define debugf(...) ((void) 0)
#endif

#define STR(s) XSTR(s)
#define XSTR(s) #s
