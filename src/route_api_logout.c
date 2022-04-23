#include <string.h>
#include "main.h"

void route_api_logout(isolate_t *isol, xh_request *req, xh_response *res, const char *usern)
{
    (void) req;
    
    if(usern == NULL)
    {
        /* Not logged in. */
        res->status = 400;
        res->body = "You're not logged in";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");
        return;
    }

    if(session_delete(isol, usern))
    {
        res->status = 303;
        xh_header_add(res, "Location", "/login");
    }
    else
        res->status = 500;
}