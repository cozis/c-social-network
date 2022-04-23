#include <string.h>
#include "main.h"

void route_api_login(isolate_t *isol, xh_request *req, xh_response *res, const char *usern)
{
    if(usern != NULL)
    {
        /* Already logged in. */
        res->status = 400;
        res->body = "You're already logged in.";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");
        return;
    }
    
    /* Parse x-www-form-urlencoded body */
    
    const char *erro;
    _Bool       inte;

    xh_params *params = xh_params_decode(req->body, req->body_len, &erro, &inte);

    if(params == NULL)
    {
        debugf("Failed to parse parameters (%s, internal=%d)\n", erro, inte);
        
        res->status = inte ? 500 : 400;
        res->body = "Failed to parse body";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    debugf("Parameters [%s] parsed\n", req->body);

    /* Get [usern] and [passw] parameters */

    int usern_len, passw_len;
    const char *param_usern = xh_params_get(params, "usern", &usern_len);
    const char *param_passw = xh_params_get(params, "passw", &passw_len);

    if(param_usern == NULL || usern_len == 0 ||
        param_passw == NULL || passw_len == 0)
    {
        res->status = 400;
        res->body = "Parameter missing or empty";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    int rc = account_exists(isol, param_usern, NULL);

    if(rc == 0)
    {
        /* Account doesn't exist. */
        res->status = 400;
        res->body = "No such profile";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");
        xh_params_free(params);
        return;
    }
    
    if(rc != 1)
    {
        /* Internal error. */
        res->status = 500;
        xh_params_free(params);

        debugf("Failed to check weather an account exists\n");
        return;
    }

    int sess_id = session_create(isol, param_usern);

    xh_params_free(params);

    if(sess_id < 0)
    {
        /* Failed to create session. */
        res->status = 500;
        res->body = "Failed to create session";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");
        return;
    }

    res->status = 303;
    xh_header_add(res, "Set-Cookie", "sess_id=%d; HttpOnly; SameSite=Lax; Path=/", sess_id);
    xh_header_add(res, "Location", "/all");
    return;
}