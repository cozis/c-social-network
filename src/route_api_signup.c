#include <string.h>
#include "main.h"

void route_api_signup(isolate_t *isol, xh_request *req, xh_response *res, const char *usern)
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
        // Failed to parse parameters.
        res->status = inte ? 500 : 400;
        res->body = "Failed to parse body";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    /* Get [usern], [passw] and [passw2] parameters */

    int usern_len, passw_len, passw2_len;
    const char *param_usern  = xh_params_get(params, "usern",  &usern_len);
    const char *param_passw  = xh_params_get(params, "passw",  &passw_len);
    const char *param_passw2 = xh_params_get(params, "passw2", &passw2_len);

    if(param_usern == NULL || usern_len == 0 ||
        param_passw == NULL || passw_len == 0 ||
        param_passw2 == NULL || passw2_len == 0)
    {
        res->status = 400;
        res->body = "Parameters missing or empty";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    if(usern_len < USERN_MIN || usern_len > USERN_MAX)
    {
        res->status = 400;
        res->body = "Username must be between " STR(USERN_MIN) " and " STR(USERN_MAX) " characters";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    if(passw_len < PASSW_MIN || passw_len > PASSW_MAX)
    {
        res->status = 400;
        res->body = "Password must be between " STR(PASSW_MIN) " and " STR(PASSW_MAX) " characters";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    if(passw_len != passw2_len || strcmp(param_passw, param_passw2))
    {
        res->status = 400;
        res->body = "Password confirmation failed";
        res->body_len = strlen(res->body);
        xh_header_add(res, "Content-Type", "text/plain");

        xh_params_free(params);
        return;
    }

    if(!account_create(isol, param_usern, param_passw))
    {
        if(account_exists(isol, param_usern, NULL) == 1)
        {
            /* Username is already in use. */
            res->status = 400;
            res->body = "Username already in use";
            res->body_len = strlen(res->body);
            xh_header_add(res, "Content-Type", "text/plain");
            return;
        }
        
        res->status = 500;

        xh_params_free(params);
        return;
    }

    int sess_id = session_create(isol, param_usern);

    xh_params_free(params);

    res->status = 303;

    if(sess_id < 0)
        /* Failed to create session. */
        xh_header_add(res, "Location", "/login");
    else
    {
        xh_header_add(res, "Set-Cookie", "sess_id=%d; HttpOnly; SameSite=Lax; Path=/", sess_id);
        xh_header_add(res, "Location", "/all");
    }
}