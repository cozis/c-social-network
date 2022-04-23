#include <string.h>
#include "main.h"

void route_signup(isolate_t *isol, xh_request *req, xh_response *res, const char *usern)
{
    (void) isol;
    (void) req;
    
    if(usern != NULL)
    {
        /* Already logged in. */
        res->status = 303;
        xh_header_add(res, "Location", "/all");
        return;
    }

    static const char body[] =
    "<html>\n"
    "    <head>\n"
    "        <title>Signup</title>\n"
    "    </head>\n"
    "    <body>\n"
    "        <form action=\"/api/signup\" method=\"POST\">\n"
    "            <input type=\"text\" name=\"usern\" placeholder=\"[Username]\" />\n"
    "            <input type=\"password\" name=\"passw\"  placeholder=\"[Password]\" />\n"
    "            <input type=\"password\" name=\"passw2\" placeholder=\"[Confirm password]\" />\n"
    "            <input type=\"submit\" value=\"Sign-Up\" />\n"
    "        </form>\n"
    "    </body>\n"
    "</html>\n";
    res->status = 200;
    res->body = body;
    res->body_len = sizeof(body);
    xh_header_add(res, "Content-Type", "text/html");
}