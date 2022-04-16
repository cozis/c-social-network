#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include "xhttp.h"
#include "xh_utils.h"
#include "sqlite3.h"

#define PASSW_MIN 6
#define PASSW_MAX 64

#define USERN_MIN 3
#define USERN_MAX 32

#define STR(s) XSTR(s)
#define XSTR(s) #s

#ifdef DEBUG
#define debugf(fmt, ...) fprintf(stderr, "DEBUG: " fmt, ## __VA_ARGS__ )
#else
#define debugf(...) ((void) 0)
#endif

typedef struct {
    char usern[USERN_MAX+1];
    int sess_id;
} session_t;

typedef struct {
    session_t *sess;
    int    sess_num, 
           sess_max;
    int next_sess_id;
    sqlite3 *database;
} isolate_t;

const char *session_find(isolate_t *isol, int sess_id)
{
    for(int i = 0; i < isol->sess_num; i += 1)
        if(isol->sess[i].sess_id == sess_id)
            return isol->sess[i].usern;
    return NULL;
}

int create_session(isolate_t *isol, const char *usern)
{
    if(isol->sess_num == isol->sess_max)
    {
        int new_max;
        if(isol->sess_max == 0)
            new_max = 16;
        else
            new_max = 1.5 * isol->sess_max;

        session_t *temp = realloc(isol->sess, new_max * sizeof(session_t));

        if(temp == NULL)
            return -1;

        isol->sess = temp;
        isol->sess_max = new_max;
    }

    session_t *sess = isol->sess + isol->sess_num;
    int     sess_id = isol->next_sess_id;

    assert(strlen(usern) <= USERN_MAX);
    assert(sess_id >= 0);

    strcpy(sess->usern, usern);
    sess->sess_id = sess_id;

    isol->sess_num     += 1;
    isol->next_sess_id += 1;
    return sess_id;
}

int account_exists(isolate_t *isol, const char *usern, const char *passw)
{
    const char *query = 
        passw == NULL ?
            "SELECT COUNT(*) FROM Accounts WHERE usern=?" :
            "SELECT COUNT(*) FROM Accounts WHERE usern=? AND passw=?";

    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(isol->database, query, -1, &stmt, NULL);
    if(rc != SQLITE_OK) 
    {
        debugf("Failed to prepare statement\n");
        goto failed;
    }

    rc = sqlite3_bind_text(stmt, 1, usern, -1, NULL);
    if(rc != SQLITE_OK) 
    {
        debugf("Failed to bind first parameter to statement\n");
        goto failed;
    }

    if(passw != NULL)
    {
        rc = sqlite3_bind_text(stmt, 2, passw, -1, NULL);
        if(rc != SQLITE_OK)
        {
            debugf("Failed to bind second parameter statement\n");
            goto failed;
        }
    }

    rc = sqlite3_step(stmt);
    if(rc != SQLITE_ROW) 
    {
        debugf("Failed to run statement\n");
        goto failed;
    }

    const char *fetched = (char*) sqlite3_column_text(stmt, 0);
    assert(fetched != NULL);

    debugf("Number of accounts is [%s]\n", fetched);

    _Bool exists = !!strcmp(fetched, "0");

    debugf("Account [%s] %s\n", usern, exists ? "exists" : "doesn't exist");

    sqlite3_finalize(stmt);
    return exists;

failed:
    if(stmt != NULL)
        sqlite3_finalize(stmt);
    return -1;
}

_Bool create_account(isolate_t *isol, const char *usern, const char *passw)
{
    static const char text[] = "INSERT INTO Accounts(usern, passw) VALUES (?, ?)";

    _Bool created = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(isol->database, text, -1, &stmt, NULL);
    if(rc != SQLITE_OK) goto done;

    rc = sqlite3_bind_text(stmt, 1, usern, -1, NULL);
    if(rc != SQLITE_OK) goto done;

    rc = sqlite3_bind_text(stmt, 2, passw, -1, NULL);
    if(rc != SQLITE_OK) goto done;

    if(sqlite3_step(stmt) != SQLITE_DONE)
        goto done;

    created = 1;

done:
    if(stmt != NULL)
        sqlite3_finalize(stmt);
    return created;
}

static void callback(xh_request *req, xh_response *res, void *userp)
{
    isolate_t *isol = userp;
    
    // Parse cookies to determine the username of
    // the client that requested the resource.
    const char *usern = NULL;
    {
        _Bool       inte;
        const char *erro;

        xh_cookies *cookies = xh_cookie_parse(req, &erro, &inte);

        if(cookies == NULL)
        {
            // Failed to parse cookies!
            // If the cause was an internal error, then
            // we report it to the client with a status
            // 500. If the error wasn't internal (bad
            // cookie syntax) then we just assume the
            // client wasn't logged.

            if(inte)
            {
                // Failed because of an internal error.
                res->status = 500;
                res->body = "Failed to parse cookies";
                res->body_len = strlen(res->body);
                return;
            }
        }
        else
        {
            // Cookies were parsed succesfully. Now get
            // the "sess_id".
            const char *sess_id_as_text = NULL;
            for(int i = 0; i < cookies->count; i += 1)
                if(!strcmp(cookies->list[i].name, "sess_id"))
                    { sess_id_as_text = cookies->list[i].value; break; }
            
            if(sess_id_as_text != NULL)
            {
                // Found the "sess_id" cookie. Now convert
                // it to an integer and query the session
                // store for the username.
                int i = 0;
                uint64_t sess_id = 0;
                do
                {
                    if(i > 9 || !isdigit(sess_id_as_text[i]))
                        // Invalid sess_id. Either it's too
                        // long or it's not a number.
                        // Just assume the client isn't logged.
                        break;
                    sess_id = sess_id * 10 + sess_id_as_text[i] - '0';
                    i += 1;
                }
                while(sess_id_as_text[i] != '\0');

                usern = session_find(isol, sess_id);
            }

            xh_cookie_free(cookies);
        }
    }

    debugf("Logged? %s\n", usern == NULL ? "No" : "Yes");

    if(!strcmp(req->URL, "/api/login"))
    {
        if(req->method_id != XH_POST)
        { 
            res->status = 405; 
            res->body = "Invalid method";
            res->body_len = strlen(res->body);
            return; 
        }

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
        const char *usern = xh_params_get(params, "usern", &usern_len);
        const char *passw = xh_params_get(params, "passw", &passw_len);

        if(usern == NULL || usern_len == 0 ||
            passw == NULL || passw_len == 0)
        {
            res->status = 400;
            res->body = "Parameter missing or empty";
            res->body_len = strlen(res->body);
            xh_header_add(res, "Content-Type", "text/plain");

            xh_params_free(params);
            return;
        }

        int rc = account_exists(isol, usern, NULL);

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

        int sess_id = create_session(isol, usern);

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
        xh_header_add(res, "Location", "/home");
        return;
    }

    if(!strcmp(req->URL, "/api/signup"))
    {
        if(req->method_id != XH_POST)
        { 
            res->status = 405; 
            res->body = "Invalid method";
            res->body_len = strlen(res->body);
            return; 
        }

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

        if(!create_account(isol, param_usern, param_passw))
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

        int sess_id = create_session(isol, param_usern);

        xh_params_free(params);

        res->status = 303;

        if(sess_id < 0)
            /* Failed to create session. */
            xh_header_add(res, "Location", "/login");
        else
        {
            xh_header_add(res, "Set-Cookie", "sess_id=%d; HttpOnly; SameSite=Lax; Path=/", sess_id);
            xh_header_add(res, "Location", "/home");
        }
        return;
    }

    if(!strcmp(req->URL, "/login"))
    {
        if(req->method_id != XH_GET)
        { 
            res->status = 405; 
            res->body = "Invalid method";
            res->body_len = strlen(res->body);
            return; 
        }

        if(usern != NULL)
        {
            /* Already logged in. */
            res->status = 303;
            xh_header_add(res, "Location", "/home");
            return;
        }

        static const char body[] =
        "<html>\n"
        "    <head>\n"
        "        <title>Login</title>\n"
        "    </head>\n"
        "    <body>\n"
        "        <form action=\"/api/login\" method=\"POST\">\n"
        "            <input type=\"text\" name=\"usern\" placeholder=\"[Username]\" />\n"
        "            <input type=\"password\" name=\"passw\" placeholder=\"[Password]\" />\n"
        "            <input type=\"submit\" value=\"Log-In\" />\n"
        "        </form>\n"
        "    </body>\n"
        "</html>\n";
        res->status = 200;
        res->body = body;
        res->body_len = sizeof(body);
        xh_header_add(res, "Content-Type", "text/html");
        return;
    }

    if(!strcmp(req->URL, "/signup"))
    {
        if(req->method_id != XH_GET)
        { 
            res->status = 405; 
            res->body = "Invalid method";
            res->body_len = strlen(res->body);
            return; 
        }

        if(usern != NULL)
        {
            /* Already logged in. */
            res->status = 303;
            xh_header_add(res, "Location", "/home");
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
        return;
    }

    if(!strcmp(req->URL, "/home"))
    {
        if(req->method_id != XH_GET)
        { 
            res->status = 405; 
            res->body = "Invalid method";
            res->body_len = strlen(res->body);
            return; 
        }

        if(usern == NULL)
        {
            /* Not logged in. */
            res->status = 303;
            xh_header_add(res, "Location", "/login");
            return;
        }

        static const char body[] =
        "<html>\n"
        "    <head>\n"
        "        <title>Home</title>\n"
        "    </head>\n"
        "    <body>\n"
        "        <a>Hello!</a>\n"
        "    </body>\n"
        "</html>\n";
        res->status = 200;
        res->body = body;
        res->body_len = sizeof(body);
        xh_header_add(res, "Content-Type", "text/html");
        return;
    }

    res->status = 404;
    res->body = "This resource doesn't exist :/";
    res->body_len = strlen(res->body);
}

static _Thread_local xh_handle handle;

static void handle_sigterm(int signo)
{ 
    (void) signo;
    xh_quit(handle); 
}

void serve(const char *addr, unsigned short port, const char *file)
{
    if(addr == NULL)
        fprintf(stderr, "INFO: Binding to all addresses and port %d\n", port);
    else
        fprintf(stderr, "INFO: Binding to address %s and port %d\n", addr, port);
    
    if(file == NULL)
        fprintf(stderr, "INFO: Using in-memory database\n");
    else
        fprintf(stderr, "INFO: Using database file \"%s\"\n", file);

    signal(SIGTERM, handle_sigterm);
    signal(SIGQUIT, handle_sigterm);
    signal(SIGINT,  handle_sigterm);

    isolate_t isol;
    {
        memset(&isol, 0, sizeof(isolate_t));

        const char *temp = file;
        if(temp == NULL)
            temp = ":memory:";

        int rc = sqlite3_open(temp, &isol.database);
        if(rc != SQLITE_OK)
        {
            fprintf(stderr, "ERROR: Failed to open database\n");
            fprintf(stderr, "EXITING\n");
            return;
        }

        static const char schema[] = 
        "CREATE TABLE IF NOT EXISTS Accounts("
        "    usern VARCHAR(" STR(USERN_MAX) ") PRIMARY KEY,"
        "    passw VARCHAR(" STR(PASSW_MAX) ") NOT NULL"
        ")";

        char *msg;
        rc = sqlite3_exec(isol.database, schema, NULL, NULL, &msg);
        if(rc != SQLITE_OK)
        {
            fprintf(stderr, "ERROR: Failed to set-up database schema (%s)\n", msg);
            fprintf(stderr, "EXITING\n");
            sqlite3_free(msg);
            sqlite3_close(isol.database);
            return;
        }
    }

    const char *err = xhttp(addr, port, callback, 
                            &isol, &handle, NULL);

    {
        free(isol.sess);
        sqlite3_close(isol.database);
    }

    fprintf(stderr, "\r");
    if(err != NULL)
        fprintf(stderr, "ERROR: %s\n", err);
    fprintf(stderr, "EXITING\n");
}

static void usage(FILE *fp, const char *exec)
{
    fprintf(fp, "Usage: %s [ --file <database-file-path> ] [ --port <n> ] [ --addr x.x.x.x ]\n", exec);
}

struct args_t {
    const char *addr, *file;
    unsigned short port;
};

static struct args_t parse_args_or_exit(int argc, char **argv)
{
    const char *addr = NULL;
    const char *file = NULL;
    const char *port_as_text = NULL;

    for(int i = 1; i < argc; i += 1)
    {
        if(!strcmp(argv[i], "--addr"))
        {
            i += 1;
            if(i == argc)
            {
                fprintf(stderr, "ERROR: argument --addr expects "
                                "an IPv4 address after it\n");
                usage(stderr, argv[0]);
                exit(1);
            }
            addr = argv[i];
        }
        else if(!strcmp(argv[i], "--port"))
        {
            i += 1;
            if(i == argc)
            {
                fprintf(stderr, "ERROR: argument --port expects an "
                                "integer between 0 and 65535 after it\n");
                usage(stderr, argv[0]);
                exit(1);
            }
            port_as_text = argv[i];
        }
        else if(!strcmp(argv[i], "--file"))
        {
            i += 1;
            if(i == argc)
            {
                fprintf(stderr, "ERROR: argument --file expects a "
                                "file path after it\n");
                usage(stderr, argv[0]);
                exit(1);
            }
            file = argv[i];
        }
        else if(!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
        {
            usage(stdout, argv[0]);
            exit(0);
        }
        else
        {
            fprintf(stderr, "ERROR: invalid argument %s\n", argv[i]);
            usage(stderr, argv[0]);
            exit(1);
        }
    }

    unsigned short port;
    if(port_as_text == NULL)
    {
        port = 8080;
    }
    else
    {
        errno = 0;
        long long int temp = strtoll(port_as_text, NULL, 10);
        if(errno != 0 || temp < 0 || temp > 65535)
        {
            fprintf(stderr, "ERROR: invalid port\n");
            usage(stderr, argv[0]);
            exit(1);
        }
        port = temp;
    }
    return (struct args_t) { .file = file, .addr = addr, .port = port };   
}

int main(int argc, char **argv)
{
    struct args_t args = parse_args_or_exit(argc, argv);
    serve(args.addr, args.port, args.file);
    return 0;
}
