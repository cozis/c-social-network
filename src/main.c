#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include "main.h"

static void callback(xh_request *req, xh_response *res, void *userp)
{
    isolate_t *isol = userp;
    buffer_reset(&isol->buffer);

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

    typedef void (*routine_t)(isolate_t*, xh_request*, xh_response*, const char*);

    typedef struct {
        const char  *path;
        int       methods;
        routine_t routine;
    } route_t;

    static const route_t routes[] = {
        { "/api/login",  XH_POST, route_api_login  },
        { "/api/signup", XH_POST, route_api_signup },
        { "/api/logout", XH_GET,  route_api_logout },
        { "/login",  XH_GET, route_login  },
        { "/signup", XH_GET, route_signup },
        { "/all",    XH_GET, route_all    },
    };

    const route_t *route = NULL;
    for(unsigned int i = 0; i < sizeof(routes)/sizeof(routes[0]); i += 1)
        if(!strcmp(req->URL, routes[i].path))
            { route = routes + i; break; }
    
    if(route == NULL)
    {
        res->status = 404;
        res->body = "This resource doesn't exist :/";
        res->body_len = strlen(res->body);
        return;
    }

    if(!(req->method_id & route->methods))
    {
        res->status = 405; 
        res->body = "Invalid method";
        res->body_len = strlen(res->body);
        return;
    }

    assert(route->routine != NULL);
    route->routine(isol, req, res, usern);
}

static const char schema[] = 
"CREATE TABLE IF NOT EXISTS Accounts (\n"
"    usern VARCHAR(" STR(USERN_MAX) ") PRIMARY KEY,\n"
"    passw VARCHAR(" STR(PASSW_MAX) ") NOT NULL\n"
");\n"
"\n"
"CREATE TABLE IF NOT EXISTS Groups (\n"
"    name VARCHAR(" STR(GNAME_MAX) ") PRIMARY KEY,\n"
"    intro VARCHAR(" STR(GINTR_MAX) ")\n"
");\n"
"\n"
"CREATE TABLE IF NOT EXISTS Posts (\n"
"    post_id INT PRIMARY KEY,\n"
"    _group VARCHAR(" STR(GNAME_MAX) ") NOT NULL,\n"
"    title VARCHAR(" STR(PTITL_MAX) ") NOT NULL,\n"
"    body TEXT NOT NULL,\n"
"    FOREIGN KEY (_group) REFERENCES Groups(name)\n"
");\n";

static _Thread_local xh_handle handle;

static void handle_sigterm(int signo)
{ 
    (void) signo;
    xh_quit(handle); 
}

void serve(const char *addr, unsigned short port, const char *file)
{

#ifdef DEBUG
    fprintf(stderr, "INFO: Debug mode active\n");
#endif

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

        buffer_init(&isol.buffer);

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
        buffer_free(&isol.buffer);
    }

    fprintf(stderr, "\r");
    if(err != NULL)
        fprintf(stderr, "ERROR: %s\n", err);
    fprintf(stderr, "EXITING\n");
}

static void usage(FILE *fp, const char *exec)
{
    fprintf(fp, "Usage:\n\t%s [ --file <database-file-path> ] [ --port <n> ] [ --addr x.x.x.x ]\n", exec);
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
                                "an IPv4 address after it\n"
                                "\n");
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
                                "integer between 0 and 65535 after it\n"
                                "\n");
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
                                "file path after it\n"
                                "\n");
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
            fprintf(stderr, "ERROR: invalid port\n\n");
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
