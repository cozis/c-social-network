#include <string.h>
#include "main.h"

static void generate_page(isolate_t *isol);

void route_all(isolate_t *isol, xh_request *req, xh_response *res, const char *usern)
{
    (void) req;
    
    if(usern == NULL)
    {
        /* Not logged in. */
        res->status = 401;
        res->body = "You're not authorized to see this! :S";
        res->body_len = strlen(res->body);
        return;
    }

    generate_page(isol);

    int   len;
    char *str;

    str = buffer_done(&isol->buffer, &len);
    
    if(str == NULL)
    {
        res->status = 500;
        res->body = "Out of memory";
        res->body_len = strlen(res->body);
    }
    else
    {
        res->status = 200;
        res->body = str;
        res->body_len = len;
    }
    xh_header_add(res, "Content-Type", "text/html");
}

static void generate_page(isolate_t *isol)
{
    buffer_append2(&isol->buffer, (const char*[]) {
    "<html>\n"
    "  <head>\n"
    "    <title>Hello, world!</title>\n"
    "      <style>\n"
    "        body {\n"
    "          font-size: 16px;\n"
    "          font-family: monospace;\n"
    "        }\n"
    "\n"
    "        #main-container {\n"
    "          max-width: 95%;\n"
    "          width: 900px;\n"
    "          margin: auto;\n"
    "        }\n"
    "\n"
    "        #page-content {\n"
    "          background: #ffefb5;\n"
    "          /*padding: 20px;*/\n"
    "          padding: 0 10px;\n"
    "          border-radius: 3px;\n"
    "        }\n"
    "\n"
    "        a.active {\n"
    "          background: #96ff61;\n"
    "        }\n"
    "\n"
    "        a:link {\n"
    "          color: #6b7dcd;\n"
    "        }\n"
    "\n"
    "        a:visited {\n"
    "          color: #c56bcd;\n"
    "        }\n"
    "\n"
    "        .left  { float:  left; }\n"
    "        .right { float: right; }\n"
    "\n"
    "        nav {\n"
    "          overflow: auto;\n"
    "          padding: 10px;\n"
    "          background: #ff7561;\n"
    "          border-radius: 3px;\n"
    "        }\n"
    "\n"
    "        nav a:link,\n"
    "        nav a:visited {\n"
    "           color: black;\n"
    "        }\n"
    "\n"
    "        nav a:hover {\n"
    "          color: #333;\n"
    "        }\n"
    "\n"
    "        .item {\n"
    "          color: #cda66b;\n"
    "          padding: 10px;\n"
    "          border-bottom: 1px dashed #cda66b;\n"
    "        }\n"
    "\n"
    "        .item:last-child {\n"
    "          border-bottom: 0;\n"
    "        }\n"
    "\n"
    "        .item .title {\n"
    "          font-size: 20px;\n"
    "        }\n"
    "\n"
    "        .item .title a {\n"
    "           color: #000;\n"
    "           text-decoration: none;\n"
    "        }\n"
    "\n"
    "        .item .info {\n"
    "          margin-top: 10px;\n"
    "          overflow: auto;\n"
    "        }\n"
    "      </style>\n"
    "  </head>\n"
    "  <body>\n"
    "    <div id=\"main-container\">\n"
    "      <nav>\n"
    "        <div class=\"left\">\n"
    "          [<a href=\"/all\">Tutti</a> | <a href=\"/follows\">Seguiti</a>]\n"
    "        </div>\n"
    "        <div class=\"right\">\n"
    "          [<a href=\"\">Cozis</a> | <a href=\"\">Esci</a>]\n"
    "        </div>\n"
    "      </nav>\n"
    "      <br>\n"
    "      <div id=\"page-content\">\n"
    "\n",
    NULL
    });

    buffer_append2(&isol->buffer, (const char*[]) {
    "<div class=\"item\">\n"
    "  <div class=\"title\">\n"
    "    <a href=\"\">Google Drive to SQLite </a>\n"
    "  </div>\n"
    "  <div class=\"info\">\n"
    "    <div class=\"left\">\n"
    "      Utente: <a href=\"\">Cozis</a>,\n"
    "      Gruppo: <a href=\"\">Matematica</a>,\n"
    "      Data: 21 Febbraio 2022\n"
    "    </div>\n"
    "    <div class=\"right\">\n"
    "      [<a href=\"\">Salva</a>]\n"
    "    </div>\n"
    "  </div>\n"
    "</div>\n",
    NULL
    });
    
    buffer_append2(&isol->buffer, (const char*[]) {
    "\n"
    "      </div>\n"
    "      <br>\n"
    "      <center>\n"
    "        [<a href=\"\"><< Precedente</a>]\n"
    "        [<a href=\"\">Successivo >></a>]\n"
    "      </center>\n"
    "      <br>\n"
    "    </div>\n"
    "  </body>\n"
    "</html>\n",
    NULL
    });
}
