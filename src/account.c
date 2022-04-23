#include <assert.h>
#include <string.h>
#include "main.h"

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

_Bool account_create(isolate_t *isol, const char *usern, const char *passw)
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