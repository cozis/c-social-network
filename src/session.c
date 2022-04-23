#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "main.h"

const char *session_find(isolate_t *isol, int sess_id)
{
    for(int i = 0; i < isol->sess_num; i += 1)
        if(isol->sess[i].sess_id == sess_id)
            return isol->sess[i].usern;
    return NULL;
}

int session_create(isolate_t *isol, const char *usern)
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

_Bool session_delete(isolate_t *isol, const char *usern)
{
    int j = -1;
    for(int i = 0; i < isol->sess_num; i += 1)
        if(!strcmp(isol->sess[i].usern, usern))
            { j = i; break; }

    if(j < 0)
        return 0;

    isol->sess[j] = isol->sess[isol->sess_num-1];
    isol->sess_num -= 1;
    return 1;
}