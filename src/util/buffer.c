#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "buffer.h"

void buffer_init(buffer_t *buff)
{
    buff->total_size = 0;
    buff->tail_used = 0;
    buff->tail = &buff->head;
    buff->head.next = NULL;
    buff->serialized = NULL;
    buff->failed = 0;
}

void buffer_free_serialized(buffer_t *buff)
{
    if(buff->serialized != NULL && buff->serialized != buff->head.body)
        free(buff->serialized);

    buff->serialized = NULL;
}

void buffer_free(buffer_t *buff)
{
    buffer_chunk_t *c = buff->head.next;
    while(c != NULL)
    {
        buffer_chunk_t *n = c->next;
        free(c);
        c = n;
    }

    buffer_free_serialized(buff);
}

void buffer_reset(buffer_t *buff)
{
    buffer_free(buff);
    buffer_init(buff);
}

char *buffer_done(buffer_t *buff, int *len)
{
    if(len)
        *len = 0;

    if(buff->serialized == NULL)
    {
        if(buff->failed)
            return NULL;

        if(buff->total_size < (int) sizeof(buff->tail->body))
        {
            // There's only one chunk and it's
            // the preallocated one.
            buff->serialized = buff->head.body;
            buff->serialized[buff->total_size] = '\0';
        }
        else
        {
            buff->serialized = malloc(buff->total_size + 1);
            
            if(buff->serialized == NULL)
                return NULL;

            int copied = 0;
            buffer_chunk_t *c = &buff->head;
            while(c->next != NULL)
            {
                memcpy(buff->serialized + copied, c->body, sizeof(c->body));
                copied += sizeof(c->body);
            }
            assert(c->next == NULL);
            memcpy(buff->serialized + copied, c->body, buff->tail_used);
            buff->serialized[buff->total_size] = '\0';
        }
    }
    if(len) *len = buff->total_size;
    return buff->serialized;
}

void buffer_append(buffer_t *buff, const char *str, int len)
{
    assert(buff != NULL && str != NULL);

    if(buff->failed)
        return;

    buffer_free_serialized(buff);

    if(len < 0)
        len = strlen(str);

    int copied = 0;
    while(copied < len)
    {
        if(buff->tail_used == sizeof(buff->tail->body))
        {
            // Add a new chunk.
            buffer_chunk_t *c = malloc(sizeof(buffer_chunk_t));

            if(c == NULL)
            {
                buff->failed = 1;
                break;
            }
            c->next = NULL;
            buff->tail->next = c;
            buff->tail = c;
            buff->tail_used = 0;
        }

        #define MIN(X, Y) ((X) < (Y)) ? (X) : (Y)

        int copying = MIN(len - copied, (int) sizeof(buff->tail->body) - buff->tail_used);

        memcpy(buff->tail->body + buff->tail_used, str + copied, copying);

        copied += copying;
        buff->tail_used += copying;

        #undef MIN
    }

    buff->total_size += copied;
}

void buffer_append2(buffer_t *buff, const char **str)
{
    int i = 0;
    while(str[i] != NULL)
        buffer_append(buff, str[i++], -1);
}