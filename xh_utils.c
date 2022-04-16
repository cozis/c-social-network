#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "xh_utils.h"

const char *xh_params_get(xh_params *params, const char *name, int *len)
{
    for(int i = 0; i < params->count; i += 1)
        if(!strcmp(params->list[i].name, name))
        {
            if(len) *len = params->list[i].value_len;
            return params->list[i].value;
        }
    return NULL;
}

static const char *decode_string(const char *str, int off, int len, char *dest)
{
    for(int j = 0, k = 0; j < len; j += 1)
    {
        char c = str[off + j];

        if(c == '+')
            dest[k++] = ' ';
        else 
            if(c == '%')
            {
                if(j+2 >= len)
                    return "%% isn't followed by 2 characters";
                
                char p = str[off + j+1], 
                     q = str[off + j+2];

                if(!isxdigit(p) || !isxdigit(q))
                    return "%% isn't followed by 2 hex digits";

                dest[k++] = ((tolower(p) - '0') << 4) | (tolower(q) - '0');
                j += 2;
            }
        else
            dest[k++] = c;
    }
    return NULL;
}

xh_params *xh_params_decode(const char *str, int len, const char **err, _Bool *inte)
{
    const char *dummy_err;
    if(err == NULL)
        err = &dummy_err;

    _Bool dummy_inte;
    if(inte == NULL)
        inte = &dummy_inte;

    *err = NULL;
    *inte = 0;

    if(len < 0)
        len = strlen(str);

    xh_param buffer[16];
    int count = 0;
    int ignored = 0;

    int i = 0;
    while(i < len)
    {
        int perc_in_name = 0;

        int name_off = i;

        // Scan until =, & or the end.
        while(i < len && str[i] != '=' && str[i] != '&')
        {
            if(str[i] == '%')
                perc_in_name += 1;
            i += 1;
        }

        int name_len = i - name_off;

        int perc_in_value = 0;
        int value_off = i+1;

        if(i < len && str[i] == '=')
            // The parameter also has a value,
            // so scan that too.
            while(i < len && str[i] != '&')
            {
                if(str[i] == '%')
                    perc_in_value += 1;
                i += 1;
            }

        int value_len = i - value_off;

        if(i < len)
        {
            assert(str[i] == '&');
            i += 1;
        }

        // Now decode name and value and push them
        // to the param list.

        // Since every % followed by 2 hex digits
        // is decoded into 1 byte, we can deduce
        // that the length of the decoded string
        // is:
        //   old_size - perc_count * 2

        int decoded_name_len  = name_len  - perc_in_name * 2;
        int decoded_value_len = value_len - perc_in_value * 2;

        char *temp = malloc(decoded_name_len + decoded_value_len + 2);

        if(temp == NULL)
            { *inte = 1; *err = "No memory"; goto failure; }

        char *decoded_name  = temp;
        char *decoded_value = temp + decoded_name_len + 1;

        *err = decode_string(str, name_off, name_len, decoded_name);
        if(*err != NULL) 
            { *inte = 0; goto failure; }

        *err = decode_string(str, value_off, value_len, decoded_value);
        if(*err != NULL) 
            { *inte = 0; goto failure; }
        
        decoded_name[decoded_name_len] = '\0';
        decoded_value[decoded_value_len] = '\0';

        assert(count >= 0);
        if((unsigned int) count < sizeof(buffer)/sizeof(buffer[0]))
        {
            buffer[count].name     = decoded_name;
            buffer[count].name_len = decoded_name_len;
            buffer[count].value     = decoded_value;
            buffer[count].value_len = decoded_value_len;
            count += 1;
        }
        else
        {
            ignored += 1;
            free(decoded_name);
        }
    }

    xh_params *params = malloc(sizeof(xh_params) + count * sizeof(xh_param));

    if(params == NULL)
        { *err = "Out of memory"; *inte = 1; goto failure; }

    params->count = count;
    params->ignored = ignored;
    for(int i = 0; i < count; i += 1)
        params->list[i] = buffer[i];
    
    return params;

failure:
    assert(*err != NULL);
    for(int i = 0; i < count; i += 1)
        free(buffer[i].name);
    return NULL;
}

void xh_params_free(xh_params *params)
{
    for(int i = 0; i < params->count; i += 1)
        free(params->list[i].name);
    free(params);
}

static _Bool is_separator(char c)
{
    return c == '(' || c == ')' ||
           c == '<' || c == '>' ||
           c == '@' || c == ',' ||
           c == ';' || c == ':' ||
           c == '\\' || c == '"' ||
           c == '/' || c == '?' ||
           c == '[' || c == ']' ||
           c == '{' || c == '}' ||
           c == '=';
}

static _Bool is_control(char c)
{
    return c < 32;
}

static _Bool is_ascii(char c)
{
    return (c & (1 << 7)) == 0;
}

void xh_cookie_free(xh_cookies *cook)
{
    for(int i = 0; i < cook->count; i += 1)
        free(cook->list[i].name);
    free(cook);
}

xh_cookies *xh_cookie_parse(xh_request *req, const char **erro, _Bool *inte)
{
    const char *dummy_erro;
    if(erro == NULL)
        erro = &dummy_erro;

    _Bool dummy_inte;
    if(inte == NULL)
        inte = &dummy_inte;

    *erro = NULL;
    *inte = 0;

    int count = 0, ignored = 0;
    xh_cookie buffer[16];

    for(int i = 0; i < (int) req->headerc; i += 1)
    {
        if(!xh_header_cmp(req->headers[i].name, "Cookie"))
            continue;

        const char *data = req->headers[i].value;

        int j = 0;

        while(1)
        {
            // Skip any whitespace that precedes the
            // cookie's name.
            while(data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r')
                j += 1;

            // Now we expect the cookie's name to have
            // started. We skip any ASCII non-control
            // and non-separator character.
            int name_off = j;
            while(data[j] != '\0' && is_ascii(data[j]) && !is_separator(data[j]) && !is_control(data[j]))
                j += 1;
            int name_len = j - name_off;

            // If the cookie's name length is zero, this
            // means that an invalid character was found
            // or the header value ended before the name.
            if(name_len == 0)
            {
                if(data[j] == '\0')
                    *erro = "Header ended before the cookie's name";
                else
                    *erro = "Invalid character before cookie's name";
                *inte = 0;
                goto failed;
            }
            
            // Skip any whitespace after the name.
            while(data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n')
                j += 1;

            if(data[j] == '\0')
            {
                *inte = 0;
                *erro = "Header ended before the cookie's value was specified";
                goto failed;
            }

            if(data[j] != '=')
            {
                *inte = 0;
                *erro = "Found character other than '=' after cookie's name";
                goto failed;
            }

            j += 1; // Skip the '='.

            // Skip any whitespace before the value.
            while(data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n')
                j += 1;

            int value_off = j;
            
            _Bool wrapped_in_double_quotes = 0;

            if(data[j] == '"')
            {
                // Value is wrapped in double quotes.
                j += 1; // Skip them.
                value_off = j;
                wrapped_in_double_quotes = 1;
            }

            while(isascii(data[j]) && !is_control(data[j]) && 
                  data[j] != '"' && data[j] != ' ' && data[j] != '\t' && 
                  data[j] != '\r' && data[j] != '\n' && data[j] != ',' && 
                  data[j] != ';' && data[j] != '\\')
                j += 1;

            int value_len = j - value_off;

            if(wrapped_in_double_quotes)
            {
                if(data[j] == '\0')
                {
                    *inte = 0;
                    *erro = "The cookie's value ended before the closing double quote";
                    goto failed;
                }
                else if(data[j] == '"')
                    j += 1; // Skip the double quote.
                else
                {
                    *inte = 0;
                    *erro = "Invalid character inside cookie's value";
                    goto failed;
                }
            }

            assert(count >= 0);
            if((unsigned int) count < sizeof(buffer)/sizeof(buffer[0]))
            {
                char *temp = malloc(name_len + value_len + 2);

                if(temp == NULL)
                {
                    *inte = 1;
                    *erro = "Out of memory";
                    goto failed;
                }

                char *name_copy = temp;
                char *value_copy = temp + name_len + 1;

                memcpy(name_copy, data + name_off, name_len);
                memcpy(value_copy, data + value_off, value_len);
                name_copy[name_len] = '\0';
                value_copy[value_len] = '\0';

                buffer[count].name = name_copy;
                buffer[count].value = value_copy;
                buffer[count].name_len = name_len;
                buffer[count].value_len = value_len;
                count += 1;
            }
            else
                ignored += 1;

            // Skip whitespace before ';' or '\0'
            while(data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n')
                j += 1;

            if(data[j] == '\0')
                break;

            if(data[j] != ';')
            {
                *inte = 0;
                *erro = "Found character other than ';' after cookie's value";
                goto failed;
            }

            j += 1; // Skip the ';'.
        }
    }

    xh_cookies *cooks = malloc(sizeof(xh_cookies) + count * sizeof(xh_cookie));
    if(cooks == NULL)
    {
        *erro = "Out of memory";
        *inte = 1;
        goto failed;
    }

    cooks->count = count;
    cooks->ignored = ignored;
    memcpy(cooks->list, buffer, count * sizeof(xh_cookie));
    return cooks;

failed:
    for(int i = 0; i < count; i += 1)
        free(buffer[i].name);
    return NULL;
}