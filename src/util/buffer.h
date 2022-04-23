
typedef struct buffer_chunk_t buffer_chunk_t;
struct buffer_chunk_t {
    buffer_chunk_t *next;
    char body[4096-sizeof(void*)];
};

typedef struct {
    int total_size, tail_used;
    buffer_chunk_t *tail, head;
    char *serialized;
    _Bool failed;
} buffer_t;

void buffer_init(buffer_t *buff);
void buffer_free_serialized(buffer_t *buff);
void buffer_free(buffer_t *buff);
void buffer_reset(buffer_t *buff);
char *buffer_done(buffer_t *buff, int *len);
void buffer_append(buffer_t *buff, const char *str, int len);
void buffer_append2(buffer_t *buff, const char **str);