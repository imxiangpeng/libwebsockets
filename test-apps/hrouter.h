#ifndef _HROUTER_
#define _HROUTER_

#include "libwebsockets.h"

#define HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE (LWS_PRE + 512) 
#define HROUTER_SERVER_PRE_DEFAULT_RESPONSE_SIZE (LWS_PRE + 1024)

struct _hrouter_buffer {
    char* data;
    size_t size;
    size_t offset;
};

struct hrouter_request {
    int method;
    char uri[32];
    int is_ws;
    struct _hrouter_buffer content;
    struct _hrouter_buffer response_hdr;
    struct _hrouter_buffer response;
};
typedef int (*hrouter_request_action_handler)(const char* action, struct hrouter_request* request);


// please using const action,
// action will be called when prefix match
int hrouter_server_register_action(const char* action, hrouter_request_action_handler handler, int need_auth);

int hrouter_buffer_alloc(struct _hrouter_buffer *buf, size_t size);
int hrouter_buffer_realloc(struct _hrouter_buffer *buf, size_t size);
int hrouter_buffer_free(struct _hrouter_buffer *buf);
int hrouter_buffer_reset(struct _hrouter_buffer *buf);

#endif //_HROUTER_
