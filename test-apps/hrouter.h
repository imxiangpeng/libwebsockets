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

    //enum lws_hrouter_request_method
    int method;
    char uri[32];
    int is_ws;
    struct _hrouter_buffer content;
    //unsigned long long content_length;
    //char* content;
    //int using_external_content;
    //size_t content_offset;
    struct _hrouter_buffer response_hdr;
    //char response_hdr[HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE/*LWS_RECOMMENDED_MIN_HEADER_SPACE*/];
    struct _hrouter_buffer response;
    //char* response;
    //size_t response_size;
    //size_t response_offset;
};
typedef int (*hrouter_request_action_handler)(const char* action, struct hrouter_request* request);


// please using const action,
// action will be called when prefix match
int hrouter_server_register_action(const char* action, hrouter_request_action_handler handler, int need_auth);


#endif //_HROUTER_
