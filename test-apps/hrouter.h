#ifndef _HROUTER_
#define _HROUTER_

#include "libwebsockets.h"

struct hrouter_request {

    //enum lws_hrouter_request_method
    int method;
    char uri[32];
    int is_ws;
    unsigned long long content_length;
    char* content;
    size_t position;
    char* response;
    char result[LWS_PRE + LWS_RECOMMENDED_MIN_HEADER_SPACE];
};
typedef int (*hrouter_request_action_handler)(const char* action, struct hrouter_request* request);


// please using const action,
// action will be called when prefix match
int hrouter_server_register_action(const char* action, hrouter_request_action_handler handler, int need_auth);


#endif //_HROUTER_
