#ifndef _HROUTER_
#define _HROUTER_

struct hrouter_request {

    //enum lws_hrouter_request_method
    int method;
    unsigned long long content_length;
    char* body_data;
    size_t position;
    //struct lws_spa *spa;
};

#endif //_HROUTER_
