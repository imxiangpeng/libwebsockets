#ifndef _HROUTER_
#define _HROUTER_

//struct cJSON;

struct hrouter_request {

    //enum lws_hrouter_request_method
    int method;
    unsigned long long content_length;
    char* content;
    size_t position;
    //cJSON* root;
    //cJSON* ele;
};
typedef int (*hrouter_action_handler)(struct hrouter_request* request);
/*struct hrouter_action {
  const char* name;
  hrouter_action_handler action;
};*/


// please using const action, do not release it
int hrouter_server_register_action(const char* action, hrouter_action_handler handler, int need_auth);


#endif //_HROUTER_
