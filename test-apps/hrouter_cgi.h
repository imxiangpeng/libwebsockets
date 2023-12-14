#ifndef _HROUTER_CGI_
#define _HROUTER_CGI_

#include "hrouter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*hrouter_cgi_action)(struct hrouter_request* request);
typedef struct _hrouter_cgi {
  const char* name;
  hrouter_cgi_action action;
  struct _hrouter_cgi *next;

} hrouter_cgi;

int hrouter_web_cgi_register(hrouter_cgi *cgi);

int hrouter_cgi_process(struct hrouter_request *request);
#ifdef __cplusplus
}
#endif

#endif //_HROUTER_CGI_
