#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hrouter_cgi.h"


#include "cjson/cJSON.h"


static hrouter_cgi *_cgi_tbl = NULL;
//static hrouter_cgi **_cgi_tbl_tail = &_cgi_tbl;

int hrouter_web_cgi_register(hrouter_cgi *cgi) {
  hrouter_cgi* l = _cgi_tbl;
  if (!_cgi_tbl) {
    _cgi_tbl = cgi;
    
    return 0;
  }
  
  for (; l->next != NULL; l = l->next) {
  
  }
  
  if (l) {
    l->next = cgi;
  }

  return 0;
}



int hrouter_cgi_process(struct hrouter_request *request) {
  int ret = -1;
  if ( !request ) {
    return -1;
  }
  
  hrouter_cgi* l = _cgi_tbl;
  
  if (!l || !l->name || !l->action) {
    return -1;
  } 


  char* target = NULL;

  char* data = request->body_data;
    cJSON *obj = cJSON_Parse(data);
    if (!obj) {
        return -1;
    }

    char *str = cJSON_Print(obj);

    printf("got :%s\n", str);

    free(str);
    cJSON * cmd = cJSON_GetObjectItem(obj, "cmd");
    
    target = cJSON_GetStringValue(cmd);
    
  for (; l != NULL; l = l->next) {
    if (0 == strncmp(l->name, target, strlen(l->name))) {
        break;
    }
  }
  
  if (l) {
    ret = l->action(request);
  }
  
      cJSON_Delete(obj);

  return ret;
}

