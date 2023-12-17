#include "hrouter.h"
#include <stddef.h>
#include <stdio.h>

#include "cjson/cJSON.h"

static int _system_version_action_handler(struct hrouter_request *request) {
  cJSON *root = NULL;
  cJSON *result = NULL;
  if (!request || !request->content)
    return -1;

  root = cJSON_Parse(request->content);
  if (!root) {
    printf("invalid data ....\n");
    return -1;
  }

#if 0 // ignore args
  data = cJSON_GetObjectItem(root, "data");
  if (!data) {
    printf("invalid data ....\n");
    cJSON_Delete(root);
    return -1;
  }

#endif

  char *str = cJSON_Print(root);

  printf("got :%s\n", str);

  free(str);

  result = cJSON_CreateObject();
  cJSON_AddStringToObject(result, "software", "1.1.0");
  cJSON_AddStringToObject(result, "hardware", "HW 1.0");
  cJSON_AddStringToObject(result, "os", "hsan 3.3.16");

  // will be released later
  request->response = cJSON_Print(result);

  cJSON_Delete(root);

  return 0;
}

static struct _action_handler {
  const char *action;
  int (*handler)(struct hrouter_request *request);
  int need_auth;
} _action_handler_tbl[] = {
    {"/system/version", _system_version_action_handler, 0}, {NULL, NULL, 0}

};

static int _system_action_handler(const char *action,
                                  struct hrouter_request *request) {
  unsigned int i = 0;
  if (!action || !request) {
    return -1;
  }

  for (i = 0; i < sizeof(_action_handler_tbl) / sizeof(_action_handler_tbl[0]);
       i++) {
    if (!_action_handler_tbl[i].action || !_action_handler_tbl[i].handler)
      continue;

    if (!strcmp(action, _action_handler_tbl[i].action)) {
      _action_handler_tbl[i].handler(request);
    }
  }

  return 0;
}

int hrouter_server_system_init() {
  return hrouter_server_register_action("/system", _system_action_handler, 0);
}
