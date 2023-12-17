#include "hrouter.h"
#include <stddef.h>
#include <stdio.h>

#include "cjson/cJSON.h"

static int _system_version_action_handler(struct hrouter_request *request) {
  cJSON *root = NULL;
  cJSON *result = NULL;
  if (!request || !request->content)
    return -1;

  root = cJSON_ParseWithLength(request->content, request->content_length);
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

  char *str = cJSON_PrintUnformatted(root);

  printf("got :%s\n", str);

  free(str);

  cJSON_Delete(root);

  result = cJSON_CreateObject();
  cJSON_AddStringToObject(result, "software", "1.1.0");
  cJSON_AddStringToObject(result, "hardware", "HW 1.0");
  cJSON_AddStringToObject(result, "os", "hsan 3.3.16");

  if (request->response) {
    char *ptr = request->response + request->response_offset;
    printf("request:%p, response:%p, ptr:%p, size:%ld, offset:%ld\n", request,
           request->response, ptr, request->response_size,
           request->response_offset);
    int ret = cJSON_PrintPreallocated(
        result, ptr, (int)(request->response_size - request->response_offset),
        0);
    if (ret != 1) {
      // memory maybe small
      // reallocate
      printf("%s(%d): failed maybe memory not enough.....\n", __FUNCTION__,
             __LINE__);
    }
    request->response_offset += strlen(ptr) + 1; // end with'\0'
  } else {
    // will be released later
    // request->response = cJSON_PrintUnformatted(result);
  }
  cJSON_Delete(result);

  return 0;
}

static struct _action_handler {
  const char *action;
  int (*handler)(struct hrouter_request *request);
  int need_auth;
} _action_handler_tbl[] = {
    {"/system/version", _system_version_action_handler, 0},
    {NULL, NULL, 0},
    {"/system/memory", _system_version_action_handler, 0},
    {NULL, NULL, 0},
    {"/system/disk", _system_version_action_handler, 0},
    {NULL, NULL, 0},
    {NULL, NULL, 0}

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
