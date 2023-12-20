#include <assert.h>
#include <getopt.h>
#include <libwebsockets.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>

#include <sys/queue.h>

#include "hrouter.h"

int debug_level = LLL_USER | 0x1FFFFFFF;
volatile int force_exit = 0;

static struct lws_context *context = NULL;

//#define LOCAL_RESOURCE_PATH "/usr/httpd/web/web/"
//#define LOCAL_RESOURCE_PATH
//"/home/alex/workspace/workspace/websockets/libwebsockets/share/libwebsockets-test-server"

#define LOCAL_RESOURCE_PATH                                                    \
  "/home/alex/workspace/hisilicon/HSAN/output/rootfs/usr/httpd/web/web/"
extern int hrouter_server_system_init();
// extern int hrouter_cgi_process(struct hrouter_request *request);

struct _hrouter_action_entry {
  const char *action;
  hrouter_request_action_handler handler;
  int need_auth;
  STAILQ_ENTRY(_hrouter_action_entry) next;
};

static STAILQ_HEAD(_hrouter_action_head, _hrouter_action_entry)
    _hrouter_action_queue = STAILQ_HEAD_INITIALIZER(_hrouter_action_queue);

int hrouter_server_register_action(const char *action,
                                   hrouter_request_action_handler handler,
                                   int need_auth) {

  struct _hrouter_action_entry *entry = (struct _hrouter_action_entry *)calloc(
      sizeof(struct _hrouter_action_entry), 1);
  if (!entry) {
    return -1;
  }

  entry->action = action;
  entry->handler = handler;
  entry->need_auth = need_auth;

  STAILQ_INSERT_TAIL(&_hrouter_action_queue, entry, next);

  return 0;
}

int hrouter_buffer_alloc(struct _hrouter_buffer *buf, size_t size) {
  if (!buf)
    return -1;

  assert(!buf->data);

  // assert(buf->size > 0);
  buf->offset = 0;
  buf->size = size;
  buf->data = (char *)calloc(1, buf->size);
  if (!buf->data) {
    lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
    return -1;
  }

  return 0;
}
int hrouter_buffer_realloc(struct _hrouter_buffer *buf, size_t size) {
  if (!buf || !buf->data)
    return -1;

  buf->data = (char *)realloc(buf->data, size);
  if (!buf->data) {
    lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
    return -1;
  }
  buf->size = size;
  return 0;
}
int hrouter_buffer_free(struct _hrouter_buffer *buf) {
  if (!buf)
    return -1;
  buf->offset = 0;

  if (buf->data) {
    memset((void *)buf->data, 0, buf->size);
    free(buf->data);
  }

  memset((void *)buf, 0, sizeof(*buf));
  return 0;
}
int hrouter_buffer_reset(struct _hrouter_buffer *buf) {
  if (!buf || !buf->data)
    return -1;
  buf->offset = 0;
  memset((void *)buf->data, 0, buf->size);

  return 0;
}

static int _hrouter_server_action_process(struct hrouter_request *request) {

  size_t length = 0;
  char action[32] = {0};
  // char buf[32] = {0};

  struct _hrouter_action_entry *ele = NULL;
  const char *ptr = NULL;

  if (!request)
    return -1;

  printf("2 content.data:%p, size:%ld, offset:%ld\n", request->content.data,
         request->content.size, request->content.offset);

  if (request->is_ws) {
    ptr = lws_json_simple_find(request->content.data, request->content.offset,
                               "\"action\":", &length);
  } else {
    ptr = request->uri;
    length = strlen(request->uri);
  }

  if (!ptr) {
    lwsl_err("%s(%d): can not find valid action field..\n", __FUNCTION__,
             __LINE__);
    return -1;
  }

  printf("mxp ....................len:%ld....action:%s, ptr:%s, ptr+1:%s, "
         "ptr+2:%s\n",
         length, action, ptr, ptr + 1, ptr + 2);

  // if (ptr[0] == '\"' && ptr[length - 1] == '\0') {
  //   strncpy(action, ptr + 1, length - 2);
  // } else {
  strncpy(action, ptr, length);
  //}

  printf("mxp ....................len:%ld....action:%s, ptr:%s\n", length,
         action, ptr);
  STAILQ_FOREACH(ele, &_hrouter_action_queue, next) {
    if (!ele || !ele->action || !ele->handler)
      continue;
    printf("ele action:%s vs %s, cmp:%d\n", ele->action, action,
           strncmp(action, ele->action, strlen(ele->action)));

    if (!strncmp(action, ele->action, strlen(ele->action))) {
      return ele->handler(action, request);
    }
  }

  printf("can not find action ..ignore ..\n");

  return -1;
}

static int _hrouter_http_data_process(struct lws *wsi,
                                      struct hrouter_request *request) {
  int ret = 0;
  const char *content_type = "application/json";
  printf("full post data:%s\n",
         request->content.data ? request->content.data : "none");
  unsigned char *start, *p, *end;
  ret = hrouter_buffer_alloc(&request->response_hdr,
                             HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE);
  if (ret != 0) {
    lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
    return -1;
  }

  p = (unsigned char *)request->response_hdr.data + LWS_PRE;
  start = p;
  end = p + request->response_hdr.size - LWS_PRE - 1;

  ret = hrouter_buffer_alloc(&request->response,
                             HROUTER_SERVER_PRE_DEFAULT_RESPONSE_SIZE);
  if (ret != 0) {
    hrouter_buffer_free(&request->response_hdr);
    lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
    return -1;
  }

  /*int ret =*/_hrouter_server_action_process(request);

  printf("mxp: response length:%ld, data:%s\n", request->response.offset, request->response.data);
  ret = lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end);
  (void)ret;

  // ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
  //                                    (const unsigned char *)server,
  //                                    (int)strlen(server), &p, end);
  //(void)ret;
  ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                     (unsigned char *)content_type,
                                     (int)strlen(content_type), &p, end);
  (void)ret;
  size_t n = request->response.offset;

  printf("wsi:%p, request:%p, response:%p\n", wsi, request,
         request->response.data);
  ret = lws_add_http_header_content_length(wsi, (unsigned int)n, &p, end);
  (void)ret;

  ret = lws_finalize_http_header(wsi, &p, end);
  (void)ret;

  lws_write(wsi, start, lws_ptr_diff_size_t(p, start), LWS_WRITE_HTTP_HEADERS);
  lws_write(wsi, (unsigned char *)request->response.data, (unsigned int)n,
            LWS_WRITE_HTTP_FINAL);

  hrouter_buffer_free(&request->response_hdr);
  hrouter_buffer_free(&request->response);
  hrouter_buffer_free(&request->content);

  return 0;
}
static int lws_callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                             void *user, void *in, size_t len) {
  // const unsigned char *c;
  char *uri_ptr = NULL;
  int uri_len = 0;
  size_t content_length = 0;
  char content_length_str[32] = {0};
  // char buf[1024];
  // int n = 0, len;

  struct hrouter_request *request = (struct hrouter_request *)user;
  printf("%s(%d): ...........wsi:%p, hrouter:%p..........reason:%d..........\n",
         __FUNCTION__, __LINE__, (void *)wsi, (void *)request, reason);

  lwsl_err(
      "%s(%d): ...........wsi:%p, hrouter:%p..........reason:%d..........\n",
      __FUNCTION__, __LINE__, (void *)wsi, (void *)request, reason);
  lwsl_err("%s: reason: %d\n", __func__, reason);
  switch (reason) {
  case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
    break;
  case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
    break;
  case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED: // 19 wsi have created
                                                    //
    break;
  case LWS_CALLBACK_EVENT_WAIT_CANCELLED: //			= 71,
    break;
  case LWS_CALLBACK_HTTP:

  {

    int meth = lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len);
    if (/*meth != LWSHUMETH_GET &&*/ meth != LWSHUMETH_POST) {
      lwsl_debug("%s: not support :%d ....\n", __func__, meth);
      return -1;
    }

    lws_hdr_copy(wsi, request->uri, sizeof(request->uri),
                 (enum lws_token_indexes)meth);
    printf("request uri:%s\n", request->uri);
    request->method = meth;
    request->is_ws = 0;

    lwsl_debug("%s: header method:%d  uri_ptr:%p, len:%d ..in:%p, len:%ld.\n",
               __func__, meth, (void *)uri_ptr, uri_len, (void *)in, len);

    if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
        lws_hdr_copy(wsi, content_length_str, sizeof(content_length_str) - 1,
                     WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0) {

      content_length = (unsigned long long)atoll(content_length_str);

      lwsl_debug("%s: content length:%ld\n", __func__, request->content.size);
    }

    if (content_length != 0) {
      // continue waiting more data
      hrouter_buffer_alloc(&request->content, content_length + 1);
      return 0;
    }

    _hrouter_http_data_process(wsi, request);
#if 0
    if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL)) {
      lwsl_debug("%s: return http status , close ....\n", __func__);
      return -1;
    }
#endif

    if (lws_http_transaction_completed(wsi)) {
      lwsl_debug("%s: return http status , transaction completed  ....\n",
                 __func__);
      return -1;
    }
  }
    return 0;
  case LWS_CALLBACK_HTTP_BODY: {

    assert(request->content.size != 0);
    assert(request->content.data != NULL);
    assert(request->content.offset + len <= request->content.size);

    memcpy((void *)(request->content.data + request->content.offset),
           (void *)in, len);
    request->content.offset += len;

    printf("position:%ld vs %ld\n", request->content.offset,
           request->content.size);

    return 0;

    break;
  }
  case LWS_CALLBACK_HTTP_BODY_COMPLETION: {

    _hrouter_http_data_process(wsi, request);
#if 0
    int ret = 0;
    const char *server = "hrouter/1.0";
    const char *content_type = "application/json";
    printf("full post data:%s\n", request->content.data);
    unsigned char *start, *p, *end;
    ret = hrouter_buffer_alloc(&request->response_hdr,
                               HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE);
#if 0
    request->response_hdr.size = HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE;
    request->response_hdr.data = (char*)calloc(1, HROUTER_SERVER_PRE_DEFAULT_HDR_SIZE);
#endif
    if (ret != 0) {
      lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
      return -1;
    }

    p = (unsigned char *)request->response_hdr.data + LWS_PRE;
    start = p;
    end = p + request->response_hdr.size - LWS_PRE - 1;

    ret = hrouter_buffer_alloc(&request->response,
                               HROUTER_SERVER_PRE_DEFAULT_RESPONSE_SIZE);
    if (ret != 0) {
      lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
      return -1;
    }

    /*int ret =*/_hrouter_server_action_process(request);

    ret = lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end);
    (void)ret;

    ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
                                       (const unsigned char *)server,
                                       (int)strlen(server), &p, end);
    (void)ret;
    ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                       (unsigned char *)content_type,
                                       (int)strlen(content_type), &p, end);
    (void)ret;
    size_t n = request->response.offset;

    printf("wsi:%p, request:%p, response:%p\n", wsi, request,
           request->response.data);
    ret = lws_add_http_header_content_length(wsi, (unsigned int)n, &p, end);
    (void)ret;

    ret = lws_finalize_http_header(wsi, &p, end);
    (void)ret;

    lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
              LWS_WRITE_HTTP_HEADERS);
    lws_write(wsi, (unsigned char *)request->response.data, (unsigned int)n,
              LWS_WRITE_HTTP_FINAL);

    hrouter_buffer_free(&request->response_hdr);
    hrouter_buffer_free(&request->response);
    hrouter_buffer_free(&request->content);

    lwsl_debug("%s: this is body completion transaction completed  ....\n",
               __func__);
#endif
    if (lws_http_transaction_completed(wsi)) {
    }
    return 0;
    break;
  }
  case LWS_CALLBACK_HTTP_WRITEABLE:

    break;

  default:
    break;
  }

  return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int lws_callback_http_api(struct lws *wsi,
                                 enum lws_callback_reasons reason, void *user,
                                 void *in, size_t len) {
  int ret = -1;
  struct hrouter_request *request = (struct hrouter_request *)user;
  printf("%s(%d): ...........wsi:%p, hrouter:%p..........reason:%d..........\n",
         __FUNCTION__, __LINE__, (void *)wsi, (void *)request, reason);
  lwsl_err(
      "%s(%d): ...........wsi:%p, hrouter:%p..........reason:%d..........\n",
      __FUNCTION__, __LINE__, (void *)wsi, (void *)request, reason);
  switch (reason) {
  case LWS_CALLBACK_ESTABLISHED: {
    lwsl_err("New connection established\n");
    request->is_ws = 1;
    ret = hrouter_buffer_alloc(&request->content,
                               HROUTER_SERVER_PRE_DEFAULT_RESPONSE_SIZE);
    if (ret != 0) {
      lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
      return -1;
    }

    memset((void *)request->content.data, 0, request->content.size);
    ret = hrouter_buffer_alloc(&request->response,
                               HROUTER_SERVER_PRE_DEFAULT_RESPONSE_SIZE);
    if (ret != 0) {
      lwsl_err("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
      return -1;
    }

    break;
  }
  case LWS_CALLBACK_CLOSED: {
    lwsl_err("connection closed\n");

    // do not release here for same connection ...
    hrouter_buffer_free(&request->response);
    hrouter_buffer_free(&request->content);
    break;
  }
  case LWS_CALLBACK_RECEIVE: {
    lwsl_debug("recevied:%s, len:%ld, content:%p\n\n", (unsigned char *)in, len,
               request->content.data);

    printf("content.data:%p, size:%ld, offset:%ld\n", request->content.data,
           request->content.size, request->content.offset);

    assert(request->content.data != NULL);
    assert(request->response.data != NULL);

    // assume all data will be received once.
    if (len > request->content.size) {
      hrouter_buffer_realloc(&request->content, len);
    }
    hrouter_buffer_reset(&request->content);
    memcpy((void *)(request->content.data /*+ request->content.offset*/),
           (void *)in, len);
    request->content.offset += len;

    printf("ws content data:%s, length:%ld\n", request->content.data,
           strlen(request->content.data));

    hrouter_buffer_reset(&request->response);
    // reserve LSW_PRE for ws
    request->response.offset = LWS_PRE;

    printf("mxp request:%p, response:%p, ptr:%p, size:%ld, offset:%ld\n",
           request, request->response.data, request->response.data + LWS_PRE,
           request->response.size, request->response.offset);
    _hrouter_server_action_process(request);

    printf("write len:%ld, %s\n", strlen(request->response.data + LWS_PRE),
           request->response.data);

    lws_write(wsi, (unsigned char *)request->response.data + LWS_PRE,
              request->response.offset - LWS_PRE /*remove null char*/,
              LWS_WRITE_TEXT);

    break;
  }
  default:
    break;
  }

  return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* list of supported protocols and callbacks */
static struct lws_protocols protocols[] = {
    /* first protocol must always be HTTP handler */
    {"http", lws_callback_http, sizeof(struct hrouter_request), 0, 0, NULL, 0},
    {"api", lws_callback_http_api, sizeof(struct hrouter_request), 0, 0, NULL,
     0},
    //{ "priv", lws_callback_http_api, sizeof(struct hrouter_request), 0, 0,
    // NULL, 0 },
    LWS_PROTOCOL_LIST_TERM};

void sighandler(int sig) {

  force_exit = 1;
  lws_cancel_service(context);
}

/*
 * mount a filesystem directory into the URL space at /
 * point it to our /usr/share directory with our assets in
 * stuff from here is autoserved by the library
 */

static const struct lws_http_mount mount = {
    /* .mount_next */ NULL,            /* linked-list "next" */
    /* .mountpoint */ "/",             /* mountpoint URL */
    /* .origin */ LOCAL_RESOURCE_PATH, /* serve from dir */
    /* .def */ "index.html",           /* default filename */
    /* .protocol */ NULL,
    /* .cgienv */ NULL,
    /* .extra_mimetypes */ NULL,
    /* .interpret */ NULL,
    /* .cgi_timeout */ 0,
    /* .cache_max_age */ 0,
    /* .auth_mask */ 0,
    /* .cache_reusable */ 0,
    /* .cache_revalidate */ 0,
    /* .cache_intermediaries */ 0,
    /* .cache_no */ 0,
    /* .origin_protocol */ LWSMPRO_FILE, /* files in a dir */
    /* .mountpoint_len */ 1,             /* char count */
    /* .basic_auth_login_file */ NULL,
};

int main(int argc, char **argv) {
  struct lws_context_creation_info info;
  struct lws_vhost *vhost;

  uid_t uid = (uid_t)-1;
  gid_t gid = (gid_t)-1;
  int n = 0;
  struct _hrouter_action_entry *ele = NULL;

  memset(&info, 0, sizeof info);

  info.port = 7681;

  signal(SIGINT, sighandler);

  /* tell the library what debug level to emit and to send it to stderr */
  lws_set_log_level(debug_level, NULL);

  lwsl_notice("libwebsockets test server - license MIT\n");
  lwsl_notice("(C) Copyright 2010-2018 Andy Green <andy@warmcat.com>\n");

  info.iface = NULL;
  info.protocols = protocols;

  info.gid = gid;
  info.uid = uid;

  info.server_string = "hrouter/1.0";
  // info.count_threads = 4;

  info.options =
      LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

  info.timeout_secs = 5;

  info.mounts = &mount;
#if defined(LWS_WITH_PEER_LIMITS)
  info.ip_limit_ah = 128;  /* for testing */
  info.ip_limit_wsi = 800; /* for testing */
#endif

  hrouter_server_system_init();

  context = lws_create_context(&info);
  if (context == NULL) {
    lwsl_err("libwebsocket init failed\n");
    return -1;
  }

  vhost = lws_create_vhost(context, &info);
  if (!vhost) {
    lwsl_err("vhost creation failed\n");
    return -1;
  }

  n = 0;
  while (n >= 0 && !force_exit) {
    struct timeval tv;

    gettimeofday(&tv, NULL);

    n = lws_service(context, 0);
  }

  lws_context_destroy(context);

  while ((ele = STAILQ_FIRST(&_hrouter_action_queue)) != NULL) {
    STAILQ_REMOVE_HEAD(&_hrouter_action_queue, next);
    free(ele);
  }

  return 0;
}
