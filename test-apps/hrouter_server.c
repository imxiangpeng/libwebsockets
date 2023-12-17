  /*
  * libwebsockets-test-server - libwebsockets test implementation
  *
  * Written in 2010-2019 by Andy Green <andy@warmcat.com>
  *
  * This file is made available under the Creative Commons CC0 1.0
  * Universal Public Domain Dedication.
  *
  * The person who associated a work with this deed has dedicated
  * the work to the public domain by waiving all of his or her rights
  * to the work worldwide under copyright law, including all related
  * and neighboring rights, to the extent allowed by law. You can copy,
  * modify, distribute and perform the work, even for commercial purposes,
  * all without asking permission.
  *
  * The test apps are intended to be adapted for use in your code, which
  * may be proprietary.	So unlike the library itself, they are licensed
  * Public Domain.
  */
  #include <assert.h>
  #include <getopt.h>
  #include <libwebsockets.h>
  #include <signal.h>
  #include <stdio.h>
  #include <stdlib.h>

  #include <unistd.h>

  #include <sys/queue.h>

  #include "hrouter.h"

  int close_testing;
  int debug_level = LLL_USER | 7;

  volatile int force_exit = 0, dynamic_vhost_enable = 0;
  // struct lws_vhost *dynamic_vhost;
  struct lws_context *context;
  // struct lws_plat_file_ops fops_plat;
  static int test_options;

  /* http server gets files from this path */
  #define LOCAL_RESOURCE_PATH                                                    \
    "/workspace/workspace/libwebsockets/share/libwebsockets-test-server"
  char *resource_path = LOCAL_RESOURCE_PATH;
  #if defined(LWS_WITH_TLS) && defined(LWS_HAVE_SSL_CTX_set1_param)
  char crl_path[1024] = "";
  #endif

  enum lws_hrouter_request_method {
    HROUTER_HTTP_UNKNOWN = 0,
    HROUTER_HTTP_GET,
    HROUTER_HTTP_POST
  };
  /*struct hrouter_request {
      enum lws_hrouter_request_method method;
      unsigned long long content_length;
      char* body_data;
      size_t position;
      struct lws_spa *spa;
  };*/

  /*static const char *const param_names[] = {
      "action",
      "adminname",
      "adminpwd",
      "PPPOEuser",
      "PPPOEpassword",
  };*/

  /*enum enum_param_names {
          EPN_TEXT,
          EPN_SEND,
          EPN_FILE,
          EPN_UPLOAD,
  };*/

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
  #if 0
  static void _string_remove_quotes(char *str) {
      size_t len = strlen(str);
      if (str[0] == '\"' && str[len-1] == '\"') {
          memmove(str, str+1, len-1);
          str[len-1] = '\0';
      }
  }
  #endif
  static int _hrouter_server_action_process(struct hrouter_request *request) {

    size_t length = 0;
    char action[32] = {0};
    //char buf[32] = {0};

    struct _hrouter_action_entry *ele = NULL;

    if (!request)
      return -1;

    const char *ptr = lws_json_simple_find(
        request->content, request->content_length, "\"action\":", &length);
    printf("mxp ....................len:%ld....action:%s, ptr:%s, ptr+1:%s, ptr+2:%s\n", length, action,
          ptr, ptr + 1, ptr+2);



    for (size_t l = 0; l < length; l++) {
        printf("i:%02ld, %c\n", l, ptr[l]);
    }
    if (ptr[0] == '\"' && ptr[length - 1] == '\0') {
    strncpy(action, ptr + 1, length - 2);
    } else {
      strncpy(action, ptr, length);
    }

        printf("mxp ....................len:%ld....action:%s, ptr:%s\n", length, action,
          ptr);
    STAILQ_FOREACH(ele, &_hrouter_action_queue, next) {
      if (!ele || !ele->action || !ele->handler) continue;
      printf("ele action:%s vs %s, cmp:%d\n", ele->action, action, strncmp(action, ele->action, strlen(ele->action)));
      
      if (!strncmp(action, ele->action, strlen(ele->action))) {
          return ele->handler(action, request);
      } 
    }

    printf("can not find action ..ignore ..\n");

    return -1;
    
    #if 0
    printf("mxp ....................len:%ld....action:%s, ptr:%s\n", length, action,
          ptr);

    ptr = lws_json_simple_find(request->content, request->content_length,
                              "\"msgid\"", &length);

    strncpy(buf, ptr, length);
    buf[length] = '\0';
    printf("mxp ....................len:%ld....msgid:%s\n", length, buf);
    printf("mxp ....................len:%ld....action:%s, ptr:%s\n", length, buf,
          ptr);

    //request->response =
    //    "{\"result\":\"0\",\"msgid\":\"1234567890\", \"data\":{}}";
    return 0;
    #endif
  }

  static int lws_callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    const unsigned char *c;
    char *uri_ptr = NULL;
    int uri_len = 0;
    char content_length_str[32] = {0};
    char buf[1024];
    int n = 0, hlen;

    struct hrouter_request *request = (struct hrouter_request *)user;
    printf("%s(%d): ...........wsi:%p, hrouter:%p..........reason:%d..........\n",
          __FUNCTION__, __LINE__, (void *)wsi, (void *)request, reason);
    lwsl_err("%s: reason: %d\n", __func__, reason);
    switch (reason) {
    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
      break;
    case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
      break;

    case LWS_CALLBACK_HTTP:

      /* non-mount-handled accesses will turn up here */

      /* dump the headers */

      do {
        c = lws_token_to_string((enum lws_token_indexes)n);
        if (!c) {
          n++;
          continue;
        }
        printf("token:n:%d -> %s\n", n, c);

        hlen = lws_hdr_total_length(wsi, (enum lws_token_indexes)n);
        if (!hlen || hlen > (int)sizeof(buf) - 1) {
          n++;
          continue;
        }

        if (lws_hdr_copy(wsi, buf, sizeof buf, (enum lws_token_indexes)n) < 0)
          fprintf(stderr, "    %s (too big)\n", (char *)c);
        else {
          buf[sizeof(buf) - 1] = '\0';
          printf("   1 %s = %s\n", (char *)c, buf);
          fprintf(stderr, "    %s = %s\n", (char *)c, buf);
          lwsl_debug("%s: %s --> buf:%s\n", __func__, c, buf);
        }
        n++;
      } while (c);

      /* dump the individual URI Arg parameters */

      n = 0;
      while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_URI_ARGS,
                                  n) > 0) {
        lwsl_notice("URI Arg %d: %s\n", ++n, buf);
        lwsl_debug("%s: buf:%s\n", __func__, buf);
      }

      char value[100];
      int z =
          lws_get_urlarg_by_name_safe(wsi, "PPPOEuser", value, sizeof(value) - 1);
      (void)z;
      lwsl_debug("%s: PPPOEuser .....:%s\n", __func__, value);

      int meth = lws_http_get_uri_and_method(wsi, &uri_ptr, &uri_len);
      if (meth != LWSHUMETH_GET && meth != LWSHUMETH_POST) {
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

  #if 1
      if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
          lws_hdr_copy(wsi, content_length_str, sizeof(content_length_str) - 1,
                      WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0) {

        request->content_length = (unsigned long long)atoll(content_length_str);

        lwsl_debug("%s: content length:%lld\n", __func__,
                  request->content_length);
      }
  #endif

      // if it's http get, it means that we can not find the page, return it ...
  #if 1
      if (request->content_length != 0) {
        // continue waiting more data
        return 0;
      }

      if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL)) {
        lwsl_debug("%s: return http status , close ....\n", __func__);
        return -1;
      }

      if (lws_http_transaction_completed(wsi)) {
        lwsl_debug("%s: return http status , transaction completed  ....\n",
                  __func__);
        return -1;
      }
  #endif
      return 0;
    case LWS_CALLBACK_HTTP_BODY: {

      if (!request->content) {
        request->content = (char *)malloc(request->content_length);
        request->position = 0;
      }

      assert(request->position + len <= request->content_length);

      memcpy((void *)(request->content + request->position), (void *)in, len);
      request->position += len;

      printf("position:%ld vs %lld\n", request->position,
            request->content_length);

      return 0;

      break;
    }
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:

      int ret = 0;
      const char* server = "hrouter/1.0";
      const char *content_type = "application/json";
      printf("full post data:%s\n", request->content);
      unsigned char *start, *p, *end;
      p = (unsigned char *)request->result + LWS_PRE;
      start = p;
      end = p + sizeof(request->result) - LWS_PRE - 1;
      /*int ret =*/_hrouter_server_action_process(request);

      ret = lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end);
      (void)ret;

      ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER, (const unsigned char*)server, (int)strlen(server), &p, end);
        (void)ret;
      ret = lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                        (unsigned char *)content_type,
                                        (int)strlen(content_type), &p, end);
      (void)ret;
      size_t n = 0;
      if (request->response) {
        n = strlen(request->response);
      }
      ret = lws_add_http_header_content_length(wsi, (unsigned int)n, &p, end);
      (void)ret;

      ret = lws_finalize_http_header(wsi, &p, end);
      (void)ret;

      lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
                LWS_WRITE_HTTP_HEADERS);
      lws_write(wsi, (unsigned char *)request->response, (unsigned int)n,
                LWS_WRITE_HTTP_FINAL);

  #if 0
      if (lws_return_http_status(wsi, HTTP_STATUS_OK, hrouter->response))
        return -1;
  #endif
  /*
  * Our response is to redirect to a static page.  We could
  * have generated a dynamic html page here instead.
  */
  #if 0
          if (lws_http_redirect(wsi, use303 ? HTTP_STATUS_SEE_OTHER :
                                HTTP_STATUS_MOVED_PERMANENTLY,
                                (unsigned char *)"after-form1.html",
                                16, &p, end) < 0)
          return -1;
  #endif
  #if 1
      lwsl_debug("%s: this is body completion transaction completed  ....\n",
                __func__);
      if (lws_http_transaction_completed(wsi)) {
      }
  #endif
      return 0;
      break;

    case LWS_CALLBACK_HTTP_WRITEABLE:

      break;
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
      // if (hrouter->spa && lws_spa_destroy(hrouter->spa)) {
      // hrouter->spa = NULL;
      // return -1;
      // }
      break;
    default:
      break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
  }

  static int lws_callback_http_api(struct lws *wsi,
                                  enum lws_callback_reasons reason, void *user,
                                  void *in, size_t len) {

    switch (reason) {
    case LWS_CALLBACK_ESTABLISHED: {
      lwsl_debug("New connection established\n");
      break;
    }
    case LWS_CALLBACK_RECEIVE: {
      lwsl_debug("recevied:%s, len:%ld\n\n", (unsigned char *)in, len);
      lws_write(wsi, (unsigned char *)in, len, LWS_WRITE_TEXT);
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

  #if 0
  /* this shows how to override the lws file operations.	You don't need
  * to do any of this unless you have a reason (eg, want to serve
  * compressed files without decompressing the whole archive)
  */
  static lws_fop_fd_t
  test_server_fops_open(const struct lws_plat_file_ops *this_fops,
                        const struct lws_plat_file_ops *fops,
                        const char *vfs_path, const char *vpath,
                        lws_fop_flags_t *flags) {
      lws_fop_fd_t fop_fd;

      /* call through to original platform implementation */
      fop_fd = fops_plat.open(fops, fops, vfs_path, vpath, flags);

      if (fop_fd) lwsl_info("%s: opening %s, ret %p, len %lu\n", __func__,
                            vfs_path, fop_fd,
                            (long)lws_vfs_get_length(fop_fd));
      else lwsl_info("%s: open %s failed\n", __func__, vfs_path);

      return fop_fd;
  }
  #endif
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
      /* .def */ "test.html",            /* default filename */
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

  static struct option options[] = {
      {"help", no_argument, NULL, 'h'},
      {"debug", required_argument, NULL, 'd'},
      {"port", required_argument, NULL, 'p'},
      {"ssl", no_argument, NULL, 's'},
      {"allow-non-ssl", no_argument, NULL, 'a'},
      {"interface", required_argument, NULL, 'i'},
      {"closetest", no_argument, NULL, 'c'},
      {"ssl-cert", required_argument, NULL, 'C'},
      {"ssl-key", required_argument, NULL, 'K'},
      {"ssl-ca", required_argument, NULL, 'A'},
      {"resource-path", required_argument, NULL, 'r'},
  #if defined(LWS_WITH_TLS)
      {"ssl-verify-client", no_argument, NULL, 'v'},
  #if defined(LWS_HAVE_SSL_CTX_set1_param)
      {"ssl-crl", required_argument, NULL, 'R'},
  #endif
  #endif
      {"libev", no_argument, NULL, 'e'},
      {"unix-socket", required_argument, NULL, 'U'},
  #ifndef LWS_NO_DAEMONIZE
      {"daemonize", no_argument, NULL, 'D'},
  #endif
      {"ignore-sigterm", no_argument, NULL, 'I'},

      {NULL, 0, 0, 0}};

  static void sigterm_catch(int sig) {}

  int main(int argc, char **argv) {
    struct lws_context_creation_info info;
    struct lws_vhost *vhost;
    char interface_name[128] = "";
    const char *iface = NULL;
    char cert_path[1024] = "";
    char key_path[1024] = "";
    char ca_path[1024] = "";
  #ifndef LWS_NO_DAEMONIZE
    int daemonize = 0;
  #endif
    uint64_t opts = 0;
    int use_ssl = 0;
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    int n = 0;

    /*
    * take care to zero down the info struct, he contains random garbaage
    * from the stack otherwise
    */
    memset(&info, 0, sizeof info);
    info.port = 7681;

    while (n >= 0) {

      n = getopt_long(argc, argv, "eci:hsap:d:DC:K:A:R:vu:g:kU:niIr:", options,
                      NULL);
      // n = getopt(argc, argv, "eci:hsap:d:DC:K:A:R:vu:g:kU:nIr:");
      if (n < 0)
        continue;
      switch (n) {
      case 'e':
        opts |= LWS_SERVER_OPTION_LIBEV;
        break;
  #ifndef LWS_NO_DAEMONIZE
      case 'D':
        daemonize = 1;
        break;
  #endif
      case 'u':
        uid = (uid_t)atoi(optarg);
        break;
      case 'g':
        gid = (gid_t)atoi(optarg);
        break;
      case 'd':
        debug_level = atoi(optarg);
        break;
      case 'n':
        /* no dumb increment send */
        test_options |= 1;
        break;
      case 'I':
        signal(SIGTERM, sigterm_catch);
        break;
      case 'r':
        resource_path = optarg;
        break;
      case 's':
        use_ssl = 1;
        opts |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        break;
      case 'a':
        opts |= LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;
        break;
      case 'p':
        info.port = atoi(optarg);
        break;
      case 'i':
        lws_strncpy(interface_name, optarg, sizeof interface_name);
        iface = interface_name;
        break;
      case 'U':
        lws_strncpy(interface_name, optarg, sizeof interface_name);
        iface = interface_name;
        opts |= LWS_SERVER_OPTION_UNIX_SOCK;
        break;
      case 'k':
        info.bind_iface = 1;
  #if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
        info.caps[0] = CAP_NET_RAW;
        info.count_caps = 1;
  #endif
        break;
      case 'c':
        close_testing = 1;
        fprintf(stderr, " Close testing mode -- closes on "
                        "client after 50 dumb increments"
                        "and suppresses lws_mirror spam\n");
        break;
      case 'C':
        lws_strncpy(cert_path, optarg, sizeof(cert_path));
        break;
      case 'K':
        lws_strncpy(key_path, optarg, sizeof(key_path));
        break;
      case 'A':
        lws_strncpy(ca_path, optarg, sizeof(ca_path));
        break;
  #if defined(LWS_WITH_TLS)
      case 'v':
        use_ssl = 1;
        opts |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
        break;

  #if defined(LWS_HAVE_SSL_CTX_set1_param)
      case 'R':
        lws_strncpy(crl_path, optarg, sizeof(crl_path));
        break;
  #endif
  #endif
      case 'h':
        fprintf(stderr, "Usage: test-server "
                        "[--port=<p>] [--ssl] "
                        "[-d <log bitfield>]\n");
        exit(1);
      }
    }

    signal(SIGINT, sighandler);

    /* tell the library what debug level to emit and to send it to stderr */
    lws_set_log_level(debug_level, NULL);

    lwsl_notice("libwebsockets test server - license MIT\n");
    lwsl_notice("(C) Copyright 2010-2018 Andy Green <andy@warmcat.com>\n");

    printf("Using resource path \"%s\"\n", resource_path);

    info.iface = iface;
    info.protocols = protocols;

  #if defined(LWS_WITH_TLS)
    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;

    if (use_ssl) {
      if (strlen(resource_path) > sizeof(cert_path) - 32) {
        lwsl_err("resource path too long\n");
        return -1;
      }
      if (!cert_path[0])
        sprintf(cert_path, "%s/libwebsockets-test-server.pem", resource_path);
      if (strlen(resource_path) > sizeof(key_path) - 32) {
        lwsl_err("resource path too long\n");
        return -1;
      }
      if (!key_path[0])
        sprintf(key_path, "%s/libwebsockets-test-server.key.pem", resource_path);
  #if defined(LWS_WITH_TLS)
      info.ssl_cert_filepath = cert_path;
      info.ssl_private_key_filepath = key_path;
      if (ca_path[0])
        info.ssl_ca_filepath = ca_path;
  #endif
    }
  #endif
    info.gid = gid;
    info.uid = uid;
    info.options = opts | LWS_SERVER_OPTION_VALIDATE_UTF8 |
                  LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
  #if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
    info.extensions = exts;
  #endif
    info.timeout_secs = 5;
  #if defined(LWS_WITH_TLS)
    info.ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
                          "ECDHE-RSA-AES256-GCM-SHA384:"
                          "DHE-RSA-AES256-GCM-SHA384:"
                          "ECDHE-RSA-AES256-SHA384:"
                          "HIGH:!aNULL:!eNULL:!EXPORT:"
                          "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
                          "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
                          "!DHE-RSA-AES128-SHA256:"
                          "!AES128-GCM-SHA256:"
                          "!AES128-SHA256:"
                          "!DHE-RSA-AES256-SHA256:"
                          "!AES256-GCM-SHA384:"
                          "!AES256-SHA256";
  #endif
    info.mounts = &mount;
  #if defined(LWS_WITH_PEER_LIMITS)
    info.ip_limit_ah = 128;  /* for testing */
    info.ip_limit_wsi = 800; /* for testing */
  #endif

    if (use_ssl)
      /* redirect guys coming on http */
      info.options |= LWS_SERVER_OPTION_REDIRECT_HTTP_TO_HTTPS;

    hrouter_server_system_init();

    context = lws_create_context(&info);
    if (context == NULL) {
      lwsl_err("libwebsocket init failed\n");
      return -1;
    }

    // info.pvo = &pvo;
  #if 1
    vhost = lws_create_vhost(context, &info);
    if (!vhost) {
      lwsl_err("vhost creation failed\n");
      return -1;
    }
  #endif
    /*
    * For testing dynamic vhost create / destroy later, we use port + 1
    * Normally if you were creating more vhosts, you would set info.name
    * for each to be the hostname external clients use to reach it
    */

    // info.port++;

  #if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_TLS)
    // lws_init_vhost_client_ssl(&info, vhost);
  #endif

    /* this shows how to override the lws file operations.	You don't need
    * to do any of this unless you have a reason (eg, want to serve
    * compressed files without decompressing the whole archive)
    */
    /* stash original platform fops */
    // fops_plat = *(lws_get_fops(context));
    /* override the active fops */
    // lws_get_fops(context)->open = test_server_fops_open;

    n = 0;
    while (n >= 0 && !force_exit) {
      struct timeval tv;

      gettimeofday(&tv, NULL);

      /*
      * This provokes the LWS_CALLBACK_SERVER_WRITEABLE for every
      * live websocket connection using the DUMB_INCREMENT protocol,
      * as soon as it can take more packets (usually immediately)
      */

      /*
      * If libwebsockets sockets are all we care about,
      * you can use this api which takes care of the poll()
      * and looping through finding who needed service.
      */

      n = lws_service(context, 0);
    }

    lws_context_destroy(context);

    lwsl_notice("libwebsockets-test-server exited cleanly\n");

    return 0;
  }
