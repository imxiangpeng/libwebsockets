#include <stddef.h>
#include <stdio.h>
#include "hrouter.h"
#include "hrouter_cgi.h"



int _system_cgi_action(struct hrouter_request* request) {

  printf("%s(%d): come ..............................\n", __FUNCTION__, __LINE__);
  return 0;
}




static hrouter_cgi cgi = {
  .name = "cgi.system",
  .action = _system_cgi_action,
  .next = NULL,
};

int system_init() {

return hrouter_web_cgi_register(&cgi);
}
