#include "dns.h"
#include "log.h"

void log_stats(void)
{
  extern uint64_t num_queries;
  extern uint64_t cache_motion;
  extern unsigned int udpclient_active;
  extern unsigned int tcpclient_active;

  log_string("stats ");
  log_number(num_queries);
  log_space();
  log_number(cache_motion);
  log_space();
  log_number(udpclient_active);
  log_space();
  log_number(tcpclient_active);
  log_line();
}
