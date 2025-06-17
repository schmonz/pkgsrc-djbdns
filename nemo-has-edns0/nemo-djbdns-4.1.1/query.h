#ifndef NEMO_QUERY_H
#define NEMO_QUERY_H

typedef enum {
  R_QUERY_EVENT_FAIL = 0,
  R_QUERY_EVENT_NEW,
  R_QUERY_EVENT_RETRY,
  R_QUERY_EVENT_IOQUERY
} query_event_t;

typedef enum {
  R_QUERY_NS_FAIL = 0,
  R_QUERY_NS_ROOTS,
  R_QUERY_NS_IP_FOUND,
  R_QUERY_NS_NEWQUERY,
  R_QUERY_NS_RETRY
} query_ns_t;

typedef enum {
  R_FAIL = 0,
  R_NOT_FOUND,
  R_FOUND_OK,
  R_LOWER_LEVEL,
} query_cache_t;


#define QUERY_MAXLEVEL 5
#define QUERY_MAXNS 32

#endif
