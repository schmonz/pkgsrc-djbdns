#include <nemo/stdint.h>
#include <nemo/uint16.h>
#include <nemo/byte.h>

#include "dnscache.h"
#include "response.h"
#include "cache.h"
#include "log.h"
#include "dn_vector.h"
#include "die.h"
#include "safe.h"

#include "client4.h"
#include "ioquery4.h"
#include "query4.h"
#include "tcpclient4.h"
#include "udpclient4.h"

/* #define DEBUG 1 */
/* #include "debug.h" */

#include "client_answer.c"
