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

#include "client6.h"
#include "ioquery6.h"
#include "query6.h"
#include "tcpclient6.h"
#include "udpclient6.h"

/* #include "debug.h" */

#include "client_answer.c"
