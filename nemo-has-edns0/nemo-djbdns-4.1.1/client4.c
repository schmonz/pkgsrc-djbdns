#include <nemo/alloc.h>

#include "dnscache.h"
#include "dn_vector.h"

#include "query4.h"
#include "client4.h"
#include "ioquery4.h"
#include "tcpclient4.h"
#include "udpclient4.h"
#include "die.h"

static client c_list[MAX_IOQUERY];

static client *c_free_list_head = 0;

#include "client.c"
