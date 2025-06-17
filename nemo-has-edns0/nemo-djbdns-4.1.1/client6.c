#include <nemo/alloc.h>

#include "dnscache.h"
#include "dn_vector.h"

#include "query6.h"
#include "client6.h"
#include "ioquery6.h"
#include "tcpclient6.h"
#include "udpclient6.h"
#include "die.h"

static client c_list[MAX_IOQUERY];

static client *c_free_list_head = 0;

#include "client.c"
