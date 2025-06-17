#include <nemo/alloc.h>
#include <nemo/byte.h>

#include "dns.h"
#include "address4_vector.h"

#define BASE 30

#define	DATA_SIZE sizeof(address4_data)

static void init_data(address4_data va[], unsigned int i, unsigned int n)
{
  register address4_data *x;
  while (i < n) {
    x = &va[i];
    dns_domain_init(&x->name);
    i++;
  }
}

unsigned int address4_vector_realloc(register address4_vector *av, register unsigned int n)
{
  register unsigned int i;
  i = av->a;
  av->a = BASE + n + (n >> 3);
  if (alloc_re((void **)&(av->va), i * DATA_SIZE, av->a * DATA_SIZE)) {
    init_data(av->va, i, av->a);
    return 1;
  }
  av->a = i;
  return 0;
}

unsigned int address4_vector_alloc(register address4_vector *av, register unsigned int n)
{
  av->len = 0;
  av->a = BASE + n + (n >> 3);
  if ((av->va = (address4_data *) alloc(av->a * DATA_SIZE))) {
    init_data(av->va, 0, av->a);
    return 1;
  }
  return 0;
}

unsigned int address4_data_erase(address4_data *x)
{
  if (!dns_domain_erase(&x->name)) return 0;
  ip4_zero(&x->ip);
  byte_zero(x->location, 2);
  return 1;
}

unsigned int address4_vector_append(register address4_vector *av, const address4_data *a)
{
  register address4_data *cur;

  if (!address4_vector_readyplus(av, 1)) return 0;
  cur = &(av->va[av->len]);
  if (!dns_domain_copy(&cur->name, &a->name)) return 0;
  ip4_copy(&cur->ip, &a->ip);
  byte_copy(cur->location, 2, a->location);
  av->len++;  /* only do this after success */
  return 1;
}
