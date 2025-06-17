#include "dns.h"

static void my_qsort(register mxip4_vector *v, register int left, register int right)
{
  register int i;
  register int last;
  if (left >= right) return;
  mxip4_vector_swap(v, (unsigned int)left, (unsigned int)(left + right)/2);
  last = left;
  for (i = left + 1; i <= right; i++) {
    if (mxip4_data_diff(&v->va[i], &v->va[left]) < 0) {
      mxip4_vector_swap(v, (unsigned int)++last, (unsigned int)i);
    }
  }
  mxip4_vector_swap(v, (unsigned int)left, (unsigned int)last);
  my_qsort(v, left, last - 1);
  my_qsort(v, last + 1, right);
}

void mxip4_vector_sort(register mxip4_vector *v)
{
  if (!v->len) return;
  my_qsort(v, 0, (int)v->len - 1);
}
