#include <nemo/exit.h>
#include <nemo/macro_unused.h>

void hier(void);

int main(int argc __UNUSED__, char **argv __UNUSED__)
{
  hier();
  _exit(0);
}
