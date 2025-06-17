#include <nemo/stdint.h>
#include <nemo/unixtypes.h>
#include <nemo/unix.h>
#include <nemo/exit.h>
#include <nemo/install.h>
#include <nemo/macro_unused.h>

void hier(void);

int main(int argc __UNUSED__, char **argv __UNUSED__)
{
  umask(077);
  install_init();
  hier();
  _exit(0);
}
