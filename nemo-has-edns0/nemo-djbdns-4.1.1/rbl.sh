RC=@PREFIX@/etc/rblrc
@PREFIX@/bin/rblcheck `[ -f "${RC}" ] && cat "${RC}";` $*
