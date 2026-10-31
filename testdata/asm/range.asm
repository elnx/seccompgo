        A = sys_number
        A >= 0x40000000 ? chk : allow
        chk:
        A = args[0]
        A == 0x3 ? err : allow
        err:
        return ERRNO(7)
        allow:
        return ALLOW
