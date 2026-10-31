        A = arch
        A == 0x14 ? chk : kill_it
        chk:
        A = sys_number
        A == 0x3 ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
