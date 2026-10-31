        A = args[0]
        A &= 0xffff
        A == 0x5 ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
