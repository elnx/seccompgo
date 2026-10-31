        A = arch
        if (A & 0x80000000) goto ok else goto kill_it
        ok:
        A = sys_number
        A == write ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
