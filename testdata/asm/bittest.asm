        A = sys_number
        if (A & 0x1) goto kill_it else goto allow
        allow:
        return ALLOW
        kill_it:
        return KILL
