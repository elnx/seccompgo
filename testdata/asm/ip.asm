        A = data[8]
        A == 0x31337000 ? next : kill_it
        A = data[12]
        A == 0x7fff ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
