        A = arch
        A == ARCH_X86_64 ? amd64_rules : other_arch
        other_arch:
        A = sys_number
        A == 0x0 ? allow : kill_it
        amd64_rules:
        A = sys_number
        A == write ? allow : kill_it
        allow:
        return ALLOW
        kill_it:
        return KILL
