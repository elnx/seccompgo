package audit

import (
	"fmt"
	"strings"

	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/explain"
)

func archUnchecked(analysis *explain.Analysis) []*Finding {
	if len(analysis.ArchValues()) == 0 {
		return []*Finding{{
			ID: "arch-unchecked", Severity: "high", Arch: nil,
			Title: "Architecture is never validated",
			Detail: "The filter checks syscall numbers without ever comparing data[4] (arch). " +
				"Numbers mean different syscalls under another AUDIT_ARCH, so the checks can be " +
				"dodged by invoking through a different ABI (e.g. i386 numbering on amd64).",
			Syscalls: []string{}, Condition: nil,
			Remediation: "Compare data[4] against your AUDIT_ARCH_* and KILL every " +
				"architecture you do not explicitly handle.",
		}}
	}
	for _, l := range analysis.OtherLeaves() {
		if explain.VerdictLabel(l.Ret) == "ALLOW" {
			return []*Finding{{
				ID: "arch-unchecked", Severity: "high", Arch: nil,
				Title: "Unlisted architectures reach ALLOW",
				Detail: "Some paths reach ALLOW on an architecture the filter does not explicitly " +
					"check, so a different-ABI call can slip past the syscall-number rules.",
				Syscalls: []string{}, Condition: nil,
				Remediation: "Compare data[4] against your AUDIT_ARCH_* and KILL every " +
					"architecture you do not explicitly handle.",
			}}
		}
	}
	return nil
}

func permissiveDefault(p *Policy) []*Finding {
	def, ok := p.DefaultLabel()
	if !ok || def != "ALLOW" {
		return nil
	}
	arch := p.ArchName()
	return []*Finding{{
		ID: "permissive-default", Severity: "high", Arch: &arch,
		Title: "Default action is ALLOW (denylist)",
		Detail: "Any syscall the filter does not explicitly block is allowed; a denylist is " +
			"bypassable by any syscall the author overlooked.",
		Syscalls: []string{}, Condition: nil,
		Remediation: "Use an allowlist: default to KILL/ERRNO and permit only the needed syscalls.",
	}}
}

func syscallAltGap(p *Policy) []*Finding {
	var out []*Finding
	for _, group := range altGroups {
		var present []string
		for _, name := range group.names {
			if p.Number(name) != nil {
				present = append(present, name)
			}
		}
		var denied, allowed []string
		for _, name := range present {
			nr := *p.Number(name)
			if p.ExplicitlyDenied(nr) {
				denied = append(denied, name)
			}
			if p.ReachableAsAllow(nr) {
				allowed = append(allowed, name)
			}
		}
		if len(denied) == 0 || len(allowed) == 0 {
			continue
		}
		severity := "medium"
		if group.name == "exec" || group.name == "open" {
			severity = "high"
		}
		arch := p.ArchName()
		syscalls := make([]string, 0, len(denied)+len(allowed))
		syscalls = append(syscalls, denied...)
		syscalls = append(syscalls, allowed...)
		out = append(out, &Finding{
			ID: "syscall-alt-gap", Severity: severity, Arch: &arch,
			Title: fmt.Sprintf("%s blocked but %s allowed",
				strings.Join(denied, "/"), strings.Join(allowed, "/")),
			Detail: fmt.Sprintf("%s denied, but the equivalent %s reaches ALLOW - "+
				"same capability, different syscall number.",
				strings.Join(denied, ", "), strings.Join(allowed, ", ")),
			Syscalls: syscalls, Condition: nil,
			Remediation: fmt.Sprintf("Deny every equivalent in the group: also block %s.",
				strings.Join(allowed, ", ")),
		})
	}
	return out
}

func firstAllowed(p *Policy, names []string) string {
	for _, name := range names {
		if nr := p.Number(name); nr != nil && p.ReachableAsAllow(*nr) {
			return name
		}
	}
	return ""
}

func orwChain(p *Policy) []*Finding {
	o := firstAllowed(p, orwOpen)
	r := firstAllowed(p, orwRead)
	w := firstAllowed(p, orwWrite)
	if o == "" || r == "" || w == "" {
		return nil
	}
	arch := p.ArchName()
	return []*Finding{{
		ID: "orw-chain", Severity: "high", Arch: &arch,
		Title: "A file can be opened and its contents copied out",
		Detail: fmt.Sprintf("%s, %s and %s all reach ALLOW, so the contents of an arbitrary file "+
			"(e.g. the flag) can be copied straight back out.", o, r, w),
		Syscalls: []string{o, r, w}, Condition: nil,
		Remediation: "Deny the open-family syscalls unless the program genuinely needs arbitrary files.",
	}}
}

func dangerousAllow(p *Policy) []*Finding {
	var out []*Finding
	for _, item := range dangerousFor(p.ArchSym) {
		nr := p.Number(item.name)
		if nr == nil || !p.ReachableAsAllow(*nr) {
			continue
		}
		arch := p.ArchName()
		out = append(out, &Finding{
			ID: "dangerous-allow", Severity: item.meta.severity, Arch: &arch,
			Title:    item.name + " is allowed",
			Detail:   fmt.Sprintf("%s reaches ALLOW - %s.", item.name, item.meta.why),
			Syscalls: []string{item.name}, Condition: p.ConditionFor(*nr, "ALLOW"),
			Remediation: fmt.Sprintf("Block %s unless the program genuinely needs it.", item.name),
		})
	}
	return out
}

func x32Guard(p *Policy) []*Finding {
	var sharp []string
	for _, name := range consts.SyscallNames("amd64") {
		if strings.HasPrefix(name, "x32_") {
			continue
		}
		x := p.Number("x32_" + name)
		if x == nil || !p.ReachableAsAllow(*x) {
			continue
		}
		native := p.Number(name)
		if native != nil && p.ReachableAsAllow(*native) {
			continue
		}
		sharp = append(sharp, name)
	}
	if len(sharp) == 0 {
		return nil
	}
	shown := sharp
	if len(shown) > 8 {
		shown = shown[:8]
	}
	more := ""
	if len(sharp) > len(shown) {
		more = fmt.Sprintf(", ... (+%d more)", len(sharp)-len(shown))
	}
	arch := p.ArchName()
	return []*Finding{{
		ID: "x32-guard", Severity: "high", Arch: &arch,
		Title: "x32 ABI is not guarded",
		Detail: fmt.Sprintf("Syscalls blocked by their native number are reachable via their x32 number "+
			"(nr | 0x40000000): %s%s.", strings.Join(shown, ", "), more),
		Syscalls: append([]string(nil), shown...), Condition: nil,
		Remediation: "After the arch check, KILL when sys_number >= 0x40000000 " +
			"(or jset 0x40000000).",
	}}
}
