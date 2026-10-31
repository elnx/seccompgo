package explain

import (
	"fmt"
	"strings"

	"seccompgo/internal/consts"
	"seccompgo/internal/symbolic"
)

// VerdictOrder is the order buckets are printed in; unlisted actions sort last.
var VerdictOrder = []string{
	"ALLOW", "USER_NOTIF", "LOG", "TRACE", "TRAP", "ERRNO", "KILL", "KILL_PROCESS", "UNKNOWN",
}

// VerdictLabel names the value a leaf returns.
func VerdictLabel(ret *symbolic.Expr) string {
	if !ret.IsImm() {
		return "UNKNOWN"
	}
	if label, ok := consts.ActionLabel(ret.Val()); ok {
		return label
	}
	return fmt.Sprintf("KILL_PROCESS (unknown action 0x%x)", ret.Val())
}

// VerdictRank is the bucket sort key: action order, then label.
func VerdictRank(label string) (int, string) {
	action := actionOf(label)
	idx := len(VerdictOrder)
	for i, a := range VerdictOrder {
		if a == action {
			idx = i
			break
		}
	}
	return idx, label
}

// actionOf strips any "(data)" or " (annotation)" suffix from a label.
func actionOf(label string) string {
	if i := strings.IndexByte(label, '('); i >= 0 {
		return strings.TrimRight(label[:i], " ")
	}
	return label
}
