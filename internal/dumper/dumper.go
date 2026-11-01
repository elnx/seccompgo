// Package dumper captures seccomp filters with ptrace, using only raw Linux system
// calls (no cgo).
package dumper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/elnx/seccompgo/internal/asm"
	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/logger"
	"github.com/elnx/seccompgo/internal/util"
)

// ptrace requests.
const (
	ptracePeekData         = 2
	ptraceAttach           = 16
	ptraceDetach           = 17
	ptraceSyscall          = 24
	ptraceReqSetOptions    = 0x4200
	ptraceGetRegset        = 0x4204
	ptraceSeccompGetFilter = 0x420c
	ptraceGetSyscallInfo   = 0x420e
	ntPrstatus             = 1
	ptraceOTraceSysgood    = 1 << 0
	ptraceOTraceFork       = 1 << 1
	ptraceOTraceVfork      = 1 << 2
	ptraceOTraceClone      = 1 << 3
	ptraceEventFork        = 1
	ptraceEventVfork       = 2
	ptraceEventClone       = 3
	sigStopCode            = 0x80
)

type abi struct {
	number     uint32
	args       [6]uint32
	ret        uint32
	sysPrctl   uint32
	sysSeccomp uint32
	bits       int
}

var abis = map[string]abi{
	"amd64": {
		number: 120, args: [6]uint32{112, 104, 96, 56, 72, 44}, ret: 80,
		sysPrctl: 157, sysSeccomp: 317, bits: 64,
	},
	"i386": {
		number: 44, args: [6]uint32{0, 4, 8, 12, 16, 20}, ret: 24,
		sysPrctl: 172, sysSeccomp: 354, bits: 32,
	},
	"aarch64": {
		number: 64, args: [6]uint32{0, 8, 16, 24, 32, 40}, ret: 0,
		sysPrctl: 167, sysSeccomp: 277, bits: 64,
	},
	"riscv64": {
		number: 136, args: [6]uint32{80, 88, 96, 104, 112, 120}, ret: 80,
		sysPrctl: 167, sysSeccomp: 277, bits: 64,
	},
	"s390x": {
		number: 24, args: [6]uint32{32, 40, 48, 56, 64, 72}, ret: 32,
		sysPrctl: 172, sysSeccomp: 348, bits: 64,
	},
}

// ptraceSyscallInfo mirrors struct ptrace_syscall_info; U holds the union.
type ptraceSyscallInfo struct {
	Op   uint8
	Pad  [3]byte
	Arch uint32
	IP   uint64
	SP   uint64
	U    [64]byte
}

func getSyscallInfo(pid int) (*ptraceSyscallInfo, error) {
	var info ptraceSyscallInfo
	_, errno := rawPtrace(ptraceGetSyscallInfo, pid, unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		return nil, errno
	}
	return &info, nil
}

func (s *ptraceSyscallInfo) entryNr() uint64 {
	return binary.NativeEndian.Uint64(s.U[0:8])
}

func (s *ptraceSyscallInfo) entryArgs() [6]uint64 {
	var args [6]uint64
	for i := range args {
		args[i] = binary.NativeEndian.Uint64(s.U[8+i*8:])
	}
	return args
}

func (s *ptraceSyscallInfo) exitRval() int64 {
	return int64(binary.NativeEndian.Uint64(s.U[0:8]))
}

// Supported reports whether tracer-based dumping is available (Linux only).
var Supported = true

// Result is one captured filter.
type Result struct {
	BPF  []byte
	Arch string
}

func rawPtrace(request uintptr, pid int, addr, data uintptr) (uintptr, syscall.Errno) {
	r, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, request, uintptr(pid), addr, data, 0, 0)
	return r, errno
}

func ptraceSetOptions(pid int, options uintptr) {
	rawPtrace(ptraceReqSetOptions, pid, 0, options)
}

func ptraceSyscallResume(pid int) {
	rawPtrace(ptraceSyscall, pid, 0, 0)
}

func peekData(pid int, addr uint64) uint64 {
	var word uint64
	_, errno := rawPtrace(ptracePeekData, pid, uintptr(addr), uintptr(unsafe.Pointer(&word)))
	if errno != 0 {
		return 0
	}
	return word
}

func peekUser(pid int, offset uint32, bits int) uint64 {
	if offset >= 4096 {
		return ^uint64(0)
	}
	width := bits / 8
	size := int(offset) + width
	buf := make([]byte, size)
	iov := struct {
		Base uintptr
		Len  uint64
	}{Base: uintptr(unsafe.Pointer(&buf[0])), Len: uint64(size)}
	r, errno := rawPtrace(ptraceGetRegset, pid, ntPrstatus, uintptr(unsafe.Pointer(&iov)))
	if errno != 0 || r == ^uintptr(0) || iov.Len < uint64(size) {
		return ^uint64(0)
	}
	if width == 4 {
		return uint64(binary.NativeEndian.Uint32(buf[offset:]))
	}
	return binary.NativeEndian.Uint64(buf[offset:])
}

// StrictBPF builds a filter equivalent to SECCOMP_MODE_STRICT for arch.
func StrictBPF(arch string) ([]byte, error) {
	sigreturn := "rt_sigreturn"
	if _, ok := consts.SyscallNum(arch, "sigreturn"); ok {
		sigreturn = "sigreturn"
	}
	src := "A = sys_number\n" +
		"A == read ? ok : next\n" +
		"A == write ? ok : next\n" +
		"A == exit ? ok : next\n" +
		"A == " + sigreturn + " ? ok : next\n" +
		"return KILL\n" +
		"ok:\n" +
		"return ALLOW\n"
	return asm.Asm(src, "-", arch)
}

type tracedSyscall struct {
	pid    int
	arch   string
	number uint64
	args   [6]uint64
	ret    uint64
}

func readSyscall(pid int) (*tracedSyscall, error) {
	arch := util.ProcessArch(pid)
	a, ok := abis[arch]
	if !ok {
		return nil, fmt.Errorf("Only supports amd64, i386, aarch64, riscv64, s390x")
	}
	s := &tracedSyscall{pid: pid, arch: arch}
	s.number = peekUser(pid, a.number, a.bits)
	for i, off := range a.args {
		s.args[i] = peekUser(pid, off, a.bits)
	}
	s.ret = peekUser(pid, a.ret, a.bits)
	return s, nil
}

func (s *tracedSyscall) filterMode(a abi) bool {
	if s.number == uint64(a.sysSeccomp) && s.args[0] == consts.SeccompSetModeFilter {
		return true
	}
	return s.number == uint64(a.sysPrctl) && s.args[0] == consts.PRSetSeccomp &&
		s.args[1] == consts.SeccompModeFilter
}

func (s *tracedSyscall) strictMode(a abi) bool {
	if s.number == uint64(a.sysSeccomp) && s.args[0] == consts.SeccompSetModeStrict {
		return true
	}
	return s.number == uint64(a.sysPrctl) && s.args[0] == consts.PRSetSeccomp &&
		s.args[1] == consts.SeccompModeStrict
}

func (s *tracedSyscall) setSeccomp(a abi) bool {
	return s.filterMode(a) || s.strictMode(a)
}

func (s *tracedSyscall) dumpBPF(a abi) ([]byte, error) {
	if s.strictMode(a) {
		return StrictBPF(s.arch)
	}
	addr := s.args[2]
	length := peekData(s.pid, addr) & 0xffff
	ptr := peekData(s.pid, addr+uint64(a.bits/8))
	if a.bits == 32 {
		ptr &= 0xffffffff
	}
	if length > 1<<20 {
		return nil, fmt.Errorf("implausible filter length %d", length)
	}
	out := make([]byte, 0, length*8)
	word := make([]byte, 8)
	for i := range length {
		v := peekData(s.pid, ptr+i*8)
		binary.NativeEndian.PutUint64(word, v)
		out = append(out, word...)
	}
	return out, nil
}

// Dump traces the command args and returns the filters it installs. limit stops after
// that many filters (negative: unlimited); timeout kills the target after that many
// seconds. It returns the filters captured before a timeout.
func Dump(args []string, limit int, timeout *float64) []Result {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := args[0]
	argv := args
	if len(args) == 1 && strings.ContainsAny(name, " \t\n*?{[~$<>()|&;\\'\"") {
		name = "/bin/sh"
		argv = []string{"/bin/sh", "-c", args[0]}
	}
	path := name
	if !strings.ContainsRune(name, '/') {
		if p, err := exec.LookPath(name); err == nil {
			path = p
		}
	}
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	proc, err := os.StartProcess(path, argv, &os.ProcAttr{
		Files: files,
		Sys:   &syscall.SysProcAttr{Ptrace: true},
	})
	if err != nil {
		logger.Error("Failed to execute " + strings.Join(args, " "))
		return nil
	}
	pid := proc.Pid

	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return nil
	}
	options := uintptr(ptraceOTraceSysgood | ptraceOTraceFork | ptraceOTraceVfork | ptraceOTraceClone)
	ptraceSetOptions(pid, options)
	ptraceSyscallResume(pid)

	collect := []Result{}
	var mu sync.Mutex
	pids := []int{pid}
	syscalls := map[int]*tracedSyscall{}
	fallbackSeen := map[int]bool{}
	stop := false
	addPID := func(p int) {
		mu.Lock()
		defer mu.Unlock()
		if slices.Contains(pids, p) {
			return
		}
		pids = append(pids, p)
	}
	killAll := func() {
		mu.Lock()
		snapshot := append([]int(nil), pids...)
		mu.Unlock()
		for _, p := range snapshot {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	}
	if timeout != nil {
		done := make(chan struct{})
		go func() {
			t := time.NewTimer(time.Duration(*timeout * float64(time.Second)))
			defer t.Stop()
			select {
			case <-t.C:
				killAll()
			case <-done:
			}
		}()
		defer close(done)
	}
	for {
		var st syscall.WaitStatus
		child, err := syscall.Wait4(-1, &st, 0, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return collect
		}
		addPID(child)
		if st.Stopped() {
			if st.StopSignal()&sigStopCode != 0 {
				handleSyscallStop(child, syscalls, fallbackSeen, &collect, &limit, &stop)
			}
			if !stop {
				ptraceSyscallResume(child)
			}
		} else {
			delete(syscalls, child)
		}
		if stop {
			killAll()
			for {
				if _, err := syscall.Wait4(-1, &st, 0, nil); err != nil {
					return collect
				}
			}
		}
	}

}

// handleSyscallStop records a syscall entry and checks a completed one for a seccomp
// installation, using PTRACE_GET_SYSCALL_INFO when available.
func handleSyscallStop(child int, syscalls map[int]*tracedSyscall, fallbackSeen map[int]bool, collect *[]Result, limit *int, stop *bool) {
	info, err := getSyscallInfo(child)
	if err == nil {
		switch info.Op {
		case 1: // PTRACE_SYSCALL_INFO_ENTRY
			arch := util.ProcessArch(child)
			if _, ok := abis[arch]; !ok {
				return
			}
			syscalls[child] = &tracedSyscall{
				pid: child, arch: arch, number: info.entryNr(), args: info.entryArgs(),
			}
		case 2: // PTRACE_SYSCALL_INFO_EXIT
			sys := syscalls[child]
			delete(syscalls, child)
			if sys == nil {
				return
			}
			a := abis[sys.arch]
			if sys.setSeccomp(a) && info.exitRval() == 0 {
				recordFilter(sys, a, collect, limit, stop)
			}
		}
		return
	}
	// Fallback for kernels without PTRACE_GET_SYSCALL_INFO: the first syscall stop
	// after the exec/fork event is the in-progress syscall's exit; skip it, then
	// alternate entry/exit.
	if !fallbackSeen[child] {
		fallbackSeen[child] = true
		return
	}
	sys := syscalls[child]
	if sys == nil {
		s, err := readSyscall(child)
		if err != nil {
			return
		}
		syscalls[child] = s
		return
	}
	delete(syscalls, child)
	cur, err := readSyscall(child)
	if err != nil {
		return
	}
	a := abis[sys.arch]
	if sys.setSeccomp(a) && cur.ret == 0 {
		recordFilter(sys, a, collect, limit, stop)
	}
}

func recordFilter(sys *tracedSyscall, a abi, collect *[]Result, limit *int, stop *bool) {
	bpf, err := sys.dumpBPF(a)
	if err != nil {
		return
	}
	*collect = append(*collect, Result{BPF: bpf, Arch: sys.arch})
	*limit--
	if *limit == 0 {
		*stop = true
	}
}

// DumpByPID reads installed filters from an existing process via
// PTRACE_SECCOMP_GET_FILTER (requires CAP_SYS_ADMIN).
func DumpByPID(pid, limit int) ([]Result, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	arch := util.ProcessArch(pid)
	if _, errno := rawPtrace(ptraceAttach, pid, 0, 0); errno != 0 {
		return nil, errno
	}
	defer rawPtrace(ptraceDetach, pid, 0, 0)
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
		return nil, err
	}
	var out []Result
	for i := 0; limit < 0 || i < limit; i++ {
		count, errno := rawPtrace(ptraceSeccompGetFilter, pid, uintptr(i), 0)
		if errno == syscall.ENOENT || errno == syscall.EINVAL {
			break
		}
		if errno != 0 {
			return nil, errno
		}
		n := int(count)
		if n < 0 || n > 1<<20 {
			return nil, fmt.Errorf("implausible filter length %d", n)
		}
		buf := make([]byte, n*8)
		if n > 0 {
			r, errno := rawPtrace(ptraceSeccompGetFilter, pid, uintptr(i), uintptr(unsafe.Pointer(&buf[0])))
			if errno != 0 {
				return nil, errno
			}
			if int(r) != n {
				return nil, errors.New("PTRACE_SECCOMP_GET_FILTER returned a short filter")
			}
		}
		out = append(out, Result{BPF: buf, Arch: arch})
	}
	return out, nil
}
