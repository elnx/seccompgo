package emulator_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/elnx/seccompgo/internal/asm"
	"github.com/elnx/seccompgo/internal/bpf"
	"github.com/elnx/seccompgo/internal/consts"
	"github.com/elnx/seccompgo/internal/disasm"
	"github.com/elnx/seccompgo/internal/emulator"
	"github.com/elnx/seccompgo/internal/instruction"
)

func instsOf(t *testing.T, raw []byte, arch string) []instruction.Inst {
	t.Helper()
	codes, err := disasm.ToBPF(raw, arch)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]instruction.Inst, 0, len(codes))
	for _, c := range codes {
		i, err := instruction.New(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, i)
	}
	return out
}

func asmInsts(t *testing.T, src, arch string) []instruction.Inst {
	t.Helper()
	raw, err := asm.Asm(src, "", arch)
	if err != nil {
		t.Fatal(err)
	}
	return instsOf(t, raw, arch)
}

func fixtureEmu(t *testing.T, name, arch string) ([]instruction.Inst, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "data", name))
	if err != nil {
		t.Fatal(err)
	}
	return instsOf(t, raw, arch), raw
}

func TestEmulatorReturnTypes(t *testing.T) {
	ret, _ := instruction.New(bpf.FromFields(consts.Command["ret"], 0, 0, 0x12345678, "amd64", 0))
	res, err := emulator.New([]instruction.Inst{ret}, nil, nil, nil, "amd64").Run()
	if err != nil || !res.HasRet || res.Ret != 0x12345678 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	ld, _ := instruction.New(bpf.FromFields(consts.Command["ld"], 0, 0, 0xdeadbeef, "amd64", 0))
	retA, _ := instruction.New(bpf.FromFields(consts.Command["ret"]|consts.Src["a"], 0, 0, 0, "amd64", 0))
	res, err = emulator.New([]instruction.Inst{ld, retA}, nil, nil, nil, "amd64").Run()
	if err != nil || res.Ret != 0xdeadbeef {
		t.Fatalf("A ret=%+v err=%v", res, err)
	}
}

func TestEmulatorDiary(t *testing.T) {
	insts, _ := fixtureEmu(t, "twctf-2016-diary.bpf", "amd64")
	res, err := emulator.New(insts, new(uint64(1)), nil, nil, "amd64").Run()
	if err != nil || res.Ret != 0x7fff0000 {
		t.Fatalf("allow: %+v %v", res, err)
	}
	res, err = emulator.New(insts, new(uint64(59)), nil, nil, "amd64").Run()
	if err != nil || res.Ret != 0 {
		t.Fatalf("kill: %+v %v", res, err)
	}
	_, err = emulator.New(insts, nil, nil, nil, "amd64").Run()
	var undef *emulator.UndefinedVariableError
	if !errors.As(err, &undef) {
		t.Fatalf("error type %T", err)
	}
	want := "Undefined Variable\n\t0000: A = sys_number <- `sys_number` is undefined"
	if err.Error() != want {
		t.Fatalf("got %q", err.Error())
	}
}

func TestEmulatorI386Args(t *testing.T) {
	insts, _ := fixtureEmu(t, "CONFidence-2017-amigo.bpf", "i386")
	res, err := emulator.New(insts, new(uint64(4)), nil, nil, "i386").Run()
	if err != nil || res.Ret != 0x7fff0000 {
		t.Fatalf("i386 allow: %+v %v", res, err)
	}
	res, err = emulator.New(insts, new(uint64(4)), []uint64{0, 0, 0, 0, 0, 0}, nil, "amd64").Run()
	if err != nil || res.Ret != 0 {
		t.Fatalf("amd64 args0: %+v %v", res, err)
	}
	res, err = emulator.New(insts, new(uint64(4)), []uint64{0, 0, 0, 0, 0, 0x313373133731337}, nil, "amd64").Run()
	if err != nil || res.Ret != 0x7fff0000 {
		t.Fatalf("amd64 args1: %+v %v", res, err)
	}
}

func TestEmulatorMiscALU(t *testing.T) {
	insts, _ := fixtureEmu(t, "misc_alu.bpf", "i386")
	for _, tc := range []struct {
		sys, ip uint64
		want    uint32
	}{
		{0, 0x123, 0},
		{1, 0x12300000edd, 0},
		{137, 0x12300000edd, 0x7fff0000},
	} {
		res, err := emulator.New(insts, new(uint64(tc.sys)), nil, new(uint64(tc.ip)), "i386").Run()
		if err != nil || res.Ret != tc.want {
			t.Fatalf("sys=%d ip=%x res=%+v err=%v", tc.sys, tc.ip, res, err)
		}
	}
}

func TestEmulatorDivisionByZero(t *testing.T) {
	insts := asmInsts(t, "A = 0\nX = A\nA /= X\nreturn ALLOW\n", "amd64")
	res, err := emulator.New(insts, nil, nil, nil, "amd64").Run()
	if err != nil {
		t.Fatal(err)
	}
	if res.Ret != 0 || res.PC != 2 {
		t.Fatalf("res=%+v", res)
	}
}

func TestEmulatorBdooos(t *testing.T) {
	insts, _ := fixtureEmu(t, "DEF-CON-2020-bdooos.bpf", "aarch64")
	res, err := emulator.New(insts, new(uint64(64)), nil, nil, "aarch64").Run()
	if err != nil || res.Ret != 0x7fff0000 {
		t.Fatalf("allow: %+v %v", res, err)
	}
	res, err = emulator.New(insts, new(uint64(221)), nil, nil, "aarch64").Run()
	if err != nil || res.Ret != 0x80000000 {
		t.Fatalf("kill: %+v %v", res, err)
	}
}

func TestEmulatorRiscv(t *testing.T) {
	raw := []byte(
		"\x20\x00\x00\x00\x04\x00\x00\x00" +
			"\x15\x00\x00\x05\xf3\x00\x00\xc0" +
			"\x20\x00\x00\x00\x00\x00\x00\x00" +
			"\x15\x00\x02\x00\x02\x01\x00\x00" +
			"\x15\x00\x01\x00\x03\x01\x00\x00" +
			"\x06\x00\x00\x00\x00\x00\x00\x80" +
			"\x06\x00\x00\x00\x00\x00\xff\x7f" +
			"\x06\x00\x00\x00\x00\x00\x00\x00")
	insts := instsOf(t, raw, "riscv64")
	res, err := emulator.New(insts, new(uint64(258)), nil, nil, "riscv64").Run()
	if err != nil || res.Ret != 0x7fff0000 {
		t.Fatalf("allow: %+v %v", res, err)
	}
	res, _ = emulator.New(insts, new(uint64(63)), nil, nil, "riscv64").Run()
	if res.Ret != 0x80000000 {
		t.Fatalf("kill: %+v", res)
	}
	res, _ = emulator.New(insts, new(uint64(258)), nil, nil, "amd64").Run()
	if res.Ret != 0 {
		t.Fatalf("amd64 kill: %+v", res)
	}
}

func TestEmulatorBigEndian(t *testing.T) {
	src := `A = data[32]
A == 0x11223344 ? next : allow
A = data[36]
A == 0x55667788 ? kill : allow
allow:
return ALLOW
kill:
return KILL
`
	insts := asmInsts(t, src, "s390x")
	res, err := emulator.New(insts, new(uint64(4)), []uint64{0, 0, 0x1122334455667788}, nil, "s390x").Run()
	if err != nil || res.Ret != 0 {
		t.Fatalf("be allow: %+v %v", res, err)
	}
	res, _ = emulator.New(insts, new(uint64(4)), []uint64{0, 0, 0x5566778811223344}, nil, "s390x").Run()
	if res.Ret != 0x7fff0000 {
		t.Fatalf("be swapped: %+v", res)
	}
	insts = asmInsts(t, src, "amd64")
	res, _ = emulator.New(insts, new(uint64(4)), []uint64{0, 0, 0x1122334455667788}, nil, "amd64").Run()
	if res.Ret != 0x7fff0000 {
		t.Fatalf("le: %+v", res)
	}

	ipSrc := `A = data[8]
A == 0xdead ? next : allow
A = data[12]
A == 0xbeef ? kill : allow
allow:
return ALLOW
kill:
return KILL
`
	insts = asmInsts(t, ipSrc, "s390x")
	res, _ = emulator.New(insts, nil, nil, new(uint64(0xdead0000beef)), "s390x").Run()
	if res.Ret != 0 {
		t.Fatalf("be ip: %+v", res)
	}
	res, _ = emulator.New(insts, nil, nil, new(uint64(0xbeef0000dead)), "s390x").Run()
	if res.Ret != 0x7fff0000 {
		t.Fatalf("be ip swapped: %+v", res)
	}
}

func TestEmulatorSimpleReturn(t *testing.T) {
	insts := asmInsts(t, "return ALLOW\n", "amd64")
	res, err := emulator.New(insts, nil, nil, nil, "amd64").Run()
	if err != nil || !res.HasRet || res.Ret != 0x7fff0000 {
		t.Fatalf("%+v %v", res, err)
	}
}
