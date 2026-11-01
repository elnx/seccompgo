# seccomp-tools (Go)

`seccomp-tools` 的纯 Go 复刻，与上游 Ruby 实现功能一致，面向 Linux。
不使用 cgo：`dump` 基于原始 `ptrace` 系统调用实现。

## 安装

```bash
go install github.com/elnx/seccompgo/cmd/seccomp-tools@latest
```

`go install` 会把二进制写到 `GOBIN`，未设置时是 `$(go env GOPATH)/bin`；确保该目录在 `PATH` 中：

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

需要 Go 1.27+。固定版本把 `@latest` 换成对应 tag（如 `@v0.2.0`）；从源码安装用
`make install`。二进制名与上游 Ruby gem 相同，两者共存时注意 `PATH` 优先级。

## 构建

```bash
make            # 输出 bin/seccomp-tools
make test       # 运行全部测试
make generate   # 从 ../seccomp-tools 的 Ruby 表重新生成 syscall 数据
```

需要 Go 1.27+（生成代码与 `new(expr)` 的使用）。仅支持 Linux。

## 命令

```bash
seccomp-tools asm IN_FILE [options]
seccomp-tools disasm BPF_FILE [options]
seccomp-tools dump [EXEC] [options]
seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 ... arg5]]
seccomp-tools explain [options] [BPF_FILE|EXEC]
seccomp-tools audit [options] [BPF_FILE|EXEC]
seccomp-tools completion <bash|zsh|fish>
```

选项、输出格式、退出行为与上游一致，包括：

- `asm` 的 `inspect`、`raw`、`c_array`、`c_source`、`assembly` 格式与标签/跳转语法；
- `disasm` 的 syscall/参数推断、`--asm-able`；
- `emu` 的执行路径输出与返回值解析；
- `explain` 的按架构/动作分组、64 位参数条件融合；
- `audit` 的 `human`/`json` 报告、堆叠过滤器提示；
- `dump` 的 `ptrace` 多过滤器、超时、strict 模式与 `--pid`。

## 目录

- `cmd/seccomp-tools`：入口。
- `internal/asm`：扫描器、递归下降解析器、编译器。
- `internal/bpf`、`internal/instruction`：BPF 指令与反汇编逻辑。
- `internal/symbolic`：符号表达式、路径约束、执行器。
- `internal/explain`、`internal/audit`：策略总结与弱点扫描。
- `internal/dumper`：纯 Go `ptrace` 抓取。
- `internal/consts`：BPF 常量与生成的 syscall 表。
- `internal/cli`：命令行接口与 shell 补全。
