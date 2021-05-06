#include "vmlinux.h"
#include "api.h"
#include "bpf_types.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
int  _version __attribute__((section(("version")), used)) = 1;

__attribute__((section(("kprobe/__x64_sys_execve")), used))
int event_exec(struct pt_regs *__ctx)
{
	struct pt_regs *ctx = (struct pt_regs *)(__ctx->di);
	struct msg_execve msg = {0};
	struct task_struct *task;

	task = (struct task_struct *)get_current_task();

	msg.pid = (get_current_pid_tgid() >> 32);
	probe_read_str(&msg.filename, sizeof(msg.filename), &ctx->di);
	msg.common.op = 2;
	perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	return 0;
}
