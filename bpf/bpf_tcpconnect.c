#include "vmlinux.h"
#include "api.h"
#include "bpf_types.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
int  _version __attribute__((section(("version")), used)) = 1;

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect msg = {0};

	msg.common.op = 1;
	perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	return 0;
}
