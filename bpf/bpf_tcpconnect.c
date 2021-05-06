#include "vmlinux.h"
#include "api.h"
#include "bpf_types.h"

char _license[] __attribute__((section(("license")), used)) = "GPL";
int  _version __attribute__((section(("version")), used)) = 1;

__attribute__((section(("kprobe/tcp_connect")), used))
int event_ipv4_connect(struct pt_regs *ctx)
{
	struct msg_ipv4_tcp_connect msg = {0};
	struct sock *skp;

	msg.common.op = 1;

        skp = (void *)((ctx)->di);

        probe_read(&msg.proto, sizeof(msg.proto), &(skp->__sk_common.skc_family));
        probe_read(&msg.saddr, sizeof(msg.saddr), &(skp->__sk_common.skc_rcv_saddr));
        probe_read(&msg.daddr, sizeof(msg.daddr), &(skp->__sk_common.skc_daddr));
        probe_read(&msg.dport, sizeof(msg.dport), &(skp->__sk_common.skc_dport));
        probe_read(&msg.sport, sizeof(msg.sport), &(skp->__sk_common.skc_num));

	perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	return 0;
}
