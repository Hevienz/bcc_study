from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 *count, key = 0;
    u64 init = 1;

    count = last.lookup(&key);
    if (count == NULL) {
        count = &init;
        bpf_trace_printk("COUNT: %d\\n", *count);
        last.update(&key, count);
    } else {
        *count = *count + 1;
        bpf_trace_printk("COUNT: %d\\n", *count);
    }

    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's count... Ctrl-C to end")

while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print(task, pid, ts, msg)
