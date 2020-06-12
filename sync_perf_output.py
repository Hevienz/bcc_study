from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(last);
BPF_PERF_OUTPUT(events);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            //bpf_trace_printk("%d\\n", delta / 1000000);
            struct data_t data = {};
            data.pid = bpf_get_current_pid_tgid();
            data.ts = bpf_ktime_get_ns();
            data.delta = delta / 1000000;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            events.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")
print("%-18s %-18s %-16s %-6s %s" % ("TIME(s)", "DELTA", "COMM", "PID", "MESSAGE"))

# format output
#start = 0
#while 1:
#    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
#    if start == 0:
#        start = ts
#    ts = ts - start
#    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))

start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-18.9f %-16s %-6d %s" % (time_s, event.delta, event.comm, event.pid,
        "Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()


