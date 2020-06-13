from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(text=r"""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, dev_t);

TRACEPOINT_PROBE(block, block_rq_issue) {
        u64 ts = bpf_ktime_get_ns();
        start.update(&args->dev, &ts);
        return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
        u64 *tsp, delta;

	tsp = start.lookup(&args->dev);
        if (tsp != 0) {
                delta = bpf_ktime_get_ns() - *tsp;
                bpf_trace_printk("%d\n",
                    delta / 1000);
                start.delete(&args->dev);
        }
        return 0;
}
""")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
	try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                print(msg)
                '''
                (bytes_s, bflags_s, us_s) = msg.split()

		if int(bflags_s, 16) & REQ_WRITE:
			type_s = b"W"
		elif bytes_s == "0":	# see blk_fill_rwbs() for logic
			type_s = b"M"
		else:
			type_s = b"R"
		ms = float(int(us_s, 10)) / 1000

		printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
                '''
	except KeyboardInterrupt:
		exit()
