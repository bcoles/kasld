all :
	cc -Wall src/boot-config.c -o boot-config
	cc -Wall src/cmdline.c -o cmdline
	cc -Wall src/default.c -o default
	cc -Wall src/kallsyms.c -o kallsyms
	cc -Wall src/mincore.c -o mincore
	cc -Wall src/free_reserved_area_dmesg.c -o free_reserved_area_dmesg
	cc -Wall src/free_reserved_area_syslog.c -o free_reserved_area_syslog
	cc -Wall src/nf_conntrack.c -o nf_conntrack
	cc -Wall src/perf_event_open.c -o perf_event_open
	cc -Wall src/pppd_kallsyms.c -o pppd_kallsyms
	cc -Wall src/tsx-rtm.c -o tsx-rtm
	cc -Wall extra/oops_inet_csk_listen_stop.c -o extra/oops_inet_csk_listen_stop
	cc -Wall extra/oops_netlink_getsockbyportid_null_ptr.c -o extra/oops_netlink_getsockbyportid_null_ptr

clean :
	rm boot-config
	rm cmdline
	rm default
	rm kallsyms
	rm mincore
	rm nf_conntrack
	rm perf_event_open
	rm pppd_kallsyms
	rm free_reserved_area_dmesg
	rm free_reserved_area_syslog
	rm tsx-rtm
	rm extra/oops_inet_csk_listen_stop
	rm extra/oops_netlink_getsockbyportid_null_ptr

