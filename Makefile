all :
	cc -Wall boot-config.c -o boot-config
	cc -Wall cmdline.c -o cmdline
	cc -Wall default.c -o default
	cc -Wall kallsyms.c -o kallsyms
	cc -Wall mincore.c -o mincore
	cc -Wall free_reserved_area_dmesg.c -o free_reserved_area_dmesg
	cc -Wall free_reserved_area_syslog.c -o free_reserved_area_syslog
	cc -Wall nf_conntrack.c -o nf_conntrack
	cc -Wall perf_event_open.c -o perf_event_open
	cc -Wall pppd_kallsyms.c -o pppd_kallsyms
	cc -Wall tsx-rtm.c -o tsx-rtm

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

