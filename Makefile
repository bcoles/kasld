all :
	cc -Wall boot-config.c -o boot-config
	cc -Wall cmdline.c -o cmdline
	cc -Wall default.c -o default
	cc -Wall kallsyms.c -o kallsyms
	cc -Wall mincore.c -o mincore
	cc -Wall syslog.c -o syslog
	cc -Wall nf_conntrack.c -o nf_conntrack
	cc -Wall perf_event_open.c -o perf_event_open
	cc -Wall pppd_kallsyms.c -o pppd_kallsyms
	cc -Wall tsx-rtm.c -o tsx-rtm

clean :
	rm boot-config cmdline default kallsyms mincore nf_conntrack perf_event_open pppd_kallsyms syslog tsx-rtm

