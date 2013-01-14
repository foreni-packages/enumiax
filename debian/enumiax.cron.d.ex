#
# Regular cron jobs for the enumiax package
#
0 4	* * *	root	[ -x /usr/bin/enumiax_maintenance ] && /usr/bin/enumiax_maintenance
