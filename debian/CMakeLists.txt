install(FILES virtualizm-wsproxy.default DESTINATION /etc/default RENAME virtualizm-wsproxy)
install(FILES virtualizm-wsproxy.logrotate DESTINATION /etc/logrotate.d RENAME virtualizm-wsproxy)
install(FILES virtualizm-wsproxy.rsyslog DESTINATION /etc/rsyslog.d RENAME virtualizm-wsproxy.conf)
