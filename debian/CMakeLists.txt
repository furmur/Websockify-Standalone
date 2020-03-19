install(FILES websockify.default DESTINATION /etc/default RENAME websockify)
install(FILES websockify.logrotate DESTINATION /etc/logrotate.d RENAME websockify)
install(FILES websockify.rsyslog DESTINATION /etc/rsyslog.d RENAME websockify.conf)
