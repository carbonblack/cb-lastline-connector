#!/bin/bash
/usr/share/cb/integrations/lastline/bin/cb-lastline-connector start
PID=$(cat /var/run/cb/integrations/cb-lastline-connector.pid)
while [ -e /proc/$PID ]
do
    echo "Process: $PID is still running" >> /dev/null
    sleep 1
done