#!/bin/bash
systemctl start cb-lastline-connector
PID=$(cat /var/run/cb/integrations/cb-lastline-connector.pid)
while [ -e /proc/$PID ]
do
    echo "Process: $PID is still running" >> /dev/null
done