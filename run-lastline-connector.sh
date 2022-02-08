#!/bin/bash
LABEL=edrlastlineconnector
IMAGE=lastlineconnector/centos7:latest
FEED_PORT=6100
CONFIG_DIR_EXTERNAL=/etc/cb/integrations/lastline
CONFIG_DIR=/etc/cb/integrations/lastline
LOG_DIR_EXTERNAL=/var/log/cb/integrations/lastline
LOG_DIR=/var/log/cb/integrations/lastline
MOUNT_POINTS="--mount type=bind,source=$CONFIG_DIR_EXTERNAL,target=$CONFIG_DIR --mount type=bind,source=$LOG_DIR_EXTERNAL,target=$LOG_DIR"
SHUTDOWN_COMMAND="docker stop $LABEL"
STARTUP_COMMAND="docker run -d --rm $MOUNT_POINTS --name $LABEL $IMAGE"
STATUS_COMMAND=get_container_status

get_container_status () {
    CONTAINER_NAME=$(docker ps | grep $LABEL | head -n1 | awk '{print $1}')
    if [ "${#CONTAINER_NAME}" -gt 0 ]; then
        CONTAINER_RUNNING=true
        echo "EDR Lastline Container status: Running"
        echo "EDR Lastline Container identifier: ${CONTAINER_NAME}"
    else
        # run ps with -a switch to see if stopped or non-existent
        STOPPED_NAME=$(docker ps | grep $LABEL | head -n1 | awk '{print $1}')
        if [ "${#STOPPED_NAME}" -gt 0 ]; then
            echo "EDR Lastline Container status: Stopped "
        else
            echo "EDR Lastline Container status: No running container"
        fi
        CONTAINER_RUNNING=false
    fi
}


print_help() {
  echo "Usage: edr-lastline-connector-run COMMAND [options]"
  echo
  echo "Options:"
  echo "  -h, --help             Print this help message."
  echo
  echo "COMMANDs:"
  echo "  start        Start the connector"
  echo "  stop       Stop the connector"
  echo "  status         Stop the connector"
  exit 2
}

PARSED=$(getopt -n run -o o: --long osversion:,help -- "$@")

if [ "${?}" != "0" ]; then
  print_help
fi

if [[ "${1}" == "" ]]; then
  echo "COMMAND required"; print_help
fi

if [[ "${1^^}" =~ ^(START|STOP|STATUS)$ ]]; then
  echo "EDR Lastline Connector: running ${1}..."
  case "${1^^}" in
    START) $STARTUP_COMMAND ;;
    STOP) $SHUTDOWN_COMMAND ;;
    STATUS) $STATUS_COMMAND ;;
  esac
else
  echo "run: invalid command '${1}'"; print_help
fi
