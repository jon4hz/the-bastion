#!/bin/sh
# vim: set filetype=sh ts=4 sw=4 sts=4 et:
if [ "$USER" != "bastionsync" ]; then
    echo "Unexpected user, aborting" >&2
    exit 2
fi
if [ -z "$SSH_CONNECTION" ]; then
    echo "Bad environment, aborting" >&2
    exit 3
fi
if [ "$1" != "-c" ]; then
    echo "Interactive session denied, aborting" >&2
    exit 4
fi
shift
# shellcheck disable=SC2068
set -- $@

# Debug: log what we received (remove this in production)
echo "DEBUG: Received command: $*" >&2
echo "DEBUG: \$1='$1' \$2='$2' \$3='$3' \$4='$4'" >&2

# Check for allowed commands
if [ "$1 $2" = "rsync --server" ]; then
    # Handle rsync commands
    shift
    shift
    if ! cd /; then
        echo "Failed to chdir /, aborting" >&2
        exit 6
    fi
    exec /usr/bin/sudo -- /usr/bin/rsync --server "$@"
elif [ "$1" = "test" ] && [ "$2" = "-d" ] && [ "$3" = "/etc/ssh/sshd_config.forward.d" ]; then
    # Allow checking if SSH config directory exists
    exec test -d /etc/ssh/sshd_config.forward.d
elif [ "$*" = "test -d /etc/ssh/sshd_config.forward.d" ]; then
    # Handle case where command comes as single argument
    exec test -d /etc/ssh/sshd_config.forward.d
elif [ "$1" = "sudo" ] && [ "$2" = "systemctl" ] && [ "$3" = "reload" ] && [ "$4" = "sshd" ]; then
    # Allow reloading sshd via systemctl
    exec /usr/bin/sudo systemctl reload sshd
elif [ "$1" = "sudo" ] && [ "$2" = "systemctl" ] && [ "$3" = "reload" ] && [ "$4" = "ssh" ]; then
    # Allow reloading ssh service via systemctl
    exec /usr/bin/sudo systemctl reload ssh
elif [ "$1" = "sudo" ] && [ "$2" = "service" ] && [ "$3" = "ssh" ] && [ "$4" = "reload" ]; then
    # Allow reloading ssh via service command
    exec /usr/bin/sudo service ssh reload
elif [ "$1" = "sudo" ] && [ "$2" = "service" ] && [ "$3" = "sshd" ] && [ "$4" = "reload" ]; then
    # Allow reloading sshd via service command
    exec /usr/bin/sudo service sshd reload
elif [ "$1" = "sudo" ] && [ "$2" = "/etc/init.d/ssh" ] && [ "$3" = "reload" ]; then
    # Allow reloading ssh via init.d
    exec /usr/bin/sudo /etc/init.d/ssh reload
elif [ "$1" = "sudo" ] && [ "$2" = "/etc/init.d/sshd" ] && [ "$3" = "reload" ]; then
    # Allow reloading sshd via init.d
    exec /usr/bin/sudo /etc/init.d/sshd reload
elif [ "$*" = "sudo systemctl reload sshd" ]; then
    # Handle systemctl sshd reload as single argument
    exec /usr/bin/sudo systemctl reload sshd
elif [ "$*" = "sudo systemctl reload ssh" ]; then
    # Handle systemctl ssh reload as single argument
    exec /usr/bin/sudo systemctl reload ssh
elif [ "$*" = "sudo service ssh reload" ]; then
    # Handle service ssh reload as single argument
    exec /usr/bin/sudo service ssh reload
elif [ "$*" = "sudo service sshd reload" ]; then
    # Handle service sshd reload as single argument
    exec /usr/bin/sudo service sshd reload
elif [ "$*" = "sudo /etc/init.d/ssh reload" ]; then
    # Handle init.d ssh reload as single argument
    exec /usr/bin/sudo /etc/init.d/ssh reload
elif [ "$*" = "sudo /etc/init.d/sshd reload" ]; then
    # Handle init.d sshd reload as single argument
    exec /usr/bin/sudo /etc/init.d/sshd reload
else
    echo "Only rsync and sshd reload commands are allowed, aborting" >&2
    exit 5
fi
