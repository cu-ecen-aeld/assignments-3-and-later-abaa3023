#! /bin/sh

case "$1" in
    start)
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
        /usr/bin/aesdchar_load
        ;;
    stop)
        start-stop-daemon -K -n aesdsocket
        /usr/bin/aesdchar_unload
        ;;
    *)
    exit 1

esac
exit 0
