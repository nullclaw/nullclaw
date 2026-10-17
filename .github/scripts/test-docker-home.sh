#!/bin/sh
set -eu

image=${1:?Usage: test-docker-home.sh IMAGE}
volume=

cleanup() {
    if [ -n "$volume" ]; then
        docker volume rm "$volume" >/dev/null
    fi
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Regression for #1017: the runtime COPY must leave HOME writable by uid 65534.
check_home() {
    docker run --rm "$@" --entrypoint sh "$image" -ec '
        test "$(id -u)" = 65534
        test "$HOME" = "$NULLCLAW_HOME"
        test -r "$HOME/config.json"
        test -d "$HOME/workspace"
        mkdir "$HOME/.home-permissions-test"
        printf "test\n" > "$HOME/.home-permissions-test/state"
        rm -r "$HOME/.home-permissions-test"
        echo "HOME is writable as uid 65534"
    '
}

check_home
volume=$(docker volume create)
check_home --mount "type=volume,source=$volume,target=/nullclaw-data"
echo "Docker HOME permissions passed for the image and a fresh named volume"
