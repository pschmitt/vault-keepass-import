#!/usr/bin/env bash

cd "$(cd "$(dirname "$0")" >/dev/null 2>&1; pwd -P)" || exit 9A

set -x

docker run -it --rm -v "$PWD:/app" pschmitt/pyinstaller:3.7 keepass_import.py

case "$1" in
  push|--push|-p)
    scp ./dist/keepass_import core@scheduler.dt.ept.lu:/srv/rundeck/scripts
esac
