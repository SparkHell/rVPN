#!/usr/bin/env bash
set -euo pipefail
installer="$(dirname "$(realpath "$0")")/install_server.py"
if ! command -v python3 >/dev/null; then
    [[ $EUID == 0 ]] || { echo '请使用 sudo 运行安装脚本'; exit 1; }
    read -rp '安装脚本需要 Python 3，使用 apt 安装？[Y/n] ' answer
    [[ -z $answer || $answer == [yY] ]] || exit 1
    apt-get update
    apt-get install -y python3
fi
exec python3 "$installer" "$@"
