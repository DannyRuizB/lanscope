#!/bin/sh
# LanScope container entrypoint (v1.54.0).
#
# The server, and every nmap it starts, run as the unprivileged `node` user.
# nmap still gets its raw sockets: the Dockerfile gives the binary file
# capabilities, and NMAP_PRIVILEGED tells nmap to use them (without it nmap
# only trusts uid 0 - measured: -sS and -O quit with "requires root
# privileges", and the ping sweep silently loses every MAC address).
#
# Up to v1.53.0 everything ran as root, so an existing data volume holds a
# root-owned database. Starting as root here lets us hand the database
# directory and the SQLite files to `node` once, then drop privileges for
# good with su-exec. Started as any other user (`user:` in compose,
# `docker run --user`), it just runs the command.
set -eu

if [ "$(id -u)" = "0" ]; then
  db="${DB_PATH:-/app/data/lanscope.db}"
  dir=$(dirname "$db")
  mkdir -p "$dir"
  # The directory and the SQLite files only, never a recursive walk: SQLite
  # needs the database, its WAL and shared-memory files, and the right to
  # create them in the directory. And only what `node` cannot write already:
  # a DB_PATH in a shared directory such as /tmp leaves the directory alone.
  if [ "$dir" = "/" ]; then
    echo "lanscope: DB_PATH=$db sits in / - not taking ownership of the root directory" >&2
    set -- "$db" "$db-wal" "$db-shm" "$db-journal" -- "$@"
  else
    set -- "$dir" "$db" "$db-wal" "$db-shm" "$db-journal" -- "$@"
  fi
  handed=""
  while [ "$1" != "--" ]; do
    if [ -e "$1" ] && ! su-exec node test -w "$1"; then
      chown node:node "$1"
      handed="$handed $1"
    fi
    shift
  done
  shift
  if [ -n "$handed" ]; then
    echo "lanscope: handed to the node user:$handed (written by LanScope <= 1.53, which ran as root)"
  fi
  exec su-exec node "$@"
fi

exec "$@"
