#!/bin/sh
# Keep the bubble's name on the house's public IPv4 through deSEC's dynDNS
# endpoint. The IP has changed before, and every certificate and config
# that named it broke. Run by desec-ddns.timer every five minutes; it calls
# deSEC only when the address has actually moved.
#
# From /etc/desec-ddns.env (root, mode 600):
#   DESEC_DOMAIN   the domain at deSEC            example.org
#   DESEC_HOST     the name to point at the house  home.example.org (default: DESEC_DOMAIN)
#   DESEC_TOKEN    a deSEC token for that domain
set -eu
: "${DESEC_DOMAIN:?}" "${DESEC_TOKEN:?}"
host="${DESEC_HOST:-$DESEC_DOMAIN}"
state="${STATE_DIRECTORY:-/var/lib/desec-ddns}/last"

ip=$(curl -fsS --max-time 10 https://checkipv4.dedyn.io/)
case "$ip" in
    *[!0-9.]*|"") echo "no usable IPv4 from checkipv4.dedyn.io: '$ip'" >&2; exit 1 ;;
esac
if [ -f "$state" ] && [ "$(cat "$state")" = "$ip" ]; then
    exit 0
fi

# The token goes to curl on stdin, not on its command line, where any user
# could read it from the process list.
printf 'user = "%s:%s"\n' "$DESEC_DOMAIN" "$DESEC_TOKEN" |
    curl -fsS --max-time 20 -K - \
        "https://update.dedyn.io/?hostname=$host&myipv4=$ip&myipv6=preserve"
echo
mkdir -p "$(dirname "$state")"
echo "$ip" > "$state"
echo "$host -> $ip"
