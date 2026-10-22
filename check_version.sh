#!/usr/bin/env bash
# check_version.sh - flag PHP versions vulnerable to CVE-2026-109618/109619
# usage: ./check_version.sh http://TARGET [--insecure]
# created by 0verDo$ed

set -u

if [ $# -lt 1 ]; then
    echo "usage: $0 <url> [--insecure]"
    exit 1
fi

URL="$1"
INSEC="${2:-}"

CMD="curl -sk -I"
if [ "$INSEC" = "--insecure" ]; then
    CMD="curl -sk -I"
fi

HDRS="$($CMD "$URL")"

VER=$(printf '%s' "$HDRS" | grep -i "x-powered-by\|^Server:" \
    | grep -oP 'PHP/\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)

G='\033[92m'; R='\033[91m'; Y='\033[93m'; N='\033[0m'

if [ -z "$VER" ]; then
    echo -e "${Y}[?]${N} no PHP version header found on $URL"
    echo "    the server may hide expose_php, check manually:"
    echo "      curl -s $URL | grep -iE '<meta|generator'"
    exit 2
fi

MAJOR=${VER%%.*}
MINOR=$(echo "$VER" | cut -d. -f2)
PATCH=$(echo "$VER" | cut -d. -f3)
BRANCH="${MAJOR}.${MINOR}"

# branch table: vulnerable through -> fixed at
FIX_82="8.2.35"
FIX_83="8.3.36"
FIX_84="8.4.27"
FIX_85="8.5.12"

LZ=$(printf '%s\n' "$VER" | sort -V | head -1)

if [ "$MAJOR" -lt 8 ] 2>/dev/null || { [ "$MAJOR" -eq 8 ] && [ "$MINOR" -le 1 ]; }; then
    echo -e "${R}[!] $VER VULNERABLE${N} - EOL branch (5.4 - 8.1), no fix ever, upgrade branch"
    exit 0
fi

is_vuln() {
    # $1 = fixed version; vulnerable when $VER is smaller
    LT=$(printf '%s\n%s\n' "$VER" "$1" | sort -V | head -1)
    [ "$LT" = "$VER" ] && [ "$VER" != "$1" ]
}

case "$BRANCH" in
    8.2) if is_vuln "$FIX_82"; then
             echo -e "${R}[!] $VER VULNERABLE${N} - fixed at $FIX_82"
         else
             echo -e "${G}[+] $VER PATCHED${N} - at or past $FIX_82"
         fi ;;
    8.3) if is_vuln "$FIX_83"; then
             echo -e "${R}[!] $VER VULNERABLE${N} - fixed at $FIX_83"
         else
             echo -e "${G}[+] $VER PATCHED${N} - at or past $FIX_83"
         fi ;;
    8.4) if is_vuln "$FIX_84"; then
             echo -e "${R}[!] $VER VULNERABLE${N} - fixed at $FIX_84"
         else
             echo -e "${G}[+] $VER PATCHED${N} - at or past $FIX_84"
         fi ;;
    8.5) if is_vuln "$FIX_85"; then
             echo -e "${R}[!] $VER VULNERABLE${N} - fixed at $FIX_85"
         else
             echo -e "${G}[+] $VER PATCHED${N} - at or past $FIX_85"
         fi ;;
    *)   echo -e "${Y}[?] $VER${N} - future or unknown branch, check upstream advisory" ;;
esac
