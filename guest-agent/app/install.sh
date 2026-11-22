#!/bin/sh
# Installs or updates the Machbox guest agent and turns on automatic login
# for <user>. Machbox Setup runs it as root, from its Resources directory,
# with the user's password as the first line of stdin.
#
# usage: install.sh <resources-dir> <user>
#
# Exit status: 0 done, 2 usage, 3 wrong password, 4 FileVault is on (the
# agent is installed, automatic login is not), 1 anything else.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin

[ $# -eq 2 ] || { echo "usage: install.sh <resources-dir> <user>" >&2; exit 2; }
res=$1
user=$2
label=dev.machbox.guest
agent=/usr/local/libexec/machbox-guest
plist=/Library/LaunchDaemons/$label.plist

pw=
IFS= read -r pw || [ -n "$pw" ] || { echo "no password on stdin" >&2; exit 1; }
if ! dscl /Search -authonly "$user" "$pw" >/dev/null 2>&1; then
	echo "Wrong password for $user." >&2
	exit 3
fi

# install <src> <dst> <mode>: never rewrite a binary in place, a running or
# cached one must not change under its code signature.
tmp=
trap 'rm -f "$tmp"' EXIT
install_file() {
	tmp=$(mktemp "$(dirname "$2")/.machbox.XXXXXX")
	cp "$1" "$tmp"
	chown root:wheel "$tmp"
	chmod "$3" "$tmp"
	mv -f "$tmp" "$2"
	tmp=
}

# The daemon runs as root from $agent: whoever can write to its directory,
# or rename that away within its parent, can replace it.
root_only() {
	[ "$(stat -f %Su "$1")" = root ] && [ $(( 0$(stat -f %Lp "$1") & 022 )) -eq 0 ]
}
libexec=$(dirname "$agent")
for d in /usr /usr/local; do
	if [ -e "$d" ] && ! root_only "$d"; then
		echo "$d is writable by users other than root, so the agent could be replaced. Make it root-owned and not group- or world-writable, then install again." >&2
		exit 1
	fi
done

echo "Installing the agent"
launchctl bootout "system/$label" 2>/dev/null || true
mkdir -p "$libexec"
# Ours to fix: nothing else belongs in it.
chown root:wheel "$libexec"
chmod go-w "$libexec"
install_file "$res/machbox-guest" "$agent" 755
install_file "$res/$label.plist" "$plist" 644
# bootout returns before the service is gone; bootstrap fails until it is.
n=0
until launchctl bootstrap system "$plist" 2>/dev/null; do
	n=$((n + 1))
	[ $n -lt 10 ] || { echo "launchctl could not load $plist" >&2; exit 1; }
	sleep 1
done
launchctl kickstart -k "system/$label"

if [ "$(fdesetup isactive 2>/dev/null || true)" = true ]; then
	echo "FileVault is on, so automatic login cannot be. Turn FileVault off in System Settings, then install again." >&2
	exit 4
fi
echo "Turning on automatic login for $user"
# sysadminctl takes the password only as an argument.
sysadminctl -autologin set -userName "$user" -password "$pw" >/dev/null 2>&1
if [ "$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true)" != "$user" ]; then
	echo "sysadminctl could not turn on automatic login." >&2
	exit 1
fi
echo "Done"
