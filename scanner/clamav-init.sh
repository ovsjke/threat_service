#!/bin/sh
set -eu
# Keep clamd and HTTP limits in sync without replacing the image's other defaults.
limit=${SCANNER_MAX_FILE_BYTES:-10485760}
case "$limit" in
  ''|*[!0-9]*) echo 'SCANNER_MAX_FILE_BYTES must be a positive integer' >&2; exit 1 ;;
esac
[ "$limit" -gt 0 ] || exit 1
sed -i '/^[#[:space:]]*StreamMaxLength[[:space:]]/d; /^[#[:space:]]*MaxFileSize[[:space:]]/d; /^[#[:space:]]*AlertExceedsMax[[:space:]]/d' /etc/clamav/clamd.conf
printf '\nStreamMaxLength %s\nMaxFileSize %s\nAlertExceedsMax yes\n' "$limit" "$limit" >> /etc/clamav/clamd.conf
exec /init
