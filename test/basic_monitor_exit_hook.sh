#!/usr/bin/env bash
set -euo pipefail

# Monitors pid + runs post-exit script

pidproxy="${1:-../result/bin/pidproxy}"

testfiles="$(mktemp -d --tmpdir pidproxytest.XXXXXXXX)"
echo "testfiles='${testfiles}'"

pidfile="${testfiles}/pid"

script="${testfiles}/main"
install -m 755 /dev/stdin "${script}" <<EOF
#!${SHELL:-/usr/bin/env bash}
set -euo pipefail

echo "Sleeping for 3 seconds, and exiting gracefully"
date +%s
sleep 3
date +%s
exit 0
EOF


launcher="${testfiles}/launcher"
install -m 755 /dev/stdin "${launcher}" <<EOF
#!${SHELL:-/usr/bin/env bash}
set -euo pipefail

"${script}" &
pid="\${!}"
echo "\${pid}" > "${pidfile}"
EOF

hook="${testfiles}/exithook"
install -m 755 /dev/stdin "${hook}" <<EOF
#!${SHELL:-/usr/bin/env bash}
set -euo pipefail

env | grep '^PIDPROXY_'
EOF

"${pidproxy}" -t -g -E "${hook}" -- "${pidfile}" "${launcher}"

echo "removing test files"
rm -rf "${testfiles}"
