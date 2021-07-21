#!/usr/bin/env bash
set -euo pipefail

# Most common use-case of pidproxy - monitor a pid

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

echo "Launcher started; \$(date +%s)"
"${script}" &
pid="\${!}"
echo "\${pid}" > "${pidfile}"
echo "Launcher exiting; \$(date +%s)"
EOF

"${pidproxy}" -t -g -- "${pidfile}" "${launcher}"

echo "removing test files"
rm -rf "${testfiles}"
