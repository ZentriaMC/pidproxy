#!/usr/bin/env bash
set -euo pipefail

pidproxy="${1:-../result/bin/pidproxy}"

testfiles="$(mktemp -d --tmpdir pidproxytest.XXXXXXXX)"
echo "testfiles='${testfiles}'"

pidfile="${testfiles}/pid"

script="${testfiles}/main"
install -m 755 /dev/stdin "${script}" <<EOF
#!${SHELL:-/usr/bin/env bash}
set -euo pipefail

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

"${pidproxy}" -H -r 2=15 -t -- "${pidfile}" "${launcher}" &
pp_pid="${!}"

sleep 0.5
kill -2 "${pp_pid}"
wait "${pp_pid}" || true

echo "removing test files"
rm -rf "${testfiles}"
