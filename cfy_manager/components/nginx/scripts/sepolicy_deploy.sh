#!/usr/bin/env sh

POLICY=${2}
PORTS=${3}

cd "${1}" || exit 1

[ -x /usr/sbin/semanage ] || exit 2

/usr/sbin/semodule -d "${POLICY}"
/bin/checkmodule -M -m -o "${POLICY}.mod" "${POLICY}.te"
/bin/semodule_package -o "${POLICY}.pp" -m "${POLICY}.mod"
/usr/sbin/semodule -i "${POLICY}.pp"

for P in ${PORTS} ; do
    /usr/sbin/semanage port -a -t "${POLICY}_port_t" -p tcp "${P}"
done
