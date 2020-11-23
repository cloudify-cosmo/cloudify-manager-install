#!/usr/bin/env sh

POLICY=${2}
PORTS=${3}

echo "Setting up SELinux cloudify policy" | tee -a /tmp/sepolicy_deploy.log
cd "${1}" || exit 1

echo "Cleaning up previous ${POLICY} policy." | tee -a /tmp/sepolicy_deploy.log
/usr/sbin/semodule -d "${POLICY}" 2>&1 | tee -a /tmp/sepolicy_deploy.log

echo "Working in $( pwd )" | tee -a /tmp/sepolicy_deploy.log
/bin/checkmodule -M -m -o "${POLICY}.mod" "${POLICY}.te" 2>&1 | tee -a /tmp/sepolicy_deploy.log
/bin/semodule_package -o "${POLICY}.pp" -m "${POLICY}.mod" 2>&1 | tee -a /tmp/sepolicy_deploy.log
/usr/sbin/semodule -i "${POLICY}.pp" 2>&1 | tee -a /tmp/sepolicy_deploy.log

for P in ${PORTS} ; do
    /usr/sbin/semanage port -a -t "${POLICY}_port_t" -p tcp "${P}" 2>&1 | tee -a /tmp/sepolicy_deploy.log
done

echo "DONE" | tee -a /tmp/sepolicy_deploy.log
