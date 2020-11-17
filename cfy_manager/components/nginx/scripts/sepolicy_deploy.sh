#!/usr/bin/env sh

PORTS=${2:-}

echo "Setting up SELinux cloudify policy" | tee -a /tmp/sepolicy_deploy.log
cd "${1}" || exit 1

echo "Cleaning up previous cloudify policy." | tee -a /tmp/sepolicy_deploy.log
/usr/sbin/semodule -d "cloudify" 2>&1 | tee -a /tmp/sepolicy_deploy.log

echo "Working in $( pwd )" | tee -a /tmp/sepolicy_deploy.log
/bin/checkmodule -M -m -o "cloudify.mod" "cloudify.te" 2>&1 | tee -a /tmp/sepolicy_deploy.log
/bin/semodule_package -o "cloudify.pp" -m "cloudify.mod" 2>&1 | tee -a /tmp/sepolicy_deploy.log
/usr/sbin/semodule -i "cloudify.pp" 2>&1 | tee -a /tmp/sepolicy_deploy.log

for P in ${PORTS} ; do
    /usr/sbin/semanage port -a -t "cloudify_port_t" -p tcp ${P} 2>&1 | tee -a /tmp/sepolicy_deploy.log
done

echo "DONE" | tee -a /tmp/sepolicy_deploy.log
