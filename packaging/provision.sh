#!/usr/bin/env bash

function create_install_rpm() {
    curl -L https://raw.githubusercontent.com/cloudify-cosmo/cloudify-manager-install/${MANAGER_INSTALL_BRANCH}/packaging/create_rpm -o /tmp/create_rpm
    chmod +x /tmp/create_rpm
    echo "/tmp/create_rpm --edition ${EDITION} --skip-pip-install --branch ${CORE_BRANCH} --installer-branch ${MANAGER_INSTALL_BRANCH} ${DEV_BRANCH_PARAM}"
    /tmp/create_rpm --edition ${EDITION} --skip-pip-install --branch ${CORE_BRANCH} --installer-branch ${MANAGER_INSTALL_BRANCH} ${DEV_BRANCH_PARAM}
}

export CORE_TAG_NAME="4.5"
export CORE_BRANCH="master"
AWS_ACCESS_KEY_ID=$1
AWS_ACCESS_KEY=$2
export REPO=$3
export GITHUB_USERNAME=$4
export GITHUB_PASSWORD=$5
export DEV_BRANCH=$6

if [ "${REPO}" == "cloudify-versions" ]; then
    export EDITION="community"
else
    export EDITION="premium"
fi

curl -u $GITHUB_USERNAME:$GITHUB_PASSWORD https://raw.githubusercontent.com/cloudify-cosmo/${REPO}/${CORE_BRANCH}/packages-urls/common_build_env.sh -o ./common_build_env.sh &&
source common_build_env.sh &&
curl https://raw.githubusercontent.com/cloudify-cosmo/cloudify-common/${CORE_BRANCH}/packaging/common/provision.sh -o ./common-provision.sh &&
source common-provision.sh

export MANAGER_INSTALL_BRANCH=${CORE_BRANCH}
export DEV_BRANCH_PARAM=""
if [[ ! -z $DEV_BRANCH ]] && [[ "$DEV_BRANCH" != "master" ]];then
    export DEV_BRANCH_PARAM=" --dev-branch $DEV_BRANCH"
    AWS_S3_PATH="$AWS_S3_PATH/$DEV_BRANCH"
    pushd /tmp
        curl -sLO https://github.com/cloudify-cosmo/cloudify-manager-install/archive/${DEV_BRANCH}.zip
        if zip -T $DEV_BRANCH.zip > /dev/null; then
            export MANAGER_INSTALL_BRANCH="$DEV_BRANCH"
        fi
        rm -f ${DEV_BRANCH}.zip
    popd
fi
echo "AWS_S3_PATH=$AWS_S3_PATH"

install_common_prereqs &&
create_install_rpm &&
cd /tmp && create_md5 "rpm" &&
[ -z ${AWS_ACCESS_KEY} ] || upload_to_s3 "rpm" && upload_to_s3 "md5"
