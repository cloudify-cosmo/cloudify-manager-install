#!/bin/bash

CONTAINER_ID=$1
PERSISTENT_VOLUMES_PATH=$2

CLOUDIFY_MANAGER_RUN_CMD=$(docker run --name $CONTAINER_ID -d --restart unless-stopped -v /sys/fs/cgroup:/sys/fs/cgroup:ro --tmpfs /run --tmpfs /run/lock --security-opt seccomp:unconfined --cap-add SYS_ADMIN --network host docker-cfy-manager:latest 1> /dev/null)


function validate_docker() {
	which docker 1> /dev/null
	if [ $? -eq 0 ]
	then
		echo "Docker installed"
		docker image ls | grep docker-cfy-manager 1> /dev/null
		if [ $? -eq 1 ]
		then
			echo -e "\033[31mdocker-cfy-manager image could not be found.\e[0m"
			exit 2
		fi
	else
		echo -e "\033[31mDocker not installed!\e[0m"
		exit 1
	fi
}

function validate_users() {
	user_name=$1
	user_id=$2
	echo "Attemting to create user $user_name with id $user_id"
	USER_OUTPUT=$(id -u $user_name) 1> /dev/null
	if [ $? -eq 0 ]
	then
		if [ $USER_OUTPUT -eq $user_id ]
		then
			echo "User $user_name already exists with correct id"
		else
			echo -e "\033[31mUser $user_name doesn't have id $user_id\e[0m"
			exit 4
		fi
	else
		# User does not exist
		id -u $user_id 1> /dev/null
		if [ $? -ne 0 ]
		then
			# User id is available
			useradd -u $user_id $user_name 1> /dev/null
			echo "User $user_name created with id $user_id"
		else
			echo -e "\033[31mUser id $user_id is used by a different user\e[0m"
			exit 4
		fi
	fi
}

function start_cloudify_manager() {
	$CLOUDIFY_MANAGER_RUN_CMD
	if [ $? -ne 0 ]
	then
		echo -e "\033[31mUnable to start docker-cfy-manager, check docker logs\e[0m"
		exit 3
	fi
	docker exec -d ${CONTAINER_ID} systemctl stop postgresql-10 1> /dev/null
}

function create_and_copy_directories() {
	err=0
	trap 'err=1' ERR
	echo "Copying cloudify manager data to given persistent storage - '${PERSISTENT_VOLUMES_PATH}'"
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/10/data 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo -e "\033[31mCouldn't create directories in ${PERSISTENT_VOLUMES_PATH}\e[0m"
		exit $err
	fi
	err=0
	trap 'err=1' ERR
	docker cp ${CONTAINER_ID}:/var/lib/pgsql/10/data/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/10/data 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/manager/resources/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/mgmtworker/env/plugins/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/mgmtworker/work/deployments/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo -e "\033[31mCouldn't copy directories from ${CONTAINER_ID} to ${PERSISTENT_VOLUMES_PATH}\e[0m"
		exit $err
	fi
}

function change_ownership_and_permissions() {
	echo "Changing ownership and permissions on '${PERSISTENT_VOLUMES_PATH}'/cloudify-external-directories"
	err=0
	trap 'err=1' ERR
	chown -R postgres:226 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/10/data 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources/ 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins/ 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments/ 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo -e "\033[31mCouldn't change ownership\e[0m"
		exit $err
	fi
	err=0
	trap 'err=1' ERR
	chmod -R 700 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/10/data 1> /dev/null
	chmod -R 755 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources/ 1> /dev/null
	chmod -R 750 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins/ 1> /dev/null
	chmod -R 755 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments/ 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo -e "\033[31mCouldn't change permissions\e[0m"
		exit $err
	fi
	echo "Finished copying cloudify manager data to given persistent storage - '${PERSISTENT_VOLUMES_PATH}' successfully"
}

function stop_cloudify_manager() {
	docker stop ${CONTAINER_ID} 1> /dev/null
	echo "Container ${CONTAINER_ID} stopped"
	echo -e "\e[93mContainer ${CONTAINER_ID} has not been deleted for extra precautions, make sure you delete it!!!\e[0m"
}

if [ $# -ne 2 ]
then
  echo -e "\033[31m2 Arguments required: [ Container name, presistent volumes path ]\e[0m"
  exit 1
fi

validate_docker
start_cloudify_manager
validate_users postgres 26
validate_users cfyuser 999
create_and_copy_directories
change_ownership_and_permissions
stop_cloudify_manager

echo -e "\e[92mSuccessfully configured cloudify persistent storage\e[0m"
echo -e "\e[92mYou can start cloudify manager container with the proper volumes\e[0m"

# Once the docker environment is ready, make sure to delete the cloudify manager container and rerun it with the following command:
# <Docker command to start container…> -v <PERSISTENT_VOLUMES_PATH>/cloudify-external-directories/pgsql/10/data:/var/lib/pgsql/10/data:rw -v <PERSISTENT_VOLUMES_PATH>/cloudify-external-directories/manager/resources:/opt/manager/resources:rw -v <PERSISTENT_VOLUMES_PATH>/cloudify-external-directories/mgmtworker/env/plugins:/opt/mgmtworker/env/plugins:rw -v <PERSISTENT_VOLUMES_PATH>/cloudify-external-directories/mgmtworker/work/deployments:/opt/mgmtworker/work/deployments:rw
# You can use the container as you would any regular Cloudify Manager, kill and delete the container, rerun the container on the same host and everything will remain intact