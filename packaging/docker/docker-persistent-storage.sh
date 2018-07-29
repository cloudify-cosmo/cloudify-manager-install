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
			echo "docker-cfy-manager image could not be found." >&2
			exit 2
		fi
	else
		echo "Docker not installed!" >&2
		exit 1
	fi
}

function validate_users() {
	user_name=$1
	user_id=$2
	echo "Attemting to create user $user_name with id $user_id"
	USER_OUTPUT=$(id -u $user_name 2> /dev/null)
	if [ $? -eq 0 ]
	then
		if [ $USER_OUTPUT -eq $user_id ]
		then
			echo "User $user_name already exists with correct id"
		else
			echo "User $user_name doesn't have id $user_id >&2"
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
			echo "User id $user_id is used by a different user"
			exit 4
		fi
	fi
}

function change_ownership_and_permissions() {
	echo "Copying cloudify manager data to given persistent storage - '${PERSISTENT_VOLUMES_PATH}'"
	err = 0
	trap 'err=1' ERR
	chown -R postgres:226 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/9.5/data 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources/ 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins/ 1> /dev/null
	chown -R cfyuser:1000 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments/ 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo "Couldn't change ownership" 
		exit $err
	fi
	err = 0
	trap 'err=1' ERR
	chmod -R 700 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/9.5/data 1> /dev/null
	chmod -R 755 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources/ 1> /dev/null
	chmod -R 750 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins/ 1> /dev/null
	chmod -R 755 ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments/ 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo "Couldn't change permissions" 
		exit $err
	fi
	echo "Finished copying cloudify manager data to given persistent storage - '${PERSISTENT_VOLUMES_PATH}' successfully"
}

function start_cloudify_manager() {
	$CLOUDIFY_MANAGER_RUN_CMD
	if [ $? -ne 0 ]
	then
		echo "Unable to start docker-cfy-manager, check docker logs" >&2
		exit 3
	fi
	docker exec -d ${CONTAINER_ID} systemctl stop postgresql-9.5 1> /dev/null
}

function create_and_copy_directories() {
	err = 0
	trap 'err=1' ERR
	echo
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/9.5/data 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins 1> /dev/null
	mkdir -p ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo "Couldn't create directories in ${PERSISTENT_VOLUMES_PATH}"
		exit $err
	fi
	err = 0
	trap 'err=1' ERR
	docker cp ${CONTAINER_ID}:/var/lib/pgsql/9.5/data/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/pgsql/9.5/data 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/manager/resources/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/manager/resources 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/mgmtworker/env/plugins/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/env/plugins 1> /dev/null
	docker cp ${CONTAINER_ID}:/opt/mgmtworker/work/deployments/. ${PERSISTENT_VOLUMES_PATH}/cloudify-external-directories/mgmtworker/work/deployments 1> /dev/null
	if [ $err -ne 0 ]
	then
		echo "Couldn't copy directories from ${CONTAINER_ID} to ${PERSISTENT_VOLUMES_PATH}"
		exit $err
	fi
}

function stop_cloudify_manager() {
	docker stop ${CONTAINER_ID} 1> /dev/null
	echo "Container ${CONTAINER_ID} stopped"
	echo -e "\e[93mContainer has not been deleted for extra precautions, make sure you delete it!!!"
}

if [ $# -ne 2 ]
then
  echo "2 Arguments required: [ Container name, presistent volumes path ]"
  exit 1
fi

validate_docker
start_cloudify_manager
validate_users postgres 26
validate_users cfyuser 999
create_and_copy_directories
change_ownership_and_permissions
stop_cloudify_manager

echo "Successfully configured cloudify persistent storage"
echo "You can start cloudify manager container with the proper volumes"


