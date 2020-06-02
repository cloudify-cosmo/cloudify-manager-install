pipeline {
    agent {
        node 'docker'
    }
    parameters {
        string(name: 'CLOUDIFY_TAG')
        string(name: 'RPM_BUILD_NUMBER')
        choice(name: 'IMAGE_TYPE', choices: "manager-aio\npostgresql\nrabbitmq\nmanager-worker")
    }
    stages {
        stage('Build image'){
            steps {
                script {
                    switch (params.IMAGE_TYPE) {
                        case "manager-aio":
                            config = 'services_to_install: [database_service, queue_service, manager_service]'
                            label = 'cloudify-manager-aio'
                            break
                        case "postgresql":
                            config = 'services_to_install: [database_service]'
                            label = 'cloudify-db'
                            break
                        case "rabbitmq":
                            config = 'services_to_install: [queue_service]'
                            label = 'cloudify-queue'
                            break
                        case 'manager-worker':
                            config = 'services_to_install: [manager_service]'
                            label = 'cloudify-manager-worker'
                            break
                    }
                }
                copyArtifacts(
                    projectName: 'dir_manager/_temp_build_rpm',
                    selector: params.RPM_BUILD_NUMBER ? specific(params.RPM_BUILD_NUMBER) : lastSuccessful(),
                    target: 'packaging/docker'
                )
                sh "mv packaging/docker/cloudify-manager-install*.rpm packaging/cloudify-manager-install.rpm"

                // the dockerfile expects the rpm file as a downloadable url, so we run a http server serving it.
                // The http server is a `python -m http.client`, run in docker (removed in cleanup), hosting on port 0,
                // so we have to look at the server's logs and parse out the port.
                sh """
                    docker run --net host --name rpm-http-${env.BUILD_NUMBER} -dt -v \$(pwd)/packaging:/mount python python -m http.server -d /mount 0
                """
                sh """docker logs rpm-http-${env.BUILD_NUMBER}"""  // just display it for the human-readable logs
                script {
                    HTTP_PORT = sh (
                        // we want the port; the log message is eg.:
                        // Serving HTTP on 0.0.0.0 port 39032 (http://0.0.0.0:39032/) ...
                        script: """
                            docker logs rpm-http-${env.BUILD_NUMBER} | grep -oP '(?<=port )\\d+'
                        """,
                        returnStdout: true
                    ).trim()
                }
                sh """echo "${config}" > packaging/docker/config.yaml"""
                sh """
                    docker build --network host -t ${label} --build-arg rpm_file=http://localhost:${HTTP_PORT}/cloudify-manager-install.rpm packaging/docker
                """
                sh """
                    docker image save -o cloudify-${params.IMAGE_TYPE}-docker-${params.CLOUDIFY_TAG}.tar ${label}:latest
                """

            }
            post {
                success {
                    archiveArtifacts artifacts: '*.tar', fingerprint: true
                }
                cleanup {
                    sh "docker rm -f rpm-http-${env.BUILD_NUMBER} || true"
                    cleanWs()
                }
            }
        }
    }
}
