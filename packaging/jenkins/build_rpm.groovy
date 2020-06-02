pipeline {
    agent {
        dockerfile {
            dir 'packaging/jenkins/rpm_builder'
            args '-u root -v /var/lib/jenkins/jobs/credentials.sh:/credentials.sh:ro'
        }
    }
    parameters {
        string(name: 'VERSION'. description: 'Cloudify version number, for use as a RPM Version (eg. 5.1.0)')
        string(name: 'PRERELEASE', description: 'Cloudify milestone version number, for use as a RPM Release (eg. .dev1)')
        string(name: 'BRANCH', defaultValue: 'master')
        choice(name: 'EDITION', choices: 'premium\ncommunity')
    }
    stages {
        stage('Download requirements'){
            steps {
                sh """
                    ln -s "${WORKSPACE}" ~/rpmbuild/SOURCES
                """
                sh """
                    source /credentials.sh > /dev/null 2>&1 &&
                    mkdir rpms
                    pushd 'rpms'
                        ../packaging/fetch_requirements -b ${params.BRANCH} --edition ${params.EDITION}
                    popd
                """
            }
        }
        stage('Build the manager RPM'){
            steps {
                sh """
                    rpmbuild -D "CLOUDIFY_VERSION ${params.VERSION}" -D "CLOUDIFY_PACKAGE_RELEASE ${params.PRERELEASE}" -bb packaging/install_rpm.spec
                """
                sh """
                    mv ~/rpmbuild/RPMS/x86_64/*.rpm "${WORKSPACE}"
                """
            }
            post {
                success {
                    archiveArtifacts artifacts: '*.rpm', fingerprint: true
                }
                cleanup {
                    cleanWs()
                }
            }
        }
    }
}
