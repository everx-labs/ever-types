G_giturl = ""
G_gitcred = 'TonJenSSH'
G_docker_creds = "TonJenDockerHub"
G_params = null
G_images = [:]
G_docker_image = null
G_commit = ""
G_binversion = "NotSet"

def isUpstream() {
    return currentBuild.getBuildCauses()[0]._class.toString() == 'hudson.model.Cause$UpstreamCause'
}

pipeline {
    tools {nodejs "Node12.8.0"}
    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '1')
        
        parallelsAlwaysFailFast()
    }
    agent {
        node {
            label 'master'
        }
    }
    parameters {
        string(
            name:'common_version',
            defaultValue: '',
            description: 'Common version'
        )
        string(
            name:'image_ton_labs_types',
            defaultValue: '',
            description: 'ton-labs-types image name'
        )
    }
    stages {
        stage('Collect commit data') {
            steps {
                sshagent([G_gitcred]) {
                    script {
                        G_giturl = env.GIT_URL
                        G_commit = GIT_COMMIT
                        echo "${G_giturl}"
                        C_PROJECT = env.GIT_URL.substring(19, env.GIT_URL.length() - 4)
                        C_COMMITER = sh (script: 'git show -s --format=%cn ${GIT_COMMIT}', returnStdout: true).trim()
                        C_TEXT = sh (script: 'git show -s --format=%s ${GIT_COMMIT}', returnStdout: true).trim()
                        C_AUTHOR = sh (script: 'git show -s --format=%an ${GIT_COMMIT}', returnStdout: true).trim()
                        C_HASH = sh (script: 'git show -s --format=%h ${GIT_COMMIT}', returnStdout: true).trim()
                    
                        def buildCause = currentBuild.getBuildCauses()[0].shortDescription
                        echo "Build cause: ${buildCause}"
                    }
                }
            }
        }
        stage('Versioning') {
            steps {
                script {
                    lock('bucket') {
                        withAWS(credentials: 'CI_bucket_writer', region: 'eu-central-1') {
                            identity = awsIdentity()
                            s3Download bucket: 'sdkbinaries.tonlabs.io', file: 'version.json', force: true, path: 'version.json'
                        }
                    }
                    if(params.common_version) {
                        G_binversion = sh (script: "node tonVersion.js --set ${params.common_version} .", returnStdout: true).trim()
                    } else {
                        G_binversion = sh (script: "node tonVersion.js .", returnStdout: true).trim()
                    }
                }
            }
        }
        stage('Build') {
            agent {
                dockerfile {
                    registryCredentialsId "${G_docker_creds}"
                    additionalBuildArgs "--pull --target ton-labs-types-rust " + 
                                        "--build-arg \"TON_LABS_TYPES_IMAGE=${G_images['ton-labs-types']}\""
                }
            }
            steps {
                script {
                    sh """
                        cd /tonlabs/ton-labs-types
                        cargo update
                        cargo build --release
                    """
                }
            }
            post {
                success { script { G_build = "success" } }
                failure { script { G_build = "failure" } }
            }
        }
        stage('Tests') {
            agent {
                dockerfile {
                    registryCredentialsId "${G_docker_creds}"
                    additionalBuildArgs "--pull --target ton-labs-types-rust " + 
                                        "--build-arg \"TON_LABS_TYPES_IMAGE=${G_images['ton-labs-types']}\""
                }
            }
            steps {
                script {
                    sh """
                        cd /tonlabs/ton-labs-types
                        cargo update
                        cargo test --release
                    """
                }
            }
            post {
                success { script { G_test = "success" } }
                failure { script { G_test = "failure" } }
            }
        }
    }
    post {
        always {
            node('master') {
                script {
                    cleanWs notFailBuild: true
                }
            } 
        }
    }
}