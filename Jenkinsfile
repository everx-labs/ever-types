G_giturl = ""
G_gitcred = 'TonJenSSH'
G_docker_creds = "TonJenDockerHub"
G_image_target = ""
G_docker_image = null
G_build = "none"
G_test = "none"
G_commit = ""

pipeline {
    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '1')
        disableConcurrentBuilds()
        parallelsAlwaysFailFast()
    }
    agent {
        node {
            label 'master'
        }
    }
    parameters {
        string(
            name:'dockerImage_ton_labs_types',
            defaultValue: '',
            description: 'ton-labs-types image name'
        )
        string(
            name:'ton_labs_block_branch',
            defaultValue: 'master',
            description: 'ton-labs-block branch for upstairs test'
        )
        string(
            name:'ton_labs_vm_branch',
            defaultValue: 'master',
            description: 'ton-labs-vm branch for upstairs test'
        )
        string(
            name:'ton_labs_abi_branch',
            defaultValue: 'master',
            description: 'ton-labs-abi branch for upstairs test'
        )
        string(
            name:'ton_executor_branch',
            defaultValue: 'master',
            description: 'ton-executor branch for upstairs test'
        )
        string(
            name:'tvm_linker_branch',
            defaultValue: 'master',
            description: 'tvm-linker branch for upstairs test'
        )
        string(
            name:'ton_sdk_branch',
            defaultValue: 'master',
            description: 'ton-sdk branch for upstairs test'
        )
        
    }
    stages {
        stage('Collect commit data') {
            steps {
                sshagent([G_gitcred]) {
                    script {
                        G_giturl = env.GIT_URL
                        echo "${G_giturl}"
                        C_PROJECT = env.GIT_URL.substring(19, env.GIT_URL.length() - 4)
                        C_COMMITER = sh (script: 'git show -s --format=%cn ${GIT_COMMIT}', returnStdout: true).trim()
                        C_TEXT = sh (script: 'git show -s --format=%s ${GIT_COMMIT}', returnStdout: true).trim()
                        C_AUTHOR = sh (script: 'git show -s --format=%an ${GIT_COMMIT}', returnStdout: true).trim()
                        C_HASH = sh (script: 'git show -s --format=%h ${GIT_COMMIT}', returnStdout: true).trim()
                    
                        DiscordURL = "https://discordapp.com/api/webhooks/496992026932543489/4exQIw18D4U_4T0H76bS3Voui4SyD7yCQzLP9IRQHKpwGRJK1-IFnyZLyYzDmcBKFTJw"
                        string DiscordFooter = "Build duration is ${currentBuild.durationString}"
                        DiscordTitle = "Job ${JOB_NAME} from GitHub ${C_PROJECT}"
                        
                        G_commit = GIT_COMMIT
                        if (params.dockerImage_ton_labs_types == '') {
                            G_image_target = "tonlabs/ton-labs-types:${GIT_COMMIT}"
                        } else {
                            G_image_target = params.dockerImage_ton_labs_types
                        }
                        echo "Target image name: ${G_image_target}"

                        def buildCause = currentBuild.getBuildCauses()
                        echo "Build cause: ${buildCause}"
                    }
                }
            }
        }
        stage('Prepare image') {
            steps {
                echo "Prepare image..."
                script {
                    docker.withRegistry('', G_docker_creds) {
                        args = "--no-cache --label 'git-commit=${GIT_COMMIT}' --force-rm ."
                        G_docker_image = docker.build(
                            G_image_target, 
                            args
                        )
                        echo "Image ${G_docker_image} as ${G_image_target}"
                        G_docker_image.push()
                    }
                }
            }
        }
        stage('Build') {
            steps {
                script {
                    docker.withRegistry('', G_docker_creds) {
                        G_docker_image.withRun() {c -> 
                            docker.image("rust:latest").inside("--volumes-from ${c.id}") {
                                sh """
                                    cd /tonlabs/ton-labs-types
                                    cargo update
                                    cargo build --release
                                """
                            }
                        }
                    }
                }
            }
            post {
                success { script { G_build = "success" } }
                failure { script { G_build = "failure" } }
            }
        }
        stage('Tests') {
            steps {
                script {
                    docker.withRegistry('', G_docker_creds) {
                        G_docker_image.withRun() {c -> 
                            docker.image("rust:latest").inside("--volumes-from ${c.id}") {
                                sh """
                                    cd /tonlabs/ton-labs-types
                                    cargo update
                                    cargo test --release
                                """
                            }
                        }
                    }
                }
            }
            post {
                success { script { G_test = "success" } }
                failure { script { G_test = "failure" } }
            }
        }
        stage('Build ton-labs-block/ton-labs-vm') {
            parallel {
                stage('Run ton-labs-block') {
                    steps {
                        script {
                            def params_block = [
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_types',
                                    value: "${G_image_target}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_block',
                                    value: "tonlabs/ton-labs-block:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_labs_abi_branch',
                                    value: params.ton_labs_abi_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_executor_branch',
                                    value: params.ton_executor_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'tvm_linker_branch',
                                    value: params.tvm_linker_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_sdk_branch',
                                    value: params.ton_sdk_branch
                                ]
                            ]
                            build job: "Node/ton-labs-block/${params.ton_labs_block_branch}", parameters: params_block
                        }
                    }
                }
                stage('Run ton-labs-vm') {
                    steps {
                        script {
                            def params_vm = [
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_types',
                                    value: "${G_image_target}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_vm',
                                    value: "tonlabs/ton-labs-vm:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_labs_abi_branch',
                                    value: params.ton_labs_abi_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_executor_branch',
                                    value: params.ton_executor_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'tvm_linker_branch',
                                    value: params.tvm_linker_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_sdk_branch',
                                    value: params.ton_sdk_branch
                                ]
                            ]
                            build job: "Node/ton-labs-vm/${params.ton_labs_vm_branch}", parameters: params_vm
                        }
                    }
                }
            }
        }
        stage('Build ton-executor/ton-labs-abi') {
            parallel {
                stage('Run ton-labs-abi') {
                    steps {
                        script {
                            def params_abi = [
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_types',
                                    value: "${G_image_target}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_block',
                                    value: "tonlabs/ton-labs-block:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_vm',
                                    value: "tonlabs/ton-labs-vm:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_abi',
                                    value: "tonlabs/ton-labs-abi:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_labs_vm_branch',
                                    value: params.ton_labs_vm_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_labs_abi_branch',
                                    value: params.ton_labs_abi_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_executor_branch',
                                    value: params.ton_executor_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'tvm_linker_branch',
                                    value: params.tvm_linker_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_sdk_branch',
                                    value: params.ton_sdk_branch
                                ]
                            ]
                            build job: "Node/ton-labs-abi/${params.ton_labs_abi_branch}", parameters: params_abi
                        }
                    }
                }
                stage('Run ton-executor') {
                    steps {
                        script {
                            def params_executor = [
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_types',
                                    value: "${G_image_target}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_block',
                                    value: "tonlabs/ton-labs-block:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_labs_vm',
                                    value: "tonlabs/ton-labs-vm:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'dockerImage_ton_executor',
                                    value: "tonlabs/ton-executor:ton-labs-types-${GIT_COMMIT}"
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'tvm_linker_branch',
                                    value: params.tvm_linker_branch
                                ],
                                [
                                    $class: 'StringParameterValue',
                                    name: 'ton_sdk_branch',
                                    value: params.ton_sdk_branch
                                ]
                            ]
                            build job: "Node/ton-executor/${params.ton_executor_branch}", parameters: params_executor
                        }
                    }
                }
            }
        }
        stage('Tag as latest') {
            steps {
                script {
                    docker.withRegistry('', G_docker_creds) {
                        G_docker_image.push('latest')
                    }
                }
            }
        }
    }
    post {
        always {
            node('master') {
                script {
                    DiscordDescription = """${C_COMMITER} pushed commit ${C_HASH} by ${C_AUTHOR} with a message '${C_TEXT}'
Build number ${BUILD_NUMBER}
Build: **${G_build}**
Tests: **${G_test}**"""
                    
                    discordSend(
                        title: DiscordTitle, 
                        description: DiscordDescription, 
                        footer: DiscordFooter, 
                        link: RUN_DISPLAY_URL, 
                        successful: currentBuild.resultIsBetterOrEqualTo('SUCCESS'), 
                        webhookURL: DiscordURL
                    )
                    cleanWs notFailBuild: true
                }
            } 
        }
    }
}