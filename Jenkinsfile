pipeline {
  agent {
    docker {
      image 'scssubstratee/substratee_dev:18.04-2.9.1-1.1.2'
      args '''
        -u root
        --privileged
      '''
    }
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '14'))
  }
  stages {
    stage('rustup') {
      steps {
        sh './ci/install_rust.sh'
      }
    }
    stage('Build') {
      steps {
        sh 'cargo build --release 2>&1 | tee build_release.log'
        sh 'cargo build 2>&1 | tee build_debug.log'
      }
    }
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: '**/integritee-node', caseSensitive: false, fingerprint: true, onlyIfSuccessful: true
      }
    }
    stage('Test') {
      steps {
        sh 'BUILD_DUMMY_WASM_BINARY=1 cargo test --all 2>&1 | tee test.log'
      }
    }
    // running clippy doesn't actually make sense here, as it's 99% upstream code.
    // however, right now it didn't take much to make it pass
    stage('Clippy') {
      steps {
        sh 'cargo clean'
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cargo clippy 2>&1 | tee clippy_debug.log'
        }
      }
    }
    // NEVER!!! run cargo fmt! This is 99% upstream code and we need easy-rebase!
    stage('Results') {
      steps {
        recordIssues(
          aggregatingResults: true,
          enabledForFailure: true,
          qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]],
          tools: [
              cargo(
                pattern: 'build.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-warnings',
                pattern: 'clippy.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-errors',
                pattern: 'clippy.log',
                reportEncoding: 'UTF-8'
              )
          ]
        )
//        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
//                  sh './ci/check_fmt_log.sh'
//        }
      }
    }
    stage('Archive logs') {
      steps {
        archiveArtifacts artifacts: '*.log', caseSensitive: false, fingerprint: true, onlyIfSuccessful: true
      }
    }
  }
  post {
    unsuccessful {
        emailext (
          subject: "Jenkins Build '${env.JOB_NAME} [${env.BUILD_NUMBER}]' is ${currentBuild.currentResult}",
          body: "${env.JOB_NAME} build ${env.BUILD_NUMBER} is ${currentBuild.currentResult}\n\nMore info at: ${env.BUILD_URL}",
          to: "${env.RECIPIENTS_SUBSTRATEE}"
        )
    }
    always {
      cleanWs()
    }
  }
}
