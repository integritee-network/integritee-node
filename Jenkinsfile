pipeline {
  agent {
    node {
      label 'rust&&sgx'
    }
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '14'))
  }
  stages {
    stage('Environment') {
      steps {
        sh './ci/install_rust.sh'
      }
    }
    stage('Build') {
      steps {
        sh 'cargo build'
      }
    }
    stage('Test') {
      steps {
        echo 'Stage TEST'
        sh 'cargo test'
      }
    }
    stage('Clippy') {
      steps {
        sh 'cargo clean'
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cargo check 2>&1 | tee rustc.log'
        }
        sh 'cargo clean'
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          sh 'cargo +nightly-2019-11-17 clippy 2>&1 | tee clippy.log'
        }
      }
    }
    stage('Formater') {
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
          sh 'cargo fmt -- --check > ${WORKSPACE}/fmt.log'
        }
      }
    }
    stage('Results') {
      steps {
        recordIssues(
          aggregatingResults: true,
          enabledForFailure: true,
          qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]],
          tools: [
              cargo(
                pattern: 'build_*.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-warnings',
                pattern: 'clippy_*.log',
                reportEncoding: 'UTF-8'
              ),
              groovyScript(
                parserId:'clippy-errors',
                pattern: 'clippy_*.log',
                reportEncoding: 'UTF-8'
              )
          ]
        )
        script {
          try {
            sh './ci/check_fmt_log.sh'
          }
          catch (exc) {
            echo 'Style changes detected. Setting stage to unstable'
            currentStage.result = 'UNSTABLE'
          }
        }
      }
    }
    stage('Archive build output') {
      steps {
        archiveArtifacts artifacts: '*.log'
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
  }
}
