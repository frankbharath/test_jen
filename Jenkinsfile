pipeline {
    agent { dockerfile true }
    stages {
        stage('build') {
            agent {
                docker { image 'maven:3-alpine' }
            }
            steps {
                sh 'mvn --version'
            }
        }
    }
}
