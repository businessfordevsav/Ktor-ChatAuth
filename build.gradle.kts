val kotlin_version: String by project
val logback_version: String by project
val kmongo_version: String by project
val koin_ktor_version: String by project
val ktor_version: String by project
val koin_logger_version: String by project
val commons_codec_version: String by project

plugins {
    kotlin("jvm") version "2.0.20"
    id("io.ktor.plugin") version "3.0.0-rc-1"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.20"
}

group = "com.routiner"
version = "0.0.1"

application {
    mainClass.set("io.ktor.server.netty.EngineMain")

    val isDevelopment: Boolean = project.ext.has("development")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=$isDevelopment")
}

repositories {
    mavenCentral()
}
val sshAntTask = configurations.create("sshAntTask")
dependencies {
    implementation("io.ktor:ktor-server-call-logging-jvm")
    implementation("io.ktor:ktor-server-content-negotiation-jvm")
    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm")
    implementation("io.ktor:ktor-serialization-gson-jvm")
    implementation("io.ktor:ktor-serialization-jackson-jvm")
    implementation("io.ktor:ktor-server-auto-head-response-jvm")
    implementation("io.ktor:ktor-server-sessions-jvm")
    implementation("io.ktor:ktor-server-auth-jvm")
    implementation("io.ktor:ktor-server-auth-jwt-jvm")
    implementation("io.ktor:ktor-server-netty-jvm")

    implementation("ch.qos.logback:logback-classic:$logback_version")
    implementation("io.ktor:ktor-server-config-yaml")
    testImplementation("io.ktor:ktor-server-test-host-jvm")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlin_version")
    implementation("org.mongodb:mongodb-driver-kotlin-coroutine:$kmongo_version")
    implementation("org.mongodb:mongodb-driver-reactivestreams:4.7.0")
    implementation("org.mongodb:bson-kotlinx:$kmongo_version")

    implementation("io.insert-koin:koin-ktor:$koin_ktor_version")
    implementation("io.insert-koin:koin-logger-slf4j:$koin_logger_version")

    implementation("commons-codec:commons-codec:$commons_codec_version")

    implementation("io.ktor:ktor-server-cors:$ktor_version")
    implementation("io.ktor:ktor-server-conditional-headers:$ktor_version")
    implementation("io.ktor:ktor-server-status-pages:$ktor_version")

    implementation("io.ktor:ktor-server-auth")
    sshAntTask("org.apache.ant:ant-jsch:1.10.12")
    implementation("io.projectreactor:reactor-core:3.5.0")  // Make sure to use the correct version


    implementation("io.ktor:ktor-server-websockets:$ktor_version")

}

tasks.withType<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar> {
    manifest {
        attributes(
            "Main-Class" to application.mainClass.get()
        )
    }
}

ant.withGroovyBuilder {
    "taskdef"(
        "name" to "scp",
        "classname" to "org.apache.tools.ant.taskdefs.optional.ssh.Scp",
        "classpath" to configurations.get("sshAntTask").asPath
    )
    "taskdef"(
        "name" to "ssh",
        "classname" to "org.apache.tools.ant.taskdefs.optional.ssh.SSHExec",
        "classpath" to configurations.get("sshAntTask").asPath
    )
}
