plugins {
    java
    application
}

group = "io.vainslab"
version = "0.1.0"

java { toolchain { languageVersion = JavaLanguageVersion.of(25) } }

repositories { mavenCentral() }

dependencies {
    implementation("io.javalin:javalin:7.2.4")
    implementation("org.slf4j:slf4j-simple:2.0.17")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.4")
    implementation("org.xerial:sqlite-jdbc:3.54.1.0")
    implementation("org.eclipse.angus:angus-mail:2.0.5")

    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application { mainClass = "io.vainslab.auka.Main" }

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
