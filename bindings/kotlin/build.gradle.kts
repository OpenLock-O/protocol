plugins { kotlin("jvm") version "2.0.21" }
group = "org.openlock"
version = "0.4.0"
repositories { mavenCentral() }
kotlin { jvmToolchain(17) }

val integration by sourceSets.creating
configurations[integration.implementationConfigurationName].extendsFrom(configurations.implementation.get())
integration.compileClasspath += sourceSets.main.get().output
integration.runtimeClasspath += sourceSets.main.get().output
tasks.register<JavaExec>("integrationTest") {
    dependsOn(integration.classesTaskName)
    classpath = integration.runtimeClasspath
    mainClass.set("org.openlock.IntegrationKt")
    systemProperty("java.library.path", layout.buildDirectory.dir("native").get().asFile.absolutePath)
}
