package com.routiner

import com.routiner.core.db.configureMongo
import com.routiner.data.user.UserDataSourceImpl
import com.routiner.plugins.configureMonitoring
import com.routiner.plugins.configureSecurity
import com.routiner.plugins.configureSerialization
import com.routiner.security.hashing.SHA256HashingService
import com.routiner.security.token.JwtTokenService
import com.routiner.security.token.TokenConfig

import io.ktor.server.application.*
import io.ktor.server.websocket.*

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureMongo()

    val userDataSource = UserDataSourceImpl()
    val tokenService = JwtTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience = environment.config.property("jwt.audience").getString(),
        expiresIn = 365L * 1000L * 60L * 60L * 24L,
        secret = System.getenv("JWT_SECRET")
    )
    val hashingService = SHA256HashingService()

    configureMonitoring()
    configureSerialization()
    configureSecurity(userDataSource, hashingService, tokenService, tokenConfig)

}
