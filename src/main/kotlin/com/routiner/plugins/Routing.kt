package com.routiner.plugins

import com.routiner.data.user.UserDataSource
import com.routiner.routes.*
import com.routiner.routes.authenticate
import com.routiner.security.hashing.HashingService
import com.routiner.security.token.TokenConfig
import com.routiner.security.token.TokenService
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig,
) {
//    install(AutoHeadResponse)
    install(WebSockets)
    routing {
        signIn(userDataSource, hashingService, tokenService, tokenConfig)
        signUp(userDataSource, hashingService, tokenService, tokenConfig)
        authenticate {
            authenticate()
            getSecretInfo()
            getUser(userDataSource, hashingService)
            logOut(userDataSource, hashingService)
            updateUser(userDataSource, hashingService)

        }
        chatUsingId(userDataSource, hashingService, tokenConfig)
        chat()
    }

}
