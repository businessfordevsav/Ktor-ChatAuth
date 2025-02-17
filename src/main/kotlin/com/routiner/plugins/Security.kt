package com.routiner.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.routiner.data.user.UserDataSource
import com.routiner.security.hashing.HashingService
import com.routiner.security.token.TokenConfig
import com.routiner.security.token.TokenService
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.autohead.*
import io.ktor.server.plugins.conditionalheaders.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.sessions.*
import kotlinx.serialization.Serializable
import kotlin.collections.set

fun Application.configureSecurity(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig,
) {

    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {

        @Serializable
        data class MySession(val count: Int = 0)
        install(Sessions) {
            cookie<MySession>("MY_SESSION") {
                cookie.extensions["SameSite"] = "lax"
            }
        }
        // Please read the jwt property from the config file if you are using EngineMain

        val jwtRealm = "ktor sample app"
        authentication {
            jwt {
                realm = jwtRealm
                verifier(
                    JWT
                        .require(Algorithm.HMAC256(tokenConfig.secret))
                        .withAudience(tokenConfig.audience)
                        .withIssuer(tokenConfig.issuer)
                        .build()
                )
                validate { credential ->
                    if (credential.payload.audience.contains(tokenConfig.audience)) JWTPrincipal(credential.payload) else null
                }
            }
        }

        install(AutoHeadResponse)


        install(ContentNegotiation) {
            json() // Use Kotlinx serialization
        }
        install(CORS) {
            anyHost() // Adjust this for production
            allowMethod(HttpMethod.Options)
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Post)
            allowHeader(HttpHeaders.ContentType)
            allowHeader(HttpHeaders.Authorization)
        }

        install(ConditionalHeaders) {

        }

        install(StatusPages) {

        }


        configureRouting(userDataSource, hashingService, tokenService, tokenConfig)
    }.start(wait = true)
}
