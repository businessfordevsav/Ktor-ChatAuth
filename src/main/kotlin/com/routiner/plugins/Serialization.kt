package com.routiner.plugins

import com.fasterxml.jackson.databind.*
import io.ktor.serialization.gson.*
import io.ktor.serialization.jackson.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.routing.*

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        json()
        gson {
            }
        jackson {
                enable(SerializationFeature.INDENT_OUTPUT)
            }
    }
    routing {
    }
}
