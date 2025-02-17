package com.routiner.data.user

import io.ktor.server.websocket.*
import org.bson.codecs.pojo.annotations.BsonId
import java.util.UUID

data class User(
    @BsonId
    val id: UUID,
    val firstName: String,
    val lastName: String,
    val email: String,
    val password: String,
    val salt: String,
    val token: String? = "",
    val tokenSalt: String? = ""
)

data class UserSession(
    val user: User,
    val session: DefaultWebSocketServerSession? = null
)
