package com.routiner.data.request

import kotlinx.serialization.Serializable

@Serializable
data class AuthRequest(
    val email: String,
    val password: String
)

@Serializable
data class SignUpRequest(
    val firstName: String,
    val lastName: String,
    val email: String,
    val password: String
)

@Serializable
data class EditeProfileRequest(
    val firstName: String?,
    val lastName: String?,
)

data class GetUserRequest(
    val Authorization: String,
)


