package com.sportify.data.response

import kotlinx.serialization.Serializable

@Serializable
data class SignUpResponse(
    val id : String,
    val firstName: String,
    val lastName: String,
    val email: String,
    val token: String
)
