package com.sportify.data.response

import kotlinx.serialization.Serializable

@Serializable
data class CommonArrayResponse<T>(
    val status: String,
    val code: Int,
    val message : String? = null,
    val data : List<T>? = null
)


