package com.sportify.data.response

import kotlinx.serialization.Serializable

@Serializable
data class CommonResponse<T>(
    val status: String,
    val code: Int,
    val message : String? = null,
    val data : T? = null
)


