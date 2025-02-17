package com.routiner.data.user

import java.util.*

interface UserDataSource {
    suspend fun getUserByEmail(email : String): User
    suspend fun isUserExists(key : String, value : Any?):Boolean
    suspend fun getUserById(id : UUID): User?
    suspend fun insertUser(user: User): User?
    suspend fun updateUserToken(id: UUID, token: String, tokenSalt: String): Boolean
    suspend fun updateUser(id: UUID, fieldMap: HashMap<String, Any>): User?
}