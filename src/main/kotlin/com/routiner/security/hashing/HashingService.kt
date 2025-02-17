package com.routiner.security.hashing

import com.routiner.security.hashing.SaltedHash

interface HashingService {

    fun generateSaltedHash(value: String, saltLength: Int = 32): SaltedHash
    fun verify(value: String, saltedHash: SaltedHash): Boolean
}