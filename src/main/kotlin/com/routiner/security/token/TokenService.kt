package com.routiner.security.token

interface TokenService {
    fun generateToken(
        config: TokenConfig,
        vararg claim: TokenClaim
    ): String
}