package com.routiner.routes

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.jetbrains.handson.chat.server.Connection
import com.routiner.core.isValidEmail
import com.routiner.data.request.AuthRequest
import com.routiner.data.request.EditeProfileRequest
import com.routiner.data.request.SignUpRequest
import com.routiner.data.user.User
import com.routiner.data.user.UserDataSource
import com.routiner.data.user.UserSession
import com.routiner.security.hashing.HashingService
import com.routiner.security.hashing.SaltedHash
import com.routiner.security.token.TokenClaim
import com.routiner.security.token.TokenConfig
import com.routiner.security.token.TokenService
import com.sportify.data.response.CommonResponse
import com.sportify.data.response.SignUpResponse
import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.*

fun Route.signUp(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    post("signup") {

        val parameters = call.receiveParameters()

        // Map parameters to SignUpRequest
        val request = SignUpRequest(
            firstName = parameters["firstName"] ?: "",
            lastName = parameters["lastName"] ?: "",
            email = parameters["email"] ?: "",
            password = parameters["password"] ?: ""
        )

        // Validate request fields
        if (request.firstName.isBlank() || request.lastName.isBlank() || request.email.isBlank() || request.password.isBlank()) {
            call.respond(
                HttpStatusCode.BadRequest,
                CommonResponse<SignUpRequest>(
                    message = "All fields are required.",
                    status = "error",
                    code = 400,
                    data = null
                )
            )
            return@post
        }


        val isPwTooShort = request.password.length < 8


        if (!request.email.trim().isValidEmail()) {
            call.respond(
                HttpStatusCode.Conflict, message =
                CommonResponse<SignUpRequest>(
                    message = "Email is not valid, please try again.",
                    status = "error",
                    code = 409
                )
            )
            return@post
        }

        if (isPwTooShort) {
            call.respond(
                HttpStatusCode.Conflict, message =
                CommonResponse<SignUpRequest>(
                    message = "Password is not valid, please try again.",
                    status = "error",
                    code = 409
                )
            )
            return@post
        }

        if (userDataSource.isUserExists(User::email.name, request.email)) {
            call.respond(
                HttpStatusCode.Conflict, message =
                CommonResponse<SignUpRequest>(
                    message = "Email are already register, please sign in.",
                    status = "error",
                    code = 409
                )
            )
            return@post
        }


        val saltedHash = hashingService.generateSaltedHash(request.password)

        val user = User(
            UUID.randomUUID(),
            firstName = request.firstName,
            lastName = request.lastName,
            email = request.email,
            password = saltedHash.hash,
            salt = saltedHash.salt

        )
        val wasAcknowledged = userDataSource.insertUser(user)
        println("wasAcknowledged ::: $wasAcknowledged")
        if (wasAcknowledged == null) {
            call.respond(
                HttpStatusCode.ServiceUnavailable, message =
                CommonResponse<SignUpRequest>(
                    message = "Something went wrong, please try again.",
                    status = "error",
                    code = 503
                )
            )
            return@post
        }

        val token = tokenService.generateToken(
            config = tokenConfig,
            TokenClaim(
                name = "userId",
                value = wasAcknowledged.id.toString()
            )
        )

        val tokenSaltedHash = hashingService.generateSaltedHash(token)

        val wasAcknowledgedToken = userDataSource.updateUserToken(
            id = wasAcknowledged.id,
            token = tokenSaltedHash.hash,
            tokenSalt = tokenSaltedHash.salt
        )

        if (!wasAcknowledgedToken) {
            call.respond(
                HttpStatusCode.UnprocessableEntity,
                message =
                CommonResponse<SignUpRequest>(
                    message = "Something went wrong, please try again.",
                    status = "error",
                    code = 422
                ),
            )
            return@post
        }

        call.respond(
            status = HttpStatusCode.OK,
            message = CommonResponse(
                message = "Your account created successfully",
                status = "success",
                code = 200,
                data = SignUpResponse(
                    id = wasAcknowledged.id.toString(),
                    firstName = wasAcknowledged.firstName,
                    lastName = wasAcknowledged.lastName,
                    email = wasAcknowledged.email,
                    token = token
                )
            )
        )
    }
}

fun Route.signIn(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    post("login") {
        val request = runCatching<AuthRequest?> { call.receiveNullable<AuthRequest>() }.getOrNull() ?: kotlin.run {
            call.respond(
                HttpStatusCode.NotFound, message =
                CommonResponse<SignUpRequest>(
                    message = "Invalid request.",
                    status = "error",
                    code = 404,
                    data = null
                )
            )
            return@post
        }


        if (!userDataSource.isUserExists(User::email.name, request.email)) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Incorrect email or password.",
                    status = "error",
                    code = 422
                )
            )
            return@post
        }

        val user = userDataSource.getUserByEmail(request.email)

        val isValidPassword = hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash = user.password,
                salt = user.salt
            )
        )

        if (!isValidPassword) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Incorrect email or password.",
                    status = "error",
                    code = 422
                )
            )
            return@post
        }

        val token = tokenService.generateToken(
            config = tokenConfig,
            TokenClaim(
                name = "userId",
                value = user.id.toString()
            )
        )

        val tokenSaltedHash = hashingService.generateSaltedHash(token)

        val wasAcknowledgedToken = userDataSource.updateUserToken(
            id = user.id,
            token = tokenSaltedHash.hash,
            tokenSalt = tokenSaltedHash.salt
        )

        if (!wasAcknowledgedToken) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Please try again later",
                    status = "error",
                    code = 503
                )
            )
            return@post
        }

        call.respond(
            status = HttpStatusCode.OK,
            message = CommonResponse(
                message = "Login successfully",
                status = "success",
                code = 200,
                data = SignUpResponse(
                    id = user.id.toString(),
                    firstName = user.firstName,
                    lastName = user.lastName,
                    email = user.email,
                    token = token
                )
            )
        )
    }
}

fun Route.authenticate() {
    authenticate {
        get("authenticate") {
            call.respond(HttpStatusCode.OK)
        }
    }
}

fun Route.getUser(userDataSource: UserDataSource, hashingService: HashingService) {

    get("user") {
        val principal = call.principal<JWTPrincipal>()
        println("principal $principal")
        val userId = principal?.getClaim("userId", String::class)
        val authorizationHeader = call.request.headers[HttpHeaders.Authorization]
        println("userId :: $userId")
        if (!userDataSource.isUserExists("_id", UUID.fromString(userId))) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Incorrect email or password.",
                    status = "error",
                    code = 422
                )
            )
            return@get
        }
        val user = userId?.let { it1 -> userDataSource.getUserById(UUID.fromString(it1)) }

        if (user == null) {
            call.respond(
                HttpStatusCode.NotFound, message =
                CommonResponse<SignUpRequest>(
                    message = "User not found.",
                    status = "error",
                    code = 404
                )
            )
            return@get
        }

        val isValidToken = hashingService.verify(
            value = authorizationHeader.toString().replace("Bearer ", ""),
            saltedHash = SaltedHash(
                hash = user.token.toString(),
                salt = user.tokenSalt.toString()
            )
        )
        print("authorizationHeader :: $authorizationHeader")
        if (!isValidToken) {
            call.respond(
                HttpStatusCode.Unauthorized, message =
                CommonResponse<SignUpRequest>(
                    message = "Unauthorized",
                    status = "error",
                    code = 422
                )
            )
            return@get
        }


        call.respond(
            status = HttpStatusCode.OK,
            message = CommonResponse(
                message = "User found successfully.",
                status = "success",
                code = 200,
                data = SignUpResponse(
                    id = user.id.toString(),
                    firstName = user.firstName,
                    lastName = user.lastName,
                    email = user.email,
                    token = authorizationHeader.toString().replace("Bearer ", "")
                )
            )
        )

    }

}

fun Route.updateUser(userDataSource: UserDataSource, hashingService: HashingService) {

    post("editeProfile") {
        val principal = call.principal<JWTPrincipal>()
        val userId = principal?.getClaim("userId", String::class)
        val authorizationHeader = call.request.headers[HttpHeaders.Authorization]
        println("userId :: $userId")
        if (!userDataSource.isUserExists("_id", UUID.fromString(userId))) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Incorrect email or password.",
                    status = "error",
                    code = 422
                )
            )
            return@post
        }
        val user = userId?.let { it1 -> userDataSource.getUserById(UUID.fromString(it1)) }

        if (user == null) {
            call.respond(
                HttpStatusCode.NotFound, message =
                CommonResponse<SignUpRequest>(
                    message = "User not found.",
                    status = "error",
                    code = 404
                )
            )
            return@post
        }

        val isValidToken = hashingService.verify(
            value = authorizationHeader.toString().replace("Bearer ", ""),
            saltedHash = SaltedHash(
                hash = user.token.toString(),
                salt = user.tokenSalt.toString()
            )
        )
        print("authorizationHeader :: $authorizationHeader")
        if (!isValidToken) {
            call.respond(
                HttpStatusCode.Unauthorized, message =
                CommonResponse<SignUpRequest>(
                    message = "Unauthorized",
                    status = "error",
                    code = 422
                )
            )
            return@post
        }
        val parameters = call.receiveParameters()
        val request = EditeProfileRequest(
            firstName = parameters["firstName"] ?: "",
            lastName = parameters["lastName"] ?: "",
        )



        if (request.firstName.isNullOrEmpty() && request.lastName.isNullOrEmpty()) {
            call.respond(
                HttpStatusCode.NotFound, message =
                CommonResponse<SignUpRequest>(
                    message = "Invalid request.",
                    status = "error",
                    code = 404,
                    data = null
                )
            )
            return@post
        }
        val fieldMap: HashMap<String, Any> = HashMap()

        request.firstName?.let {
            fieldMap[User::firstName.name] = it
        }

        request.lastName?.let {
            fieldMap[User::lastName.name] = it
        }



        println("fieldMap :: $fieldMap")

        val userResponse = userDataSource.updateUser(user.id, fieldMap)

        call.respond(
            status = HttpStatusCode.OK,
            message = CommonResponse(
                message = "User found successfully.",
                status = "success",
                code = 200,
                data = SignUpResponse(
                    id = userResponse?.id.toString(),
                    firstName = userResponse?.firstName.toString(),
                    lastName = userResponse?.lastName.toString(),
                    email = userResponse?.email.toString(),
                    token = authorizationHeader.toString()
                )
            )
        )

    }

}


fun Route.logOut(userDataSource: UserDataSource, hashingService: HashingService) {

    get("logout") {
        val principal = call.principal<JWTPrincipal>()
        val userId = principal?.getClaim("userId", String::class)
        val authorizationHeader = call.request.headers[HttpHeaders.Authorization]

        val user = userId?.let { it1 -> userDataSource.getUserById(UUID.fromString(it1)) }
        if (user == null) {
            call.respond(
                HttpStatusCode.NotFound, message =
                CommonResponse<SignUpRequest>(
                    message = "User not found.",
                    status = "error",
                    code = 404
                )
            )
            return@get
        }

        val isValidToken = hashingService.verify(
            value = authorizationHeader.toString().replace("Bearer ", ""),
            saltedHash = SaltedHash(
                hash = user.token.toString(),
                salt = user.tokenSalt.toString()
            )
        )

        if (!isValidToken) {
            call.respond(
                HttpStatusCode.Unauthorized, message =
                CommonResponse<SignUpRequest>(
                    message = "Unauthorized",
                    status = "error",
                    code = 422
                )
            )
            return@get
        }

        val wasAcknowledgedToken = userDataSource.updateUserToken(id = user.id, token = "", tokenSalt = "")

        if (!wasAcknowledgedToken) {
            call.respond(
                HttpStatusCode.UnprocessableEntity, message =
                CommonResponse<SignUpRequest>(
                    message = "Please try again later.",
                    status = "error",
                    code = 503
                )
            )
            return@get
        }

        call.respond(
            status = HttpStatusCode.OK,
            message = CommonResponse(
                message = "User logout successfully.",
                status = "success",
                code = 200,
                data = null
            )
        )

    }

}

fun Route.getSecretInfo() {
    get("secret") {
        val principal = call.principal<JWTPrincipal>()
        val userId = principal?.getClaim("userId", String::class)
        call.respond(HttpStatusCode.OK, "Your userId is $userId")
    }

}

fun Route.chat() {
    val connections = Collections.synchronizedSet<Connection?>(LinkedHashSet())
    webSocket("chat") {
        val name = call.parameters["name"] // Example parameter
        send("Hello, $name!")
        println("Adding $name!")
        val thisConnection = Connection(this)
        connections += thisConnection
        try {
            send("You are connected! There are ${connections.count()} users here.")
            for (frame in incoming) {
                frame as? Frame.Text ?: continue
                val receivedText = frame.readText()
                val textWithUsername = "[${thisConnection.name}]: $receivedText"
                connections.forEach {
                    if (thisConnection.name != it.name)
                        it.session.send(textWithUsername)
                }
                println("textWithUsername :: $textWithUsername")

            }
        } catch (e: Exception) {
            println(e.localizedMessage)
        } finally {
            println("Removing $thisConnection!")
            connections -= thisConnection
        }
    }
}

val userPairs = mutableMapOf<UUID, UserSession>()
val mutex = Mutex()

fun Route.chatUsingId(userDataSource: UserDataSource, hashingService: HashingService, tokenConfig: TokenConfig) {
    webSocket("/chat/{partnerId}") {
        // Extract the user ID from the JWT principal


        val authorizationHeader = call.request.queryParameters["token"]?.replace("Bearer ", "")

        println("authorizationHeader $authorizationHeader")
        // Verify the token
        val decodedToken: DecodedJWT? = try {
            val algorithm = Algorithm.HMAC256(tokenConfig.secret)  // Use the same secret you used to sign the token
            val verifier = JWT.require(algorithm)
                .withAudience(tokenConfig.audience)
                .withIssuer(tokenConfig.issuer)
                .build()

            verifier.verify(authorizationHeader)
        } catch (e: Exception) {
            call.respond(HttpStatusCode.Unauthorized, "Invalid token: ${e.message}")
            return@webSocket
        }

        // Extract the userId claim from the decoded token
        val userIdClaim = decodedToken?.getClaim("userId")?.asString()

        if (userIdClaim == null) {
            call.respond(HttpStatusCode.Unauthorized, "User ID not found in token")
            return@webSocket
        }

        // Convert userId to UUID (optional, if userId is a UUID)
        val userId = UUID.fromString(userIdClaim)

        if (userId == null || !userDataSource.isUserExists("_id", userId)) {
            call.respond(
                HttpStatusCode.UnprocessableEntity,
                CommonResponse<SignUpRequest>("error", 422, "Incorrect user ID.")
            )
            return@webSocket
        }

        // Retrieve the user
        val user = userDataSource.getUserById(userId) ?: run {
            call.respond(
                HttpStatusCode.NotFound,
                CommonResponse<SignUpRequest>("error", 404, "User not found.")
            )
            return@webSocket
        }

        // Validate the token
        val isValidToken = authorizationHeader?.replace("Bearer ", "")?.let { token ->
            hashingService.verify(
                value = token,
                saltedHash = SaltedHash(
                    hash = user.token ?: "",
                    salt = user.tokenSalt ?: ""
                )
            )
        } ?: false

        if (!isValidToken) {
            call.respond(
                HttpStatusCode.Unauthorized,
                CommonResponse<SignUpRequest>("error", 404, "Unauthorized")
            )
            return@webSocket
        }

        // Get the partner ID
        val partnerId = UUID.fromString(call.parameters["partnerId"] ?: return@webSocket)
        val partner = userDataSource.getUserById(partnerId) ?: run {
            send("Partner not found.")
            return@webSocket
        }

        // Create and register the current user session
        val currentUserSession = UserSession(user, this)

        mutex.withLock {
            userPairs[userId] = currentUserSession
            userPairs[partnerId]?.let { it.session?.send("User ${user.firstName} ${user.lastName} joined the chat.") }
        }

        send("Welcome to the chat, ${user.firstName} ${user.lastName}! You're chatting with ${partner.firstName} ${partner.lastName}.")

        // Handle incoming messages
        try {
            for (frame in incoming) {
                if (frame is Frame.Text) {
                    val message = frame.readText()
                    handleIncomingMessage(message, userId, user)
                }
            }
        } finally {
            // Cleanup on disconnect
            mutex.withLock {
                userPairs.remove(userId)
            }
        }
    }
}


@Serializable
data class Message(val type: String, val data: String)

suspend fun handleIncomingMessage(message: String, senderId: UUID, partner: User) {
    val jsonMessage = Json.decodeFromString<SendMessage>(message)
    when (jsonMessage.flags) {
        1 -> {
            val textMessage = jsonMessage.data
            broadcastTextMessage(senderId, textMessage, partner)
        }

       2 -> {
            val base64Data = jsonMessage.data // Assume data contains base64 string
            broadcastFile(senderId, base64Data, partner)
        }
    }
}

@Serializable
data class SendMessage(val userName: String, val data: String, val flags : Int)

suspend fun broadcastTextMessage(senderId: UUID, message: String, partner: User) {
    val textMessage = SendMessage(userName = "${partner.firstName} ${partner.lastName}", data = message, 1)

    mutex.withLock {
        userPairs.values.forEach { session ->
            if (session.user.id != senderId) {
                session.session?.sendMessage(textMessage)
            }
        }
    }
}

suspend fun broadcastFile(senderId: UUID, base64Data: String, partner: User) {
    val fileMessage = "data:image/png;base64,$base64Data" // Adjust MIME type as necessary
    val textMessage = SendMessage(userName = "${partner.firstName} ${partner.lastName}", data = fileMessage, 2)

    mutex.withLock {
        userPairs.values.forEach { session ->
            if (session.user.id != senderId) {
                session.session?.sendMessage(textMessage)
            }
        }
    }
}
suspend fun DefaultWebSocketServerSession.sendMessage(message: SendMessage) {
    val jsonMessage = Json.encodeToString(message)
    send(Frame.Text(jsonMessage))
}
