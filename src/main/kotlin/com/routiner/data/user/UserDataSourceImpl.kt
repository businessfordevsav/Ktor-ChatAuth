package com.routiner.data.user

import com.mongodb.client.model.Filters.eq
import com.mongodb.client.model.Updates
import com.routiner.core.db.MongoConfig
import kotlinx.coroutines.flow.first
import org.bson.Document
import java.util.*

class UserDataSourceImpl : UserDataSource {
    private val collection = MongoConfig.database().getCollection<User>("user")
    override suspend fun getUserByEmail(email: String): User {
        val document = collection.find(eq("email", email)).first()
        return document
    }

    override suspend fun isUserExists(key: String, value: Any?): Boolean {
        val count = collection.countDocuments(eq(key, value))
        return count > 0
    }

    override suspend fun getUserById(id: UUID): User {
        val query = Document("_id", id)
        return collection.find(query).first()
    }

    override suspend fun insertUser(user: User): User? {
        return when (collection.insertOne(user).wasAcknowledged()) {
            true -> user
            false -> null
        }
    }

    override suspend fun updateUserToken(id: UUID, token: String, tokenSalt: String): Boolean {

        val query = eq("_id", id)
        val updates = Updates.combine(
            Updates.set(User::token.name, token),
            Updates.set(User::tokenSalt.name, tokenSalt)
        )
        return collection.updateOne(query, updates).matchedCount > 0
    }

    override suspend fun updateUser(id: UUID, fieldMap: HashMap<String, Any>): User? {
        val query = eq("_id", id)
        var updates = Updates.combine()

        fieldMap.forEach {
            updates = Updates.combine(
                updates,
                Updates.set(it.key, it.value),
            )
        }

        println("updateUser :: $updates")

        return when (collection.updateOne(query, updates).wasAcknowledged()) {
            true -> getUserById(id)
            false -> null
        }
    }
}