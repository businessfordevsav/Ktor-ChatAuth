package com.routiner.core.db

import com.mongodb.ConnectionString
import com.mongodb.MongoClientSettings
import com.mongodb.kotlin.client.coroutine.MongoClient
import com.mongodb.kotlin.client.coroutine.MongoDatabase
import io.ktor.server.application.*
import org.bson.UuidRepresentation

fun Application.configureMongo() {
    val connection = System.getenv("mongo.connection")
    val database = System.getenv("mongo.database")

    MongoConfig.configure(connection, database)
}

object MongoConfig {
    private lateinit var client: MongoClient
    private lateinit var database: MongoDatabase

    fun configure(connection: String, database: String) {
        client = MongoClient.create(
            MongoClientSettings.builder()
                // We want to use UUIDs as type at our DOC objects.
                .uuidRepresentation(UuidRepresentation.STANDARD)
                .applyConnectionString(ConnectionString(connection)).build()
        )
        MongoConfig.database = client.getDatabase(database)
    }

    fun client(): MongoClient {
        return client
    }

    fun database(): MongoDatabase {
        return database
    }
}
