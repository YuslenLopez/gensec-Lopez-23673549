"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const sqlite3 = require("sqlite3").verbose();

const DEFAULT_ADMIN_USERNAME = "admin";
const DEFAULT_ADMIN_PASSWORD = "password123";
const HASH_ALGORITHM = "sha256";
const HASH_ITERATIONS = 100_000;
const HASH_LENGTH = 32;
const SALT_SIZE = 16;

function getDatabaseFile() {
	return process.env.USERS_DB_FILE || path.join(__dirname, "users.db");
}

function logCall(name, parameters) {
	console.log(`[users.js] ${name} called ${JSON.stringify(parameters)}`);
}

function openDatabase() {
	return new Promise((resolve, reject) => {
		const database = new sqlite3.Database(getDatabaseFile(), (error) => {
			if (error) {
				reject(error);
			} else {
				resolve(database);
			}
		});
	});
}

function closeDatabase(database) {
	return new Promise((resolve, reject) => {
		database.close((error) => {
			if (error) {
				reject(error);
			} else {
				resolve();
			}
		});
	});
}

async function withDatabase(operation) {
	const database = await openDatabase();

	try {
		return await operation(database);
	} finally {
		await closeDatabase(database);
	}
}

function run(database, sql, parameters = []) {
	return new Promise((resolve, reject) => {
		database.run(sql, parameters, function onRun(error) {
			if (error) {
				reject(error);
			} else {
				resolve({ lastID: this.lastID, changes: this.changes });
			}
		});
	});
}

function get(database, sql, parameters = []) {
	return new Promise((resolve, reject) => {
		database.get(sql, parameters, (error, row) => {
			if (error) {
				reject(error);
			} else {
				resolve(row);
			}
		});
	});
}

function all(database, sql, parameters = []) {
	return new Promise((resolve, reject) => {
		database.all(sql, parameters, (error, rows) => {
			if (error) {
				reject(error);
			} else {
				resolve(rows);
			}
		});
	});
}

function hashPassword(password, salt) {
	return new Promise((resolve, reject) => {
		crypto.pbkdf2(
			password,
			salt,
			HASH_ITERATIONS,
			HASH_LENGTH,
			HASH_ALGORITHM,
			(error, passwordHash) => {
				if (error) {
					reject(error);
				} else {
					resolve(passwordHash);
				}
			}
		);
	});
}

async function initialize_users_table() {
	const databaseFile = getDatabaseFile();
	logCall("initialize_users_table", { databaseFile });

	await withDatabase(async (database) => {
		await run(database, `
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT UNIQUE NOT NULL,
				password_hash BLOB,
				salt BLOB
			)
		`);

		const columns = await all(database, "PRAGMA table_info(users)");
		const columnNames = columns.map((column) => column.name);

		if (!columnNames.includes("password_hash")) {
			await run(database, "ALTER TABLE users ADD COLUMN password_hash BLOB");
		}

		if (!columnNames.includes("salt")) {
			await run(database, "ALTER TABLE users ADD COLUMN salt BLOB");
		}

		const admin = await get(
			database,
			"SELECT username FROM users WHERE username = ?",
			[DEFAULT_ADMIN_USERNAME]
		);

		if (!admin) {
			const salt = crypto.randomBytes(SALT_SIZE);
			const passwordHash = await hashPassword(DEFAULT_ADMIN_PASSWORD, salt);

			await run(
				database,
				"INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
				[DEFAULT_ADMIN_USERNAME, passwordHash, salt]
			);
		}
	});
}

async function add_user(username, password) {
	logCall("add_user", { username, password: "[REDACTED]" });

	if (!username || !password) {
		return false;
	}

	const salt = crypto.randomBytes(SALT_SIZE);
	const passwordHash = await hashPassword(password, salt);

	try {
		await withDatabase((database) => run(
			database,
			"INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
			[username, passwordHash, salt]
		));
		return true;
	} catch (error) {
		if (error.code && error.code.startsWith("SQLITE_CONSTRAINT")) {
			return false;
		}
		throw error;
	}
}

async function get_user(username) {
	logCall("get_user", { username });

	const row = await withDatabase((database) => get(
		database,
		`SELECT username, password_hash, salt
		 FROM users
		 WHERE username = ?`,
		[username]
	));

	if (!row) {
		return null;
	}

	return {
		username: row.username,
		password_hash: row.password_hash,
		salt: row.salt
	};
}

async function user_exists(username) {
	logCall("user_exists", { username });

	const row = await withDatabase((database) => get(
		database,
		"SELECT 1 AS found FROM users WHERE username = ?",
		[username]
	));

	return Boolean(row);
}

async function authenticate_user(username, password) {
	logCall("authenticate_user", { username, password: "[REDACTED]" });

	const user = await get_user(username);
	if (!user || !user.password_hash || !user.salt) {
		return false;
	}

	const enteredHash = await hashPassword(password, user.salt);
	return crypto.timingSafeEqual(user.password_hash, enteredHash);
}

if (require.main === module) {
	initialize_users_table()
		.then(() => console.log("Users table initialized."))
		.catch((error) => {
			console.error("Failed to initialize users table:", error.message);
			process.exitCode = 1;
		});
}

module.exports = {
	add_user,
	authenticate_user,
	get_user,
	initialize_users_table,
	user_exists
};
