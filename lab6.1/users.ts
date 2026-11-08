import crypto = require("node:crypto");
import path = require("node:path");
import sqlite3 = require("sqlite3");

const sqlite = sqlite3.verbose();

const DEFAULT_ADMIN_USERNAME = "admin";
const DEFAULT_ADMIN_PASSWORD = "password123";
const HASH_ALGORITHM = "sha256";
const HASH_ITERATIONS = 100_000;
const HASH_LENGTH = 32;
const SALT_SIZE = 16;

export interface UserRecord {
	username: string;
	password_hash: Buffer | null;
	salt: Buffer | null;
}

interface UserRow {
	username: string;
	password_hash: Buffer | null;
	salt: Buffer | null;
}

function getDatabaseFile(): string {
	return process.env.USERS_DB_FILE || path.join(__dirname, "users.db");
}

function logCall(name: string, parameters: Record<string, unknown>): void {
	console.log(`[users.ts] ${name} called ${JSON.stringify(parameters)}`);
}

function openDatabase(): Promise<sqlite3.Database> {
	return new Promise((resolve, reject) => {
		const database = new sqlite.Database(getDatabaseFile(), (error) => {
			if (error) {
				reject(error);
			} else {
				resolve(database);
			}
		});
	});
}

function closeDatabase(database: sqlite3.Database): Promise<void> {
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

async function withDatabase<T>(
	operation: (database: sqlite3.Database) => Promise<T>
): Promise<T> {
	const database = await openDatabase();

	try {
		return await operation(database);
	} finally {
		await closeDatabase(database);
	}
}

function run(
	database: sqlite3.Database,
	sql: string,
	parameters: unknown[] = []
): Promise<void> {
	return new Promise((resolve, reject) => {
		database.run(sql, parameters, (error) => {
			if (error) {
				reject(error);
			} else {
				resolve();
			}
		});
	});
}

function get<T>(
	database: sqlite3.Database,
	sql: string,
	parameters: unknown[] = []
): Promise<T | undefined> {
	return new Promise((resolve, reject) => {
		database.get(sql, parameters, (error, row) => {
			if (error) {
				reject(error);
			} else {
				resolve(row as T | undefined);
			}
		});
	});
}

function all<T>(
	database: sqlite3.Database,
	sql: string,
	parameters: unknown[] = []
): Promise<T[]> {
	return new Promise((resolve, reject) => {
		database.all(sql, parameters, (error, rows) => {
			if (error) {
				reject(error);
			} else {
				resolve(rows as T[]);
			}
		});
	});
}

function hashPassword(password: string, salt: Buffer): Promise<Buffer> {
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

export async function initialize_users_table(): Promise<void> {
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

		const columns = await all<{ name: string }>(
			database,
			"PRAGMA table_info(users)"
		);
		const columnNames = columns.map((column) => column.name);

		if (!columnNames.includes("password_hash")) {
			await run(database, "ALTER TABLE users ADD COLUMN password_hash BLOB");
		}

		if (!columnNames.includes("salt")) {
			await run(database, "ALTER TABLE users ADD COLUMN salt BLOB");
		}

		const admin = await get<{ username: string }>(
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

export async function add_user(username: string, password: string): Promise<boolean> {
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
	} catch (error: unknown) {
		if (
			error instanceof Error &&
			"code" in error &&
			typeof error.code === "string" &&
			error.code.startsWith("SQLITE_CONSTRAINT")
		) {
			return false;
		}
		throw error;
	}
}

export async function get_user(username: string): Promise<UserRecord | null> {
	logCall("get_user", { username });

	const row = await withDatabase((database) => get<UserRow>(
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

export async function user_exists(username: string): Promise<boolean> {
	logCall("user_exists", { username });

	const row = await withDatabase((database) => get<{ found: number }>(
		database,
		"SELECT 1 AS found FROM users WHERE username = ?",
		[username]
	));

	return Boolean(row);
}

export async function authenticate_user(
	username: string,
	password: string
): Promise<boolean> {
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
		.catch((error: unknown) => {
			const message = error instanceof Error ? error.message : String(error);
			console.error("Failed to initialize users table:", message);
			process.exitCode = 1;
		});
}
