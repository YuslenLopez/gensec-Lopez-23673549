"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const users = require("./users");

test("users.js stores and verifies password hashes", async (t) => {
  const originalDatabaseFile = process.env.USERS_DB_FILE;
  const temporaryDirectory = await fs.mkdtemp(
    path.join(os.tmpdir(), "sqlite-users-test-")
  );
  process.env.USERS_DB_FILE = path.join(temporaryDirectory, "users.db");

  try {
    await t.test("initializes admin with a PBKDF2-SHA-256 hash", async () => {
      await users.initialize_users_table();

      const admin = await users.get_user("admin");
      assert.equal(admin.username, "admin");
      assert.ok(Buffer.isBuffer(admin.password_hash));
      assert.ok(Buffer.isBuffer(admin.salt));

      const expectedHash = crypto.pbkdf2Sync(
        "password123",
        admin.salt,
        100_000,
        32,
        "sha256"
      );
      assert.deepEqual(admin.password_hash, expectedHash);
      assert.equal(await users.authenticate_user("admin", "password123"), true);
      assert.equal(await users.authenticate_user("admin", "incorrect"), false);
    });

    await t.test("adds users without storing plaintext passwords", async () => {
      const capturedLogs = [];
      const originalConsoleLog = console.log;
      console.log = (...arguments_) => capturedLogs.push(arguments_.join(" "));

      try {
        assert.equal(await users.add_user("alice", "alice-secret"), true);
      } finally {
        console.log = originalConsoleLog;
      }

      const user = await users.get_user("alice");
      assert.equal(user.username, "alice");
      assert.notDeepEqual(user.password_hash, Buffer.from("alice-secret"));
      assert.equal(await users.user_exists("alice"), true);
      assert.equal(await users.authenticate_user("alice", "alice-secret"), true);
      assert.equal(await users.authenticate_user("alice", "wrong-secret"), false);
      assert.ok(capturedLogs.some((line) => line.includes('"username":"alice"')));
      assert.ok(capturedLogs.some((line) => line.includes('"password":"[REDACTED]"')));
      assert.ok(capturedLogs.every((line) => !line.includes("alice-secret")));
    });

    await t.test("rejects duplicate usernames", async () => {
      assert.equal(await users.add_user("alice", "another-secret"), false);
    });
  } finally {
    if (originalDatabaseFile === undefined) {
      delete process.env.USERS_DB_FILE;
    } else {
      process.env.USERS_DB_FILE = originalDatabaseFile;
    }
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
});