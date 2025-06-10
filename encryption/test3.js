const crypto = require("crypto");

// ✅ 1. Generate RSA Key Pair, Salt, and IV
function generateKeysAndSecrets() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });

  const salt = crypto.randomBytes(16); // 128-bit salt
  const iv = crypto.randomBytes(16);   // 128-bit IV

  return {
    publicKey,
    privateKey,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
  };
}

// 🔐 2. Encrypt using RSA + AES-256-CBC with Salt-based KDF
function encryptMessage(plaintext, publicKey, saltBase64, ivBase64) {
  const salt = Buffer.from(saltBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const password = crypto.randomBytes(32).toString("base64"); // used as base for AES key
  const aesKey = crypto.scryptSync(password, salt, 32); // derive key with salt

  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const ciphertext = encrypted.toString("base64");

  const encryptedAESPassword = crypto.publicEncrypt(publicKey, Buffer.from(password)).toString("base64");

  return {
    ciphertext,
    encryptedAESPassword,
  };
}

// 🔓 3. Decrypt
function decryptMessage(ciphertextBase64, encryptedAESPasswordBase64, privateKey, saltBase64, ivBase64) {
  const salt = Buffer.from(saltBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const decryptedPassword = crypto.privateDecrypt(
    privateKey,
    Buffer.from(encryptedAESPasswordBase64, "base64")
  ).toString("utf8");

  const aesKey = crypto.scryptSync(decryptedPassword, salt, 32);
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextBase64, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}
