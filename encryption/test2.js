const crypto = require("crypto");

// 🔑 1. Generate RSA Key Pair (PEM string format)
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "pkcs1", // You asked for PKCS1
    format: "pem", // String format
  },
  privateKeyEncoding: {
    type: "pkcs1",
    format: "pem",
  },
});

console.log("publicKey",publicKey)

// 🔐 2. Derive AES-256 Key using scrypt with custom N, r, p
const password = "your-strong-password"; // Use a secure password!
const salt = crypto.randomBytes(16);     // 128-bit salt

const n = 2 ** 14; // Cost factor
const r = 8;       // Block size
const p = 1;       // Parallelization

const aesKey = crypto.scryptSync(password, salt, 32, { n, r, p }); // 32 bytes = 256 bits
const iv = crypto.randomBytes(16);   // 128-bit IV

// Convert AES key, salt, IV to base64 strings
const aesKeyStr = aesKey.toString("base64");
const ivStr = iv.toString("base64");
const saltStr = salt.toString("base64");

// 🔐 3. Encrypt AES key using RSA public key
const encryptedAESKey = crypto.publicEncrypt(publicKey, aesKey).toString("base64");

// 🔒 4. Encrypt Data using AES-256-CBC
function encryptAES(plaintext, aesKeyBase64, ivBase64) {
  const key = Buffer.from(aesKeyBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return encrypted.toString("base64");
}

// 🔓 5. Decrypt Data using AES-256-CBC
function decryptAES(ciphertextBase64, aesKeyBase64, ivBase64) {
  const key = Buffer.from(aesKeyBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextBase64, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// 🔓 6. Decrypt AES Key using Private Key
const decryptedAESKey = crypto.privateDecrypt(
  privateKey,
  Buffer.from(encryptedAESKey, "base64")
).toString("base64");

// 📦 7. Example message
const message = "This is a secret message!";
const ciphertext = encryptAES(message, aesKeyStr, ivStr);
const decryptedMessage = decryptAES(ciphertext, decryptedAESKey, ivStr);

// ✅ 8. Output everything
console.log("🔑 Public Key (String PEM):\n", publicKey);
console.log("🔐 Private Key (String PEM):\n", privateKey);
console.log("🧂 Salt (base64):", saltStr);
console.log("🧊 IV (base64):", ivStr);
console.log("🔑 AES Key (base64):", aesKeyStr);
console.log("🔒 Encrypted AES Key (base64):", encryptedAESKey);
console.log("📦 Encrypted Message:", ciphertext);
console.log("✅ Decrypted Message:", decryptedMessage);
