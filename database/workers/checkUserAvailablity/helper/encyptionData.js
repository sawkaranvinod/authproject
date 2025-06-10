import crypto from "crypto";
import pkg from "scrypt-js";
const { scrypt: scryptJS } = pkg;

// 🔑 Generate RSA Keys, Salt, IV
export function generateKeysAndSecrets(method = "standard") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });

  const salt = crypto.randomBytes(16); // 128-bit salt
  const iv = crypto.randomBytes(16);   // 128-bit IV

  // Parameters based on method
  const r = 8;
  const p = 1;
  const n = method === "premium" ? 2 ** 16 : 2 ** 14;

  return {
    publicKey,
    privateKey,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    r,
    p,
    n,
  };
}

// 🔐 Encrypt function
export async function encryptMessage(plaintext, publicKey, saltBase64, ivBase64, r, p, n) {
  const salt = Buffer.from(saltBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");
  const password = crypto.randomBytes(32); // random 256-bit

  const passwordUint8 = Uint8Array.from(password);
  const saltUint8 = Uint8Array.from(salt);

  const aesKey = await scryptJS(passwordUint8, saltUint8, n, r, p, 32);

  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(aesKey), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const ciphertext = encrypted.toString("base64");

  const encryptedAESPassword = crypto.publicEncrypt(publicKey, password).toString("base64");

  const encryptedMessage = `${ciphertext}:::${encryptedAESPassword}`;
  return { encryptedMessage };
}

// 🔓 Decrypt function
export async function decryptMessage(encryptedMessage, privateKey, saltBase64, ivBase64, r, p, n) {
  const [ciphertextBase64, encryptedAESPasswordBase64] = encryptedMessage.split(":::");
  const salt = Buffer.from(saltBase64, "base64");
  const iv = Buffer.from(ivBase64, "base64");

  const decryptedPassword = crypto.privateDecrypt(
    privateKey,
    Buffer.from(encryptedAESPasswordBase64, "base64")
  );

  const passwordUint8 = Uint8Array.from(decryptedPassword);
  const saltUint8 = Uint8Array.from(salt);

  const aesKey = await scryptJS(passwordUint8, saltUint8, n, r, p, 32);

  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(aesKey), iv);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertextBase64, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}
