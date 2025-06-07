import crypto from 'crypto';
import { promisify } from 'util'; // <-- Add this line

// --- Configuration Constants ---
// Centralized configuration for easier management and potential externalization
const CONFIG = {
    AES_ALGORITHM: 'aes-256-gcm',
    AES_KEY_LENGTH: 32, // 256 bits for aes-256-gcm
    IV_LENGTH: 12,      // GCM recommended IV length
    SALT_LENGTH: 16,    // Recommended salt length for Scrypt
    RSA_MODULUS_LENGTH: 2048, // Standard RSA key length
    RSA_PADDING: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Recommended RSA padding
    RSA_HASH: 'sha256', // Hashing algorithm for RSA OAEP and Signatures
    KDF_PARAMS: { N: 16384, r: 8, p: 1, keyLen: 32 }, // Scrypt parameters (N, r, p, derived key length)
    DATA_VERSION: 1, // Schema version for encrypted data structure
};

// Regex to validate Base64 characters
const BASE64_REGEX = /^[A-Za-z0-9+/=]*$/;

// --- Custom Error Classes ---
class CryptoError extends Error {
    constructor(message, cause) {
        super(message);
        this.name = 'CryptoError';
        this.cause = cause;
        Object.setPrototypeOf(this, CryptoError.prototype);
    }
}

class InvalidInputError extends CryptoError {
    constructor(message, cause) {
        super(`Invalid Input: ${message}`, cause);
        this.name = 'InvalidInputError';
        Object.setPrototypeOf(this, InvalidInputError.prototype);
    }
}

class DecryptionError extends CryptoError {
    constructor(message, cause) {
        super(`Decryption Failed: ${message}`, cause);
        this.name = 'DecryptionError';
        Object.setPrototypeOf(this, DecryptionError.prototype);
    }
}

class SignatureVerificationError extends CryptoError {
    constructor(message, cause) {
        super(`Signature Verification Failed: ${message}`, cause);
        this.name = 'SignatureVerificationError';
        Object.setPrototypeOf(this, SignatureVerificationError.prototype);
    }
}

// --- Helper Functions ---

/**
 * Converts a Base64 string to a Buffer with strict validation.
 * @param {string} b64String - The Base64 encoded string.
 * @param {string} [name='input'] - A descriptive name for the input in error messages.
 * @returns {Buffer} The decoded Buffer.
 * @throws {InvalidInputError} If the input is not a string, empty, or contains invalid Base64 characters.
 */
function bufferFromBase64(b64String, name = 'input') {
    if (typeof b64String !== 'string' || !b64String.length) {
        throw new InvalidInputError(`${name} must be a non-empty string.`);
    }
    if (!BASE64_REGEX.test(b64String)) {
        throw new InvalidInputError(`${name} contains invalid Base64 characters.`);
    }
    try {
        return Buffer.from(b64String, 'base64');
    } catch (e) {
        throw new InvalidInputError(`Failed to decode ${name} from Base64.`, e);
    }
}

/**
 * Converts a Buffer to a Base64 string.
 * @param {Buffer} buffer - The Buffer to encode.
 * @param {string} [name='buffer'] - A descriptive name for the buffer in error messages.
 * @returns {string} The Base64 encoded string.
 * @throws {InvalidInputError} If the input is not a valid Buffer.
 */
function bufferToBase64(buffer, name = 'buffer') {
    if (!Buffer.isBuffer(buffer)) {
        throw new InvalidInputError(`${name} must be a Buffer.`);
    }
    return buffer.toString('base64');
}

/**
 * Validates a given key/buffer for expected type and length.
 * @param {Buffer} buffer - The buffer to validate.
 * @param {number} expectedLength - The expected byte length of the buffer.
 * @param {string} name - A descriptive name for the key/buffer.
 * @throws {InvalidInputError} If the buffer is not valid or doesn't match the expected length.
 */
function validateBuffer(buffer, expectedLength, name) {
    if (!Buffer.isBuffer(buffer) || buffer.length !== expectedLength) {
        throw new InvalidInputError(`${name} must be a Buffer of length ${expectedLength} bytes.`);
    }
}

/**
 * Validates a string for non-empty status.
 * @param {string} str - The string to validate.
 * @param {string} name - A descriptive name for the string.
 * @throws {InvalidInputError} If the string is not valid or empty.
 */
function validateString(str, name) {
    if (typeof str !== 'string' || str.length === 0) {
        throw new InvalidInputError(`${name} must be a non-empty string.`);
    }
}


// --- RSA Key Generation (Base64 DER) ---
/**
 * Generates an RSA key pair (2048-bit) suitable for encryption/decryption and signing/verification.
 * Keys are encoded in DER format and then Base64 for transport/storage.
 * @returns {{publicKey: string, privateKey: string}} An object containing the Base64-encoded public and private keys.
 * @throws {CryptoError} If key generation fails due to system or invalid configuration.
 */
function generateRsaKeyPairBase64() {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: CONFIG.RSA_MODULUS_LENGTH,
            publicKeyEncoding: { type: 'spki', format: 'der' },
            privateKeyEncoding: { type: 'pkcs8', format: 'der' },
        });
        return {
            publicKey: bufferToBase64(publicKey, 'publicKey'),
            privateKey: bufferToBase64(privateKey, 'privateKey'),
        };
    } catch (e) {
        throw new CryptoError('Failed to generate RSA key pair.', e);
    }
}

// --- AES Encrypt ---
/**
 * Encrypts plaintext using AES-256-GCM. Includes AAD (Additional Authenticated Data) for header integrity.
 * @param {string} plaintext - The data to encrypt (UTF-8 string).
 * @param {Buffer} key - The AES key (32-byte Buffer).
 * @param {Buffer} iv - The Initialization Vector (12-byte Buffer).
 * @param {Buffer} [aad=Buffer.alloc(0)] - Optional Additional Authenticated Data (Buffer). This data is authenticated but not encrypted.
 * @returns {{ciphertext: Buffer, authTag: Buffer}} An object containing the ciphertext and authentication tag.
 * @throws {InvalidInputError} If inputs are invalid (e.g., wrong key/IV length, empty plaintext).
 * @throws {CryptoError} If encryption fails due to internal crypto errors.
 */
function aesEncrypt(plaintext, key, iv, aad = Buffer.alloc(0)) {
    validateString(plaintext, 'Plaintext');
    validateBuffer(key, CONFIG.AES_KEY_LENGTH, 'AES key');
    validateBuffer(iv, CONFIG.IV_LENGTH, 'IV');
    if (!Buffer.isBuffer(aad)) {
        throw new InvalidInputError('AAD must be a Buffer.');
    }

    try {
        const cipher = crypto.createCipheriv(CONFIG.AES_ALGORITHM, key, iv);
        cipher.setAAD(aad); // Set Additional Authenticated Data
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return { ciphertext, authTag };
    } catch (e) {
        throw new CryptoError('AES encryption failed.', e);
    }
}

// --- AES Decrypt ---
/**
 * Decrypts ciphertext using AES-256-GCM. Requires the same AAD used during encryption for successful decryption.
 * @param {Buffer} ciphertext - The encrypted data.
 * @param {Buffer} key - The AES key (32-byte Buffer).
 * @param {Buffer} iv - The Initialization Vector (12-byte Buffer).
 * @param {Buffer} authTag - The authentication tag.
 * @param {Buffer} [aad=Buffer.alloc(0)] - Optional Additional Authenticated Data (Buffer). Must match data used during encryption.
 * @returns {string} The decrypted plaintext (UTF-8 string).
 * @throws {InvalidInputError} If inputs are invalid (e.g., wrong key/IV length, empty ciphertext).
 * @throws {DecryptionError} If decryption fails (e.g., invalid authTag, wrong key/IV, tampered AAD).
 */
function aesDecrypt(ciphertext, key, iv, authTag, aad = Buffer.alloc(0)) {
    if (!Buffer.isBuffer(ciphertext) || ciphertext.length === 0) {
        throw new InvalidInputError('Ciphertext must be a non-empty Buffer.');
    }
    validateBuffer(key, CONFIG.AES_KEY_LENGTH, 'AES key');
    validateBuffer(iv, CONFIG.IV_LENGTH, 'IV');
    if (!Buffer.isBuffer(authTag) || authTag.length === 0) {
        throw new InvalidInputError('AuthTag must be a non-empty Buffer.');
    }
    if (!Buffer.isBuffer(aad)) {
        throw new InvalidInputError('AAD must be a Buffer.');
    }

    try {
        const decipher = crypto.createDecipheriv(CONFIG.AES_ALGORITHM, key, iv);
        decipher.setAAD(aad); // Set Additional Authenticated Data
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        // GCM decryption fails if authTag is invalid or AAD is tampered
        throw new DecryptionError('AES decryption failed. Possible invalid key, IV, authentication tag, or tampered AAD.', e);
    }
}

// --- Scrypt Key Derivation ---
/**
 * Asynchronously derives a strong AES key from a password/KEK and salt using Scrypt.
 * This function is CPU-intensive and designed to be asynchronous to prevent blocking the event loop.
 * @param {string | Buffer} password - The password or Key Encryption Key (KEK).
 * @param {Buffer} salt - The salt (16-byte Buffer).
 * @returns {Promise<Buffer>} A Promise that resolves with the derived AES key (32-byte Buffer).
 * @throws {InvalidInputError} If inputs are invalid (e.g., empty password, wrong salt length).
 * @throws {CryptoError} If key derivation fails due to internal crypto errors.
 */
const scryptAsync = promisify(crypto.scrypt); // <-- Add this line

async function deriveAesKey(password, salt) {
    if (typeof password !== 'string' && !Buffer.isBuffer(password)) {
        throw new InvalidInputError('Password/KEK must be a string or Buffer.');
    }
    if (typeof password === 'string' && password.length === 0) {
        throw new InvalidInputError('Password/KEK cannot be an empty string.');
    }
    validateBuffer(salt, CONFIG.SALT_LENGTH, 'Salt');

    try {
        const derivedKey = await scryptAsync(password, salt, CONFIG.KDF_PARAMS.keyLen, {
            N: CONFIG.KDF_PARAMS.N,
            r: CONFIG.KDF_PARAMS.r,
            p: CONFIG.KDF_PARAMS.p
        });
        return derivedKey;
    } catch (e) {
        throw new CryptoError('Failed to derive AES key using Scrypt.', e);
    }
}

// --- RSA Encrypt/Decrypt ---
/**
 * Encrypts data (Base64 encoded) using an RSA public key with OAEP padding.
 * @param {string} dataB64 - The data to encrypt (Base64 encoded string).
 * @param {string} publicKeyB64 - The RSA public key (Base64 DER encoded string).
 * @returns {string} The encrypted data (Base64 encoded string).
 * @throws {InvalidInputError} If inputs are invalid (e.g., malformed Base64, empty key).
 * @throws {CryptoError} If encryption fails (e.g., data too large for key, invalid key format).
 */
function rsaEncrypt(dataB64, publicKeyB64) {
    const dataBuffer = bufferFromBase64(dataB64, 'data to encrypt');
    const publicKeyBuffer = bufferFromBase64(publicKeyB64, 'RSA public key');

    try {
        const encrypted = crypto.publicEncrypt(
            {
                key: publicKeyBuffer,
                format: 'der',
                type: 'spki', // <-- Add this line
                padding: CONFIG.RSA_PADDING,
                oaepHash: CONFIG.RSA_HASH,
            },
            dataBuffer
        );
        return bufferToBase64(encrypted, 'encrypted RSA data');
    } catch (e) {
        throw new CryptoError('RSA encryption failed. Ensure public key is valid and data fits key size.', e);
    }
}

/**
 * Decrypts data (Base64 encoded) using an RSA private key with OAEP padding.
 * @param {string} dataB64 - The data to decrypt (Base64 encoded string).
 * @param {string} privateKeyB64 - The RSA private key (Base64 DER encoded string).
 * @returns {string} The decrypted data (Base64 encoded string).
 * @throws {InvalidInputError} If inputs are invalid (e.g., malformed Base64, empty key).
 * @throws {DecryptionError} If decryption fails (e.g., invalid key, data not correctly encrypted).
 */
function rsaDecrypt(dataB64, privateKeyB64) {
    const dataBuffer = bufferFromBase64(dataB64, 'data to decrypt');
    const privateKeyBuffer = bufferFromBase64(privateKeyB64, 'RSA private key');

    try {
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKeyBuffer,
                format: 'der',
                type: 'pkcs8', // <-- Add this line
                padding: CONFIG.RSA_PADDING,
                oaepHash: CONFIG.RSA_HASH,
            },
            dataBuffer
        );
        return bufferToBase64(decrypted, 'decrypted RSA data');
    } catch (e) {
        throw new DecryptionError('RSA decryption failed. Ensure private key is valid and data is correctly encrypted.', e);
    }
}

// --- RSA Sign/Verify ---
/**
 * Signs data using an RSA private key with SHA256.
 * @param {string} data - The data to sign (UTF-8 string).
 * @param {string} privateKeyB64 - The RSA private key (Base64 DER encoded string).
 * @returns {string} The signature (Base64 encoded string).
 * @throws {InvalidInputError} If inputs are invalid (e.g., empty data, malformed key).
 * @throws {CryptoError} If signing fails due to internal crypto errors.
 */
function rsaSign(data, privateKeyB64) {
    validateString(data, 'Data to sign');
    const privateKeyBuffer = bufferFromBase64(privateKeyB64, 'RSA private key');

    try {
        const signer = crypto.createSign(CONFIG.RSA_HASH);
        signer.update(data);
        signer.end(); // Finalizes the data for signing
        const signature = signer.sign({
            key: privateKeyBuffer,
            format: 'der',
            type: 'pkcs8', // <-- Add this line
        });
        return bufferToBase64(signature, 'RSA signature');
    } catch (e) {
        throw new CryptoError('RSA signing failed.', e);
    }
}

function rsaVerify(data, signatureB64, publicKeyB64) {
    validateString(data, 'Original data for verification');
    const signatureBuffer = bufferFromBase64(signatureB64, 'signature');
    const publicKeyBuffer = bufferFromBase64(publicKeyB64, 'RSA public key');

    try {
        const verifier = crypto.createVerify(CONFIG.RSA_HASH);
        verifier.update(data);
        verifier.end(); // Finalizes the data for verification
        return verifier.verify(
            {
                key: publicKeyBuffer,
                format: 'der',
                type: 'spki', // <-- Add this line
            },
            signatureBuffer
        );
    } catch (e) {
        throw new CryptoError('RSA verification process failed. Check inputs or key format.', e);
    }
}

// --- Encrypt User Data with KEK and RSA ---
/**
 * Encrypts user data using AES-256-GCM, wrapping the AES key with RSA.
 * A Key Encryption Key (KEK) is used to derive the AES key via Scrypt.
 * Includes authenticated metadata (AAD) and optional RSA signature for integrity/authenticity.
 * @param {object} params - The encryption parameters.
 * @param {string} params.plaintext - The user data to encrypt (UTF-8 string).
 * @param {string} params.rsaPublicKeyB64 - The RSA public key (Base64 DER encoded) for key wrapping.
 * @param {string | Buffer} params.kek - The Key Encryption Key (password or secret). Strongly recommend deriving this from a user's password with a KDF, or using a securely managed secret.
 * @param {boolean} [params.enableSignature=false] - Whether to include an RSA signature of the ciphertext.
 * @param {string} [params.rsaPrivateKeyB64=null] - The RSA private key (Base64 DER encoded) for signing. Required if `enableSignature` is true.
 * @param {string} params.userId - The ID of the user associated with the data.
 * @returns {Promise<object>} A Promise that resolves with the encrypted data object, including metadata and audit trail.
 * @throws {InvalidInputError} If required parameters are missing or invalid.
 * @throws {CryptoError} If any encryption step fails (e.g., key derivation, AES/RSA operation).
 */
async function encryptUserData({
    plaintext,
    rsaPublicKeyB64,
    kek,
    enableSignature = false,
    rsaPrivateKeyB64 = null,
    userId,
}) {
    validateString(plaintext, 'Plaintext');
    validateString(rsaPublicKeyB64, 'RSA public key');
    validateString(userId, 'User ID');
    if (typeof kek !== 'string' && !Buffer.isBuffer(kek)) {
        throw new InvalidInputError('KEK must be a non-empty string or Buffer.');
    }
    if (enableSignature && (typeof rsaPrivateKeyB64 !== 'string' || rsaPrivateKeyB64.length === 0)) {
        throw new InvalidInputError('RSA private key is required for signing when enableSignature is true.');
    }

    try {
        const salt = crypto.randomBytes(CONFIG.SALT_LENGTH);
        const iv = crypto.randomBytes(CONFIG.IV_LENGTH);

        // Derive AES key asynchronously using Scrypt
        const aesKey = await deriveAesKey(kek, salt);

        // Encrypt the AES key with RSA
        const encryptedAesKey = rsaEncrypt(bufferToBase64(aesKey, 'AES key'), rsaPublicKeyB64);

        // Construct the core metadata object for AAD
        const metadata = {
            userId,
            version: CONFIG.DATA_VERSION,
            timestamp: new Date().toISOString(),
            kdf: { N: CONFIG.KDF_PARAMS.N, r: CONFIG.KDF_PARAMS.r, p: CONFIG.KDF_PARAMS.p },
            salt: bufferToBase64(salt, 'salt'),
            iv: bufferToBase64(iv, 'IV'),
            encryptedKey: encryptedAesKey, // Include encrypted AES key in AAD for integrity
        };

        // Convert metadata to a consistent Buffer for AAD
        const aadBuffer = Buffer.from(JSON.stringify(metadata), 'utf8');

        // Encrypt the plaintext using AES-GCM with AAD
        const { ciphertext, authTag } = aesEncrypt(plaintext, aesKey, iv, aadBuffer);

        const result = {
            ...metadata, // Include authenticated metadata directly in the result object
            ciphertext: bufferToBase64(ciphertext, 'ciphertext'),
            authTag: bufferToBase64(authTag, 'authTag'),
            signature: null, // Will be populated if enabled
            audit: [], // Initialize audit log
        };

        // Apply RSA signature if enabled
        if (enableSignature && rsaPrivateKeyB64) {
            result.signature = rsaSign(result.ciphertext, rsaPrivateKeyB64);
        }

        // Add audit log entry for encryption
        result.audit.push({
            action: 'encrypt',
            userId,
            timestamp: new Date().toISOString(),
        });

        return result;
    } catch (e) {
        throw new CryptoError('Failed to encrypt user data.', e);
    }
}

// --- Decrypt User Data with KEK and RSA ---
/**
 * Decrypts user data encrypted by `encryptUserData`.
 * Verifies the integrity of the AES key using Scrypt and RSA decryption, and authenticates metadata via AAD.
 * Optionally verifies the data signature if present.
 * @param {object} params - The decryption parameters.
 * @param {object} params.encrypted - The encrypted data object (must contain all fields from `encryptUserData` output).
 * @param {string} params.rsaPrivateKeyB64 - The RSA private key (Base64 DER encoded) for key unwrapping.
 * @param {string | Buffer} params.kek - The Key Encryption Key (password or secret). Must match the one used during encryption.
 * @param {string} [params.rsaPublicKeyB64=null] - The RSA public key (Base64 DER encoded) for signature verification. Required if `verifySignature` is true.
 * @param {boolean} [params.verifySignature=false] - Whether to verify the RSA signature.
 * @returns {Promise<string>} A Promise that resolves with the decrypted plaintext.
 * @throws {InvalidInputError} If encrypted data structure is invalid or keys are missing/malformed.
 * @throws {DecryptionError} If decryption fails (e.g., invalid KEK, RSA private key, tampered AAD, corrupted data).
 * @throws {SignatureVerificationError} If signature verification is enabled and fails.
 * @throws {CryptoError} For other unexpected errors during the process.
 */
async function decryptUserData({
    encrypted,
    rsaPrivateKeyB64,
    kek,
    rsaPublicKeyB64 = null,
    verifySignature = false,
}) {
    if (typeof encrypted !== 'object' || encrypted === null) {
        throw new InvalidInputError('Encrypted data must be a non-null object.');
    }
    validateString(rsaPrivateKeyB64, 'RSA private key');
    if (typeof kek !== 'string' && !Buffer.isBuffer(kek)) {
        throw new InvalidInputError('KEK must be a non-empty string or Buffer.');
    }
    if (verifySignature && (!encrypted.signature || typeof rsaPublicKeyB64 !== 'string' || rsaPublicKeyB64.length === 0)) {
        throw new InvalidInputError('RSA public key and a signature are required for signature verification.');
    }

    try {
        // Validate and convert Base64 fields to Buffers
        const encryptedSalt = bufferFromBase64(encrypted.salt, 'salt');
        const encryptedIv = bufferFromBase64(encrypted.iv, 'IV');
        const encryptedCiphertext = bufferFromBase64(encrypted.ciphertext, 'ciphertext');
        const encryptedAuthTag = bufferFromBase64(encrypted.authTag, 'authTag');

        // Extract metadata for AAD (must match the structure used during encryption)
        const metadataForAad = {
            userId: encrypted.userId,
            version: encrypted.version,
            timestamp: encrypted.timestamp,
            kdf: encrypted.kdf,
            salt: encrypted.salt, // Use Base64 string for consistency in AAD JSON
            iv: encrypted.iv,     // Use Base64 string for consistency in AAD JSON
            encryptedKey: encrypted.encryptedKey,
        };
        const aadBuffer = Buffer.from(JSON.stringify(metadataForAad), 'utf8');

        // Derive AES key asynchronously using parameters from encrypted data
        const derivedAesKey = await deriveAesKey(kek, encryptedSalt);

        // Decrypt the AES key wrapped by RSA
        const decryptedAesKeyB64 = rsaDecrypt(encrypted.encryptedKey, rsaPrivateKeyB64);
        const decryptedAesKey = bufferFromBase64(decryptedAesKeyB64, 'decrypted AES key');

        // Crucial check: Ensure the derived KEK matches the RSA-decrypted KEK
        // Using timingSafeEqual to prevent timing attacks
        if (!crypto.timingSafeEqual(derivedAesKey, decryptedAesKey)) {
            throw new DecryptionError('Invalid Key Encryption Key (KEK) or corrupted encrypted key.');
        }

        // Signature Verification (if enabled)
        if (verifySignature && encrypted.signature && rsaPublicKeyB64) {
            const isValid = rsaVerify(encrypted.ciphertext, encrypted.signature, rsaPublicKeyB64);
            if (!isValid) {
                throw new SignatureVerificationError('Data signature verification failed.');
            }
        }

        // Perform final AES decryption using the derived AES key and AAD
        const plaintext = aesDecrypt(
            encryptedCiphertext,
            derivedAesKey,
            encryptedIv,
            encryptedAuthTag,
            aadBuffer // Pass the AAD buffer
        );

        // Create a copy of the audit log to avoid mutating the original input object
        const auditLogCopy = Array.isArray(encrypted.audit) ? [...encrypted.audit] : [];
        auditLogCopy.push({
            action: 'decrypt',
            userId: encrypted.userId || 'unknown',
            timestamp: new Date().toISOString(),
        });
        // In a real system, this updated audit log would be persisted separately or returned.
        // For this function, we return only the plaintext.

        return plaintext;

    } catch (e) {
        // Re-throw specific errors, wrap others as general CryptoError
        if (e instanceof CryptoError) {
            throw e;
        }
        throw new CryptoError('An unexpected error occurred during user data decryption.', e);
    }
}

// --- Demo ---
/**
 * Demonstrates the encryption and decryption process with comprehensive test cases,
 * including error handling and AAD validation.
 * @returns {Promise<void>}
 */
async function test() {
    console.log("--- Starting Encryption/Decryption Demo (Enhanced) ---");

    try {
        // 1. Generate RSA Keys (one-time setup for the application/system)
        const { publicKey, privateKey } = generateRsaKeyPairBase64();
        console.log("RSA Key Pair Generated successfully.");

        // 2. Define KEK (Key Encryption Key) and Message
        // IMPORTANT: In a real application, 'kek' should be:
        //    a) Derived from a user's password using a strong KDF (like Scrypt itself)
        //    b) A securely managed secret key (e.g., loaded from environment variables, KMS, HSM)
        //    NEVER hardcode or store user passwords directly.
        const kek = Buffer.from('this-is-a-very-strong-and-long-user-password-or-master-secret-key-for-the-demo-only');
        const message = 'Ultra-secure user data! This message is a secret and its metadata is authenticated.';
        const userId = 'demoUser123';

        console.log(`\nOriginal Message: "${message}"`);
        console.log(`Using KEK (first 10 chars): "${kek.toString('utf8').substring(0, 10)}..."`);
        console.log(`User ID: "${userId}"`);


        // 3. Encrypt Data
        console.log("\n--- Encrypting Data ---");
        const encrypted = await encryptUserData({
            plaintext: message,
            rsaPublicKeyB64: publicKey,
            kek: kek,
            enableSignature: true,
            rsaPrivateKeyB64: privateKey,
            userId: userId,
        });
        console.log("Encrypted Object (partial view):\n", JSON.stringify(encrypted, null, 2).substring(0, 500) + '...');
        console.log("Encryption successful.");

        // 4. Decrypt Data
        console.log("\n--- Decrypting Data ---");
        const decrypted = await decryptUserData({
            encrypted: encrypted,
            rsaPrivateKeyB64: privateKey,
            kek: kek,
            rsaPublicKeyB64: publicKey,
            verifySignature: true,
        });
        console.log("Decrypted Message:", decrypted);
        console.log("Decryption successful.");

        // 5. Verification
        if (decrypted === message) {
            console.log("\nVerification: SUCCESS! Decrypted message matches original.");
        } else {
            console.error("\nVerification: FAILED! Decrypted message does NOT match original.");
            throw new Error("Decryption mismatch");
        }

        console.log("\n--- Testing Error Cases ---");

        // Test Case 1: Incorrect KEK during decryption
        try {
            console.log("\nTesting: Decryption with incorrect KEK...");
            const incorrectKek = Buffer.from('wrong-password-or-secret');
            await decryptUserData({
                encrypted: encrypted,
                rsaPrivateKeyB64: privateKey,
                kek: incorrectKek,
                rsaPublicKeyB64: publicKey,
                verifySignature: true,
            });
            console.error("FAIL: Decryption with incorrect KEK should have thrown an error.");
        } catch (e) {
            console.log(`PASS: Caught expected error (Incorrect KEK): ${e.name}: ${e.message}`);
        }

        // Test Case 2: Signature verification failure (if enabled)
        if (encrypted.signature) {
            console.log("\nTesting: Signature verification failure (tampered ciphertext)...");
            const tamperedEncrypted = { ...encrypted, ciphertext: bufferToBase64(crypto.randomBytes(encrypted.ciphertext.length / 4 * 3)) };
            try {
                await decryptUserData({
                    encrypted: tamperedEncrypted,
                    rsaPrivateKeyB64: privateKey,
                    kek: kek,
                    rsaPublicKeyB64: publicKey,
                    verifySignature: true,
                });
                console.error("FAIL: Signature verification should have failed.");
            } catch (e) {
                console.log(`PASS: Caught expected error (Signature Failure): ${e.name}: ${e.message}`);
            }
        }

        // Test Case 3: AAD tampering (e.g., changing userId in the encrypted object)
        console.log("\nTesting: AAD tampering failure (changed userId)...");
        const tamperedEncryptedMetadata = { ...encrypted, userId: 'evilUser' };
        try {
            await decryptUserData({
                encrypted: tamperedEncryptedMetadata,
                rsaPrivateKeyB64: privateKey,
                kek: kek,
                rsaPublicKeyB64: publicKey,
                verifySignature: true,
            });
            console.error("FAIL: AAD tampering should have failed decryption.");
        } catch (e) {
            console.log(`PASS: Caught expected error (AAD Tampering): ${e.name}: ${e.message}`);
        }

        // Test Case 4: Missing required field in encrypted object
        try {
            console.log("\nTesting: Decryption with missing IV in encrypted object...");
            const missingIvEncrypted = { ...encrypted };
            delete missingIvEncrypted.iv; // Simulate missing IV
            await decryptUserData({
                encrypted: missingIvEncrypted,
                rsaPrivateKeyB64: privateKey,
                kek: kek,
            });
            console.error("FAIL: Decryption with missing IV should have thrown an InvalidInputError.");
        } catch (e) {
            console.log(`PASS: Caught expected error (Missing IV): ${e.name}: ${e.message}`);
        }

        // Test Case 5: Invalid Base64 input for key
        try {
            console.log("\nTesting: RSA Decryption with invalid Base64 private key...");
            await rsaDecrypt("someB64Data", "not-a-valid-base64-key-!");
            console.error("FAIL: Invalid Base64 key should have thrown an error.");
        } catch (e) {
            console.log(`PASS: Caught expected error (Invalid Base64): ${e.name}: ${e.message}`);
        }


    } catch (e) {
        console.error("\n--- Demo Encountered an Unexpected Critical Error ---");
        console.error(e);
        if (e.cause) {
            console.error("Caused by:", e.cause);
        }
    } finally {
        console.log("\n--- Demo Finished ---");
    }
}

// Execute the demo
test();