import crypto from "crypto"

// Storage arrays
let users = [];
let sessions = [];
let keyPairs = [];

// Utility functions
function findUser(username) {
    return users.find(user => user.username === username);
}

function findSession(sessionToken) {
    return sessions.find(session => session.sessionToken === sessionToken);
}

function findKeyPair(userId) {
    return keyPairs.find(pair => pair.userId === userId);
}

// Generate RSA key pair
function generateKeyPair(userId) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'der'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'der'
        }
    });

    const keyPairData = {
        userId,
        publicKey: publicKey.toString('hex'),
        privateKey: privateKey.toString('hex')
    };

    keyPairs.push(keyPairData);
    return keyPairData;
}

// Generate HMAC authentication tag
function generateAuthTag(data, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// Verify HMAC authentication tag
function verifyAuthTag(data, tag, key) {
    const computedTag = generateAuthTag(data, key);
    return crypto.timingSafeEqual(
        Buffer.from(tag, 'hex'),
        Buffer.from(computedTag, 'hex')
    );
}

// Encrypt data with public key
function encryptWithPublicKey(data, publicKeyHex) {
    const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
    return crypto.publicEncrypt({
        key: publicKeyBuffer,
        format: 'der',
        type: 'spki',
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, Buffer.from(data));
}

// Decrypt data with private key
function decryptWithPrivateKey(encryptedData, privateKeyHex) {
    const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');
    return crypto.privateDecrypt({
        key: privateKeyBuffer,
        format: 'der',
        type: 'pkcs8',
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, encryptedData);
}

// Register a new user
function registerUser(username, password) {
    const existingUser = findUser(username);
    if (existingUser) {
        throw new Error('User already exists');
    }

    // Generate salt and hash password
    const salt = crypto.randomBytes(32).toString('hex');
    const hashedPassword = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), 100000, 64, 'sha512').toString('hex');
    
    // Generate RSA key pair for the user
    const keyPair = generateKeyPair(username);
    
    // Generate HMAC key for authentication tags
    const hmacKey = crypto.randomBytes(32).toString('hex');

    const user = {
        username,
        salt,
        hashedPassword,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        hmacKey,
        createdAt: new Date().toISOString()
    };

    users.push(user);
    
    return {
        username,
        publicKey: keyPair.publicKey,
        message: 'User registered successfully'
    };
}

// Authenticate user and create encrypted session
function authenticateUser(username, password) {
    const user = findUser(username);
    if (!user) {
        throw new Error('User not found');
    }

    // Verify password
    const salt = Buffer.from(user.salt, 'hex');
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    
    if (hashedPassword !== user.hashedPassword) {
        throw new Error('Invalid credentials');
    }

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const sessionData = {
        username,
        loginTime: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    // Encrypt session data with user's public key
    const sessionDataStr = JSON.stringify(sessionData);
    const encryptedSession = encryptWithPublicKey(sessionDataStr, user.publicKey);
    const encryptedSessionB64 = encryptedSession.toString('base64');
    
    // Generate authentication tag for the encrypted session
    const hmacKey = Buffer.from(user.hmacKey, 'hex');
    const authTag = generateAuthTag(encryptedSessionB64, hmacKey);

    const sessionInfo = {
        sessionToken,
        encryptedSession: encryptedSessionB64,
        authTag,
        publicKey: user.publicKey
    };

    const sessionRecord = {
        sessionToken,
        username,
        encryptedSession: encryptedSessionB64,
        authTag,
        createdAt: new Date().toISOString()
    };

    sessions.push(sessionRecord);
    return sessionInfo;
}

// Verify and decrypt session
function verifySession(sessionToken, privateKeyHexString) {
    const session = findSession(sessionToken);
    if (!session) {
        throw new Error('Invalid session token');
    }

    const user = findUser(session.username);
    if (!user) {
        throw new Error('User not found');
    }

    // Verify authentication tag
    const hmacKey = Buffer.from(user.hmacKey, 'hex');
    
    if (!verifyAuthTag(session.encryptedSession, session.authTag, hmacKey)) {
        throw new Error('Authentication tag verification failed - session may be tampered');
    }

    // Decrypt session data with private key
    try {
        const encryptedSessionBuffer = Buffer.from(session.encryptedSession, 'base64');
        const decryptedSessionData = decryptWithPrivateKey(encryptedSessionBuffer, privateKeyHexString);
        const sessionData = JSON.parse(decryptedSessionData.toString());
        
        // Check if session is expired
        if (new Date() > new Date(sessionData.expiresAt)) {
            // Remove expired session
            const sessionIndex = sessions.findIndex(s => s.sessionToken === sessionToken);
            if (sessionIndex > -1) {
                sessions.splice(sessionIndex, 1);
            }
            throw new Error('Session expired');
        }

        return {
            valid: true,
            sessionData,
            message: 'Session verified successfully'
        };
    } catch (error) {
        if (error.message === 'Session expired') {
            throw error;
        }
        throw new Error('Failed to decrypt session - invalid private key');
    }
}

// Send encrypted message between users
function sendEncryptedMessage(senderUsername, recipientUsername, message, senderPrivateKeyHexString) {
    const sender = findUser(senderUsername);
    const recipient = findUser(recipientUsername);
    
    if (!sender || !recipient) {
        throw new Error('Sender or recipient not found');
    }

    // Create message payload
    const messagePayload = {
        from: senderUsername,
        to: recipientUsername,
        message,
        timestamp: new Date().toISOString()
    };

    // Encrypt message with recipient's public key
    const messageStr = JSON.stringify(messagePayload);
    const encryptedMessage = encryptWithPublicKey(messageStr, recipient.publicKey);
    const encryptedMessageB64 = encryptedMessage.toString('base64');
    
    // Generate authentication tag using sender's HMAC key
    const senderHmacKey = Buffer.from(sender.hmacKey, 'hex');
    const authTag = generateAuthTag(encryptedMessageB64, senderHmacKey);

    return {
        encryptedMessage: encryptedMessageB64,
        authTag,
        senderPublicKey: sender.publicKey
    };
}

// Decrypt and verify message
function decryptMessage(encryptedMessageData, recipientPrivateKeyHexString, senderUsername) {
    const sender = findUser(senderUsername);
    if (!sender) {
        throw new Error('Sender not found');
    }

    // Verify authentication tag
    const senderHmacKey = Buffer.from(sender.hmacKey, 'hex');
    if (!verifyAuthTag(encryptedMessageData.encryptedMessage, encryptedMessageData.authTag, senderHmacKey)) {
        throw new Error('Message authentication failed - message may be tampered');
    }

    // Decrypt message
    try {
        const encryptedMessage = Buffer.from(encryptedMessageData.encryptedMessage, 'base64');
        const decryptedMessage = decryptWithPrivateKey(encryptedMessage, recipientPrivateKeyHexString);
        const messagePayload = JSON.parse(decryptedMessage.toString());

        return {
            from: messagePayload.from,
            message: messagePayload.message,
            timestamp: messagePayload.timestamp,
            verified: true
        };
    } catch (error) {
        throw new Error('Failed to decrypt message - invalid private key');
    }
}

// Get user's public key
function getPublicKey(username) {
    const user = findUser(username);
    return user ? user.publicKey : null;
}

// Get user's private key (use carefully - only for the user themselves)
function getPrivateKey(username) {
    const user = findUser(username);
    return user ? user.privateKey : null;
}

// List all users (public keys only)
function listUsers() {
    return users.map(user => ({
        username: user.username,
        publicKey: user.publicKey,
        createdAt: user.createdAt
    }));
}

// Logout user
function logout(sessionToken) {
    const sessionIndex = sessions.findIndex(s => s.sessionToken === sessionToken);
    if (sessionIndex > -1) {
        sessions.splice(sessionIndex, 1);
        return { message: 'Logged out successfully' };
    }
    throw new Error('Invalid session token');
}

// Clear all data (for testing purposes)
function clearAllData() {
    users.length = 0;
    sessions.length = 0;
    keyPairs.length = 0;
    return { message: 'All data cleared' };
}

// Get storage statistics
function getStorageStats() {
    return {
        totalUsers: users.length,
        activeSessions: sessions.length,
        keyPairs: keyPairs.length
    };
}

// Usage Example and Testing
function demonstrateE2EEAuthSystem() {
    console.log('=== E2EE Authentication System Demo (Function-based) ===\n');
    
    try {
        // Clear any existing data
        clearAllData();

        // 1. Register users
        console.log('1. Registering users...');
        const alice = registerUser('alice', 'password123');
        const bob = registerUser('bob', 'securepass456');
        console.log('Alice registered:', alice.username);
        console.log('Bob registered:', bob.username);
        console.log();

        // 2. Authenticate Alice
        console.log('2. Authenticating Alice...');
        const aliceSession = authenticateUser('alice', 'password123');
        console.log('Alice session created:', aliceSession.sessionToken);
        console.log('Session encrypted and authenticated');
        console.log();

        // 3. Verify Alice's session
        console.log('3. Verifying Alice\'s session...');
        const alicePrivateKey = getPrivateKey('alice');
        const sessionVerification = verifySession(aliceSession.sessionToken, alicePrivateKey);
        console.log('Session verified for:', sessionVerification.sessionData.username);
        console.log();

        // 4. Send encrypted message from Alice to Bob
        console.log('4. Sending encrypted message from Alice to Bob...');
        const encryptedMsg = sendEncryptedMessage(
            'alice', 
            'bob', 
            'Hello Bob! This is a secret message.', 
            alicePrivateKey
        );
        console.log('Message encrypted and authenticated');
        console.log();

        // 5. Decrypt message as Bob
        console.log('5. Bob decrypting the message...');
        const bobPrivateKey = getPrivateKey('bob');
        const decryptedMsg = decryptMessage(encryptedMsg, bobPrivateKey, 'alice');
        console.log('Decrypted message:', decryptedMsg.message);
        console.log('From:', decryptedMsg.from);
        console.log('Verified:', decryptedMsg.verified);
        console.log();

        // 6. List all users
        console.log('6. Listing all users...');
        const userList = listUsers();
        userList.forEach(user => {
            console.log(`User: ${user.username}, Created: ${user.createdAt}`);
        });
        console.log();

        // 7. Storage statistics
        console.log('7. Storage statistics...');
        const stats = getStorageStats();
        console.log('Stats:', stats);

    } catch (error) {
        console.error('Error:', error.message);
    }
}

// Export functions
export default {
    // Core functions
    registerUser,
    authenticateUser,
    verifySession,
    sendEncryptedMessage,
    decryptMessage,
    
    // Utility functions
    getPublicKey,
    getPrivateKey,
    listUsers,
    logout,
    clearAllData,
    getStorageStats,
    
    // Crypto helper functions
    generateAuthTag,
    verifyAuthTag,
    encryptWithPublicKey,
    decryptWithPrivateKey,
    
    // Storage access (for advanced usage)
    getUsers: () => users,
    getSessions: () => sessions,
    getKeyPairs: () => keyPairs
};

// Run demo if this file is executed directly
if (import.meta.url === process.argv[1] || import.meta.url === `file://${process.argv[1]}`) {
    demonstrateE2EEAuthSystem();
}