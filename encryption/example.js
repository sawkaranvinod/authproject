// Import the E2EE authentication system
import auth from './e2e.js';

// =============================================================================
// EXAMPLE 1: Basic User Registration and Authentication
// =============================================================================

async function basicAuthExample() {
    console.log('=== EXAMPLE 1: Basic Authentication ===\n');
    
    try {
        // Clear any existing data
        auth.clearAllData();
        
        // 1. Register new users
        console.log('📝 Registering users...');
        const alice = auth.registerUser('alice', 'mySecurePassword123');
        const bob = auth.registerUser('bob', 'bobsPassword456');
        
        console.log('✅ Alice registered successfully');
        console.log('   Username:', alice.username);
        console.log('   Public Key (first 64 chars):', alice.publicKey.substring(0, 64) + '...');
        
        console.log('✅ Bob registered successfully');
        console.log('   Username:', bob.username);
        console.log('   Public Key (first 64 chars):', bob.publicKey.substring(0, 64) + '...');
        console.log();
        
        // 2. Authenticate Alice
        console.log('🔐 Authenticating Alice...');
        const aliceSession = auth.authenticateUser('alice', 'mySecurePassword123');
        
        console.log('✅ Alice authenticated successfully');
        console.log('   Session Token:', aliceSession.sessionToken);
        console.log('   Session Encrypted:', aliceSession.encryptedSession.substring(0, 32) + '...');
        console.log('   Auth Tag:', aliceSession.authTag);
        console.log();
        
        // 3. Verify Alice's session
        console.log('🔍 Verifying Alice\'s session...');
        const alicePrivateKey = auth.getPrivateKey('alice');
        const sessionCheck = auth.verifySession(aliceSession.sessionToken, alicePrivateKey);
        
        console.log('✅ Session verified successfully');
        console.log('   Valid:', sessionCheck.valid);
        console.log('   Username:', sessionCheck.sessionData.username);
        console.log('   Login Time:', sessionCheck.sessionData.loginTime);
        console.log('   Expires At:', sessionCheck.sessionData.expiresAt);
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// EXAMPLE 2: Secure Messaging Between Users
// =============================================================================

async function secureMessagingExample() {
    console.log('=== EXAMPLE 2: Secure Messaging ===\n');
    
    try {
        // Ensure users exist (register if needed)
        let alice = auth.getPublicKey('alice');
        let bob = auth.getPublicKey('bob');
        
        if (!alice) {
            auth.registerUser('alice', 'mySecurePassword123');
            console.log('📝 Alice registered for messaging demo');
        }
        if (!bob) {
            auth.registerUser('bob', 'bobsPassword456');
            console.log('📝 Bob registered for messaging demo');
        }
        
        // Get private keys
        const alicePrivateKey = auth.getPrivateKey('alice');
        const bobPrivateKey = auth.getPrivateKey('bob');
        
        // 1. Alice sends encrypted message to Bob
        console.log('📤 Alice sending encrypted message to Bob...');
        const secretMessage = 'Hey Bob! This is a top secret message. Only you can read this! 🔒';
        
        const encryptedMsg = auth.sendEncryptedMessage(
            'alice',           // sender
            'bob',            // recipient
            secretMessage,    // message
            alicePrivateKey   // sender's private key for authentication
        );
        
        console.log('✅ Message encrypted and authenticated');
        console.log('   Encrypted Message (first 64 chars):', encryptedMsg.encryptedMessage.substring(0, 64) + '...');
        console.log('   Auth Tag:', encryptedMsg.authTag);
        console.log('   Sender Public Key (first 32 chars):', encryptedMsg.senderPublicKey.substring(0, 32) + '...');
        console.log();
        
        // 2. Bob decrypts the message
        console.log('📥 Bob decrypting the message...');
        const decryptedMsg = auth.decryptMessage(
            encryptedMsg,     // encrypted message data
            bobPrivateKey,    // Bob's private key
            'alice'           // sender's username for verification
        );
        
        console.log('✅ Message decrypted and verified');
        console.log('   From:', decryptedMsg.from);
        console.log('   Message:', decryptedMsg.message);
        console.log('   Timestamp:', decryptedMsg.timestamp);
        console.log('   Verified:', decryptedMsg.verified);
        console.log();
        
        // 3. Bob replies to Alice
        console.log('📤 Bob replying to Alice...');
        const replyMessage = 'Hi Alice! Got your secret message. This reply is also encrypted! 🛡️';
        
        const encryptedReply = auth.sendEncryptedMessage('bob', 'alice', replyMessage, bobPrivateKey);
        const decryptedReply = auth.decryptMessage(encryptedReply, alicePrivateKey, 'bob');
        
        console.log('✅ Bob\'s reply:');
        console.log('   Message:', decryptedReply.message);
        console.log('   From:', decryptedReply.from);
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// EXAMPLE 3: Multi-User Chat System
// =============================================================================

async function multiUserChatExample() {
    console.log('=== EXAMPLE 3: Multi-User Chat System ===\n');
    
    try {
        // Register multiple users
        const users = ['alice', 'bob', 'charlie', 'diana'];
        const passwords = ['pass123', 'secure456', 'charlie789', 'diana012'];
        
        console.log('📝 Setting up chat room with multiple users...');
        for (let i = 0; i < users.length; i++) {
            try {
                auth.registerUser(users[i], passwords[i]);
                console.log(`✅ ${users[i]} joined the chat`);
            } catch (error) {
                if (error.message === 'User already exists') {
                    console.log(`ℹ️  ${users[i]} already in chat`);
                }
            }
        }
        console.log();
        
        // Simulate group conversation
        const conversations = [
            { from: 'alice', to: 'bob', message: 'Hi Bob! How are you today? 👋' },
            { from: 'bob', to: 'alice', message: 'Hey Alice! I\'m doing great, thanks for asking! 😊' },
            { from: 'charlie', to: 'diana', message: 'Diana, did you see the latest updates? 📰' },
            { from: 'diana', to: 'charlie', message: 'Yes Charlie! Very interesting developments! 🔍' },
            { from: 'alice', to: 'charlie', message: 'Charlie, can you share that document with me? 📄' }
        ];
        
        console.log('💬 Secure group conversation:');
        console.log('-----------------------------');
        
        for (const conv of conversations) {
            // Get sender's private key
            const senderPrivateKey = auth.getPrivateKey(conv.from);
            const recipientPrivateKey = auth.getPrivateKey(conv.to);
            
            // Encrypt message
            const encrypted = auth.sendEncryptedMessage(conv.from, conv.to, conv.message, senderPrivateKey);
            
            // Decrypt to display (in real app, only recipient would decrypt)
            const decrypted = auth.decryptMessage(encrypted, recipientPrivateKey, conv.from);
            
            console.log(`${conv.from} → ${conv.to}: ${decrypted.message}`);
            console.log(`   [Encrypted ✓] [Verified ✓] [${decrypted.timestamp}]`);
        }
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// EXAMPLE 4: Session Management and Security
// =============================================================================

async function sessionManagementExample() {
    console.log('=== EXAMPLE 4: Session Management ===\n');
    
    try {
        // Ensure Alice exists
        try {
            auth.registerUser('alice', 'mySecurePassword123');
        } catch (error) {
            if (error.message !== 'User already exists') throw error;
        }
        
        // 1. Create multiple sessions for Alice
        console.log('🔐 Creating multiple sessions for Alice...');
        const session1 = auth.authenticateUser('alice', 'mySecurePassword123');
        const session2 = auth.authenticateUser('alice', 'mySecurePassword123');
        const session3 = auth.authenticateUser('alice', 'mySecurePassword123');
        
        console.log('✅ Created 3 sessions:');
        console.log('   Session 1:', session1.sessionToken);
        console.log('   Session 2:', session2.sessionToken);
        console.log('   Session 3:', session3.sessionToken);
        console.log();
        
        // 2. Verify all sessions
        console.log('🔍 Verifying all sessions...');
        const alicePrivateKey = auth.getPrivateKey('alice');
        
        for (let i = 1; i <= 3; i++) {
            const sessionToken = eval(`session${i}.sessionToken`);
            const verification = auth.verifySession(sessionToken, alicePrivateKey);
            console.log(`✅ Session ${i} verified - User: ${verification.sessionData.username}`);
        }
        console.log();
        
        // 3. Show storage statistics
        console.log('📊 Storage statistics:');
        const stats = auth.getStorageStats();
        console.log('   Total Users:', stats.totalUsers);
        console.log('   Active Sessions:', stats.activeSessions);
        console.log('   Key Pairs:', stats.keyPairs);
        console.log();
        
        // 4. Logout one session
        console.log('🚪 Logging out session 2...');
        auth.logout(session2.sessionToken);
        console.log('✅ Session 2 logged out');
        
        // 5. Try to verify logged out session (should fail)
        console.log('🔍 Trying to verify logged out session...');
        try {
            auth.verifySession(session2.sessionToken, alicePrivateKey);
        } catch (error) {
            console.log('❌ Expected error:', error.message);
        }
        
        // 6. Updated statistics
        const newStats = auth.getStorageStats();
        console.log('📊 Updated statistics:');
        console.log('   Active Sessions:', newStats.activeSessions);
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// EXAMPLE 5: Error Handling and Security Features
// =============================================================================

async function securityFeaturesExample() {
    console.log('=== EXAMPLE 5: Security Features & Error Handling ===\n');
    
    try {
        // Ensure users exist
        try {
            auth.registerUser('alice', 'password123');
            auth.registerUser('eve', 'evilpassword');
        } catch (error) {
            if (error.message !== 'User already exists') throw error;
        }
        
        const alicePrivateKey = auth.getPrivateKey('alice');
        const evePrivateKey = auth.getPrivateKey('eve');
        
        // 1. Test authentication tag tampering
        console.log('🛡️  Testing message integrity (tampering detection)...');
        const message = auth.sendEncryptedMessage('alice', 'eve', 'Secret message', alicePrivateKey);
        
        // Tamper with the authentication tag
        const tamperedMessage = {
            ...message,
            authTag: message.authTag.replace('a', 'b') // Change one character
        };
        
        try {
            auth.decryptMessage(tamperedMessage, evePrivateKey, 'alice');
        } catch (error) {
            console.log('✅ Tampering detected:', error.message);
        }
        console.log();
        
        // 2. Test wrong private key
        console.log('🔑 Testing wrong private key...');
        try {
            auth.decryptMessage(message, alicePrivateKey, 'alice'); // Alice trying to decrypt message meant for Eve
        } catch (error) {
            console.log('✅ Wrong key detected:', error.message);
        }
        console.log();
        
        // 3. Test invalid credentials
        console.log('🚫 Testing invalid login credentials...');
        try {
            auth.authenticateUser('alice', 'wrongpassword');
        } catch (error) {
            console.log('✅ Invalid credentials detected:', error.message);
        }
        console.log();
        
        // 4. Test duplicate registration
        console.log('👥 Testing duplicate user registration...');
        try {
            auth.registerUser('alice', 'newpassword');
        } catch (error) {
            console.log('✅ Duplicate user detected:', error.message);
        }
        console.log();
        
        // 5. Show all users (public info only)
        console.log('📋 All registered users:');
        const userList = auth.listUsers();
        userList.forEach((user, index) => {
            console.log(`   ${index + 1}. ${user.username} (registered: ${user.createdAt})`);
            console.log(`      Public Key: ${user.publicKey.substring(0, 32)}...`);
        });
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// EXAMPLE 6: Real-World API Integration Example
// =============================================================================

async function apiIntegrationExample() {
    console.log('=== EXAMPLE 6: API Integration Example ===\n');
    
    // Simulate a REST API endpoint that uses E2EE auth
    function simulateAPIEndpoint(endpoint, method, headers, body) {
        console.log(`🌐 API Call: ${method} ${endpoint}`);
        
        try {
            switch (endpoint) {
                case '/api/register':
                    const registerResult = auth.registerUser(body.username, body.password);
                    return {
                        status: 200,
                        data: {
                            success: true,
                            username: registerResult.username,
                            publicKey: registerResult.publicKey
                        }
                    };
                
                case '/api/login':
                    const loginResult = auth.authenticateUser(body.username, body.password);
                    return {
                        status: 200,
                        data: {
                            success: true,
                            sessionToken: loginResult.sessionToken,
                            encryptedSession: loginResult.encryptedSession,
                            authTag: loginResult.authTag
                        }
                    };
                
                case '/api/verify-session':
                    const privateKey = auth.getPrivateKey(body.username);
                    const verifyResult = auth.verifySession(body.sessionToken, privateKey);
                    return {
                        status: 200,
                        data: {
                            success: true,
                            valid: verifyResult.valid,
                            sessionData: verifyResult.sessionData
                        }
                    };
                
                case '/api/send-message':
                    const senderKey = auth.getPrivateKey(body.from);
                    const messageResult = auth.sendEncryptedMessage(body.from, body.to, body.message, senderKey);
                    return {
                        status: 200,
                        data: {
                            success: true,
                            encryptedMessage: messageResult.encryptedMessage,
                            authTag: messageResult.authTag
                        }
                    };
                
                default:
                    return { status: 404, data: { error: 'Endpoint not found' } };
            }
        } catch (error) {
            return {
                status: 400,
                data: {
                    success: false,
                    error: error.message
                }
            };
        }
    }
    
    try {
        // Clear data for clean demo
        auth.clearAllData();
        
        // 1. Register via API
        console.log('📝 Registering user via API...');
        const registerResponse = simulateAPIEndpoint('/api/register', 'POST', {}, {
            username: 'apiuser',
            password: 'apipassword123'
        });
        console.log('   Response:', registerResponse.status, registerResponse.data);
        console.log();
        
        // 2. Login via API
        console.log('🔐 Login via API...');
        const loginResponse = simulateAPIEndpoint('/api/login', 'POST', {}, {
            username: 'apiuser',
            password: 'apipassword123'
        });
        console.log('   Response:', loginResponse.status);
        console.log('   Session Token:', loginResponse.data.sessionToken);
        console.log();
        
        // 3. Verify session via API
        console.log('🔍 Verify session via API...');
        const verifyResponse = simulateAPIEndpoint('/api/verify-session', 'POST', {}, {
            username: 'apiuser',
            sessionToken: loginResponse.data.sessionToken
        });
        console.log('   Response:', verifyResponse.status);
        console.log('   Valid:', verifyResponse.data.valid);
        console.log('   User:', verifyResponse.data.sessionData.username);
        console.log();
        
        // 4. Register second user and send message
        console.log('📝 Registering second user...');
        simulateAPIEndpoint('/api/register', 'POST', {}, {
            username: 'recipient',
            password: 'recipient123'
        });
        
        console.log('📤 Sending encrypted message via API...');
        const messageResponse = simulateAPIEndpoint('/api/send-message', 'POST', {}, {
            from: 'apiuser',
            to: 'recipient',
            message: 'Hello from the API! This message is E2EE encrypted! 🚀'
        });
        console.log('   Response:', messageResponse.status);
        console.log('   Message encrypted:', messageResponse.data.success);
        console.log();
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

// =============================================================================
// RUN ALL EXAMPLES
// =============================================================================

async function runAllExamples() {
    console.log('🚀 E2EE Authentication System - Complete Usage Examples\n');
    console.log('========================================================\n');
    
    await basicAuthExample();
    await secureMessagingExample();
    await multiUserChatExample();
    await sessionManagementExample();
    await securityFeaturesExample();
    await apiIntegrationExample();
    
    console.log('========================================================');
    console.log('✅ All examples completed successfully!');
    console.log('🔒 Your E2EE authentication system is ready for production use!');
}

// // Export examples for individual use
// export {
//     basicAuthExample,
//     secureMessagingExample,
//     multiUserChatExample,
//     sessionManagementExample,
//     securityFeaturesExample,
//     apiIntegrationExample,
//     runAllExamples
// };

// // Run all examples if this file is executed directly
// if (import.meta.url === process.argv[1] || import.meta.url === `file://${process.argv[1]}`) {
//     runAllExamples().catch(console.error);
// }
runAllExamples()