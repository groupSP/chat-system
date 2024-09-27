let ws;
let username;
let aesKey;
let iv;
let messageCounter = 0;
let selectedMessages = [];
let onlineUsers = [];
let processedMessages = new Set();  // Track processed message IDs
let serverPublicKeyPem = ''; // Server's RSA public key (set dynamically)

// RSA
function pemToArrayBuffer(pem) {
    const b64Lines = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, '');
    const b64 = atob(b64Lines);
    const buffer = new ArrayBuffer(b64.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < b64.length; i++) {
        view[i] = b64.charCodeAt(i);
    }
    return buffer;
}

async function importServerPublicKey(pemKey) {
    const keyBuffer = pemToArrayBuffer(pemKey);
    return await window.crypto.subtle.importKey(
        'spki',
        keyBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
    );
}

// Message Signing
async function signMessage(data, counter) {
    const encoder = new TextEncoder();
    const messageToSign = encoder.encode(JSON.stringify(data) + counter);
    const signature = await window.crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        privateKey,  // Private key needed
        messageToSign
    );
    return btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
}

// Message Verification
async function verifySignature(data, counter, signature) {
    const encoder = new TextEncoder();
    const messageToVerify = encoder.encode(JSON.stringify(data) + counter);
    const publicKey = await importServerPublicKey(serverPublicKeyPem);
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

    return await window.crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: 32 },
        publicKey,
        signatureBytes,
        messageToVerify
    );
}

// AES Key Generation
function generateAESKey() {
    return window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    ).then(key => {
        aesKey = key;
        console.log('AES Key Generated', aesKey);
    }).catch(err => {
        console.error('Error generating AES key:', err);
    });
}

// AES Encryption
async function encryptMessage(message) {
    iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);

    const encryptedMessage = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        encodedMessage
    );

    const encryptedArray = new Uint8Array(encryptedMessage);
    const ciphertext = encryptedArray.slice(0, -16);
    const authTag = encryptedArray.slice(-16);

    return {
        encryptedMessage: btoa(String.fromCharCode.apply(null, ciphertext)),
        authTag: btoa(String.fromCharCode.apply(null, authTag)),
        iv: btoa(String.fromCharCode.apply(null, iv))
    };
}

// AES Decryption
async function decryptMessage(encryptedData) {
    const iv = Uint8Array.from(atob(encryptedData.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(encryptedData.encryptedMessage), c => c.charCodeAt(0));
    const authTag = Uint8Array.from(atob(encryptedData.authTag), c => c.charCodeAt(0));
    
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const decryptedMessage = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        combined
    );

    return new TextDecoder().decode(decryptedMessage);
}

// Export AES Key and Encrypt with RSA Public Key
async function exportAndEncryptAESKey() {
    const rawAESKey = await window.crypto.subtle.exportKey('raw', aesKey);
    const publicKey = await importServerPublicKey(serverPublicKeyPem);
    const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        publicKey,
        rawAESKey
    );
    return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedAESKey)));
}

// Send message with signature
async function sendMessage(type, data) {
    messageCounter++;  // Increment the message counter
    const signature = await signMessage(data, messageCounter);

    ws.send(JSON.stringify({
        type: type,
        data: data,
        counter: messageCounter,
        signature: signature
    }));
}

// WebSocket Initialization
function initWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
    }

    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () => {
        console.log("WebSocket connection opened.");
        sendMessage('hello', { public_key: serverPublicKeyPem, name: username });
    };

    ws.onmessage = async (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'signed_data') {
            const fromUser = data.data.from;
            const counterValid = data.counter > (lastCounter[fromUser] || 0);

            if (counterValid && await verifySignature(data.data, data.counter, data.signature)) {
                lastCounter[fromUser] = data.counter;
                handleMessage(data.data);
            } else {
                console.error("Replay attack or invalid signature detected.");
            }
        }
    };

    ws.onerror = (error) => console.error("WebSocket error:", error);
    ws.onclose = () => setTimeout(initWebSocket, 2000);
}

// Handle incoming messages
function handleMessage(data) {
    if (data.type === 'privateMessage' || data.type === 'groupMessage') {
        if (data.from !== username) {
            displayMessage(data.from, data.message);
        }
    }
}

// Display message
function displayMessage(from, message) {
    const messageId = `${from}-${message}`;
    if (processedMessages.has(messageId)) return;  // Ignore duplicates
    processedMessages.add(messageId);

    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');

    const displayFrom = from === username ? 'You' : from;
    const messageContent = document.createElement('span');
    messageContent.textContent = `${displayFrom}: ${message}`;

    messageDiv.appendChild(messageContent);
    chatMessages.appendChild(messageDiv);
}

// Fetch Public Key
async function fetchPublicKey() {
    const response = await fetch('/public-key');
    const data = await response.json();
    serverPublicKeyPem = data.key;
    if (serverPublicKeyPem) initWebSocket();
}

// UI Interaction (Login and Send Message)
document.addEventListener("DOMContentLoaded", () => {
    fetchPublicKey();

    document.getElementById('login-btn').addEventListener('click', () => {
        username = document.getElementById('username').value.trim();
        if (username) {
            document.body.classList.add('logged-in');
            generateAESKey();
            document.getElementById('login-container').style.display = 'none';
        } else {
            alert('Please enter a valid username.');
        }
    });

    document.getElementById('send-message').addEventListener('click', async () => {
        const message = document.getElementById('message').value;
        const recipient = document.getElementById('recipient').value;
        if (message) {
            const encryptedMessage = await encryptMessage(message);
            const encryptedAESKey = await exportAndEncryptAESKey();

            sendMessage('privateMessage', {
                encryptedMessage: encryptedMessage.encryptedMessage,
                authTag: encryptedMessage.authTag,
                iv: encryptedMessage.iv,
                symm_key: encryptedAESKey,
                to: recipient
            });

            displayMessage('You', message);
            document.getElementById('message').value = ''; // Clear input
        }
    });
});
