let ws;
let username;
let aesKey; // AES key
let iv; // Initialization vector (IV)
let messageCounter = 0; // Message counter
let selectedMessages = []; // Stores selected messages
let onlineUsers = {}; // Stores online users
let processedFileMessages = [];
let retryAttempts = 0;

// Server's RSA Public Key (replace with actual PEM key)
let serverPublicKeyPem = ''; // public key
let privateKey;
let publicKey;

//#region Encryption
const generateKeyPair = async (username) =>
{
    const keyPair = await window.crypto.subtle.generateKey({
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: { name: "SHA-256" }
    }, true, ["encrypt", "decrypt"]);

    const publicKeyTem = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);

    // Send the public key to the server in "hello" message
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyTem)));
    const helloMessage = {
        data: {
            type: "hello",
            public_key: publicKeyBase64
        }
    };

    ws.send(JSON.stringify(helloMessage));

    // Store the private key locally (for signing and decryption)
    // localStorage.setItem("privateKey", JSON.stringify(keyPair.privateKey));
    // localStorage.setItem("publicKey", publicKeyBase64);
    privateKey = keyPair.privateKey;
    publicKey = publicKeyBase64;
};

// RSA
function pemToArrayBuffer(pem)
{
    const b64Lines = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, '');
    const b64 = atob(b64Lines);
    const buffer = new ArrayBuffer(b64.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < b64.length; i++) {
        view[i] = b64.charCodeAt(i);
    }
    return buffer;
}

async function signMessage(message, messageCounter)
{
    if (!privateKey) {
        console.error('Private key is not defined');
        return;
    }
    const encoder = new TextEncoder();
    const messageToSign = encoder.encode(JSON.stringify(message) + messageCounter);
    const signature = await crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        privateKey,
        messageToSign
    );
    return signature;
}


async function importServerPublicKey(pemKey)
{
    const keyBuffer = pemToArrayBuffer(pemKey);
    return await window.crypto.subtle.importKey(
        'spki',
        keyBuffer,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        true,
        ['encrypt']
    );
}

async function fetchPublicKey()
{
    try {
        const response = await fetch('/public-key');
        const data = await response.json();
        serverPublicKeyPem = data.key; // 设置公钥
        if (!serverPublicKeyPem) {
            console.error('Public key is undefined or empty');
        } else {
            if (!ws || ws.readyState !== WebSocket.OPEN)
                initWebSocket(); // 在成功获取公钥后初始化 WebSocket
        }
    } catch (error) {
        console.error('Error fetching public key:', error);
    }
}

function generateAESKey()
{
    window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 128,
        },
        true,
        ["encrypt", "decrypt"]
    ).then(key =>
    {
        aesKey = key;
        console.log('AES Key Generated', aesKey);
    }).catch(err =>
    {
        console.error('Error generating AES key:', err);
    });
}

function encryptMessage(message)
{
    iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);

    return window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        aesKey,
        encodedMessage
    ).then(encryptedMessage =>
    {
        const encryptedArray = new Uint8Array(encryptedMessage);
        const ciphertext = encryptedArray.slice(0, -16);
        const authTag = encryptedArray.slice(-16);

        return {
            encryptedMessage: btoa(String.fromCharCode.apply(null, ciphertext)),
            authTag: btoa(String.fromCharCode.apply(null, authTag)),
            iv: btoa(String.fromCharCode.apply(null, iv))
        };
    }).catch(err =>
    {
        console.error('Error encrypting message:', err);
    });
}

function encryptWithRSA(publicKey, aesKeyBase64)
{
    // Assume we have an RSA encryption function here
    // It should use the recipient's public RSA key to encrypt the AES key.
    const encryptedKey = publicKey.encrypt(aesKeyBase64); // Pseudocode
    return CryptoJS.enc.Base64.stringify(encryptedKey);
}

function encryptChatMessage(plainText, recipientPublicKeys)
{
    // 1. Generate a random AES key
    const aesKey = CryptoJS.lib.WordArray.random(32); // 256-bit key
    const keyBase64 = CryptoJS.enc.Base64.stringify(aesKey);

    // 2. Generate a random IV
    const iv = CryptoJS.lib.WordArray.random(16);

    // 3. Encrypt the plaintext message with AES
    const encrypted = CryptoJS.AES.encrypt(plainText, aesKey, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });

    // 4. Encrypt the AES key with each recipient's public RSA key
    const encryptedSymmKeys = recipientPublicKeys.map(publicKey =>
    {
        return encryptWithRSA(publicKey, keyBase64);
    });

    // 5. Structure the result
    const result = {
        data: {
            type: "chat",
            destination_servers: recipientPublicKeys.map(pk => pk.serverAddress), // Placeholder for each recipient's server address
            iv: iv.toString(CryptoJS.enc.Base64), // Base64 encode the IV
            symm_keys: encryptedSymmKeys, // AES keys encrypted with each recipient's public RSA key
            chat: encrypted.ciphertext.toString(CryptoJS.enc.Base64) // Encrypted message in base64
        }
    };

    return result;
}

function decryptWithAES(encryptedData, keyBase64, ivBase64)
{
    // Decode the key and IV from Base64
    const key = CryptoJS.enc.Base64.parse(keyBase64);
    const iv = CryptoJS.enc.Base64.parse(ivBase64);

    // Decode the encrypted data from Base64
    const encrypted = CryptoJS.enc.Base64.parse(encryptedData);

    // Decrypt the data
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: encrypted },
        key,
        {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        }
    );

    // Log the decrypted data as a WordArray
    console.log("Decrypted WordArray:", decrypted);

    // Convert decrypted data to UTF-8 string
    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);

    // Check if decrypted text is empty
    if (!decryptedText) {
        throw new Error("Decryption failed. Check your key, IV, and encrypted data.");
    }

    return decryptedText;
}



async function exportAndEncryptAESKey()
{
    const rawAESKey = await window.crypto.subtle.exportKey('raw', aesKey);
    const publicKey = await importServerPublicKey(serverPublicKeyPem);
    const encryptedAESKey = await window.crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        publicKey,
        rawAESKey
    );
    return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedAESKey)));
}

async function sendSignedMessage(data)
{
    messageCounter++; // Increment the message counter
    const jData = JSON.stringify(data);

    const messageToSign = {
        data: jData,
        counter: messageCounter
    };

    // Sign the message (data + counter) using the private key
    const signature = await signMessage(messageToSign, messageCounter);

    const signedMessage = {
        type: "signed_data",
        data: jData,
        counter: messageCounter,
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))) // Convert signature to Base64
    };

    // Send the signed message via WebSocket
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(signedMessage));
    } else {
        console.error('WebSocket is not open. Message not sent.');
    }
}
//#endregion

// Forward message functionality
document.getElementById('forward-btn').addEventListener('click', () =>
{
    const selectedUser = document.getElementById('forward-user-list').value;

    selectedMessages.forEach(message =>
    {
        // Forwarding only text messages
        ws.send(JSON.stringify({
            type: 'forwardMessage',
            data: {
                originalMessage: message,
                forwardTo: selectedUser,
                from: username
            }
        }));
        displayMessage('You (Forwarded)', message);
    });

    document.getElementById('forward-modal').style.display = 'none';
    selectedMessages = [];
});

function selectMessage(message, checkbox)
{
    if (checkbox.checked) {
        selectedMessages.push(message);
    } else {
        selectedMessages = selectedMessages.filter(msg => msg !== message);
    }
}


//#region WebSocket
// Initialize WebSocket connection
function initWebSocket()
{
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log("WebSocket already connected.");
        ws.close();
    }
    else if (retryAttempts > 1) {
        console.log("Retry attempts:", retryAttempts);
    }
    ws = new WebSocket(`ws://${window.location.host}`);
    generateKeyPair();

    ws.onopen = () =>
    {
        retryAttempts = 0;

        // console.log("WebSocket connection opened.");
        // ws.send(JSON.stringify({
        //     type: 'hello',
        //     public_key: publicKey,
        //     // name: username,
        //     // from: username
        // }));

        // server hello
        // ws.send(JSON.stringify({
        //     type: 'server_hello',
        //     sender: window.location.host, // Server IP or host
        //     username
        // }));
    };

    async function computeFingerprint(publicKeyPem)
    {
        const keyBuffer = pemToArrayBuffer(publicKeyPem);
        const hash = await window.crypto.subtle.digest('SHA-256', keyBuffer);
        return btoa(String.fromCharCode.apply(null, new Uint8Array(hash)));
    }

    // Forward button opens the modal to choose the recipient
    document.getElementById('forward-file').addEventListener('click', () =>
    {
        const modal = document.getElementById('forward-modal');
        const forwardList = document.getElementById('forward-user-list');

        // Clear the previous user list
        forwardList.innerHTML = '';

        // Populate the online user list, excluding the current user and ignoring undefined or empty users
        onlineUsers.forEach(user =>
        {
            if (user !== username && user && user.trim() !== 'undefined') {
                const option = document.createElement('option');
                option.value = user;
                option.textContent = user;
                forwardList.appendChild(option);
            }
        });

        // Show the modal to select the user for forwarding
        modal.style.display = 'block';
    });

    // Forwarding the selected message to the chosen user
    document.getElementById('forward-btn').addEventListener('click', () =>
    {
        const selectedUser = document.getElementById('forward-user-list').value;

        selectedMessages.forEach(message =>
        {
            // Forwarding the message to the selected user
            ws.send(JSON.stringify({
                type: 'forwardMessage',
                data: {
                    originalMessage: message,
                    forwardTo: selectedUser
                }
            }));

            // Display the message in the chatbox as a forwarded message
            displayMessage('You (Forwarded)', message);
        });

        // Hide the modal after forwarding
        document.getElementById('forward-modal').style.display = 'none';
        selectedMessages = []; // Clear selected messages
    });

    // Cancel the forward action and hide the modal
    document.getElementById('cancel-forward-btn').addEventListener('click', () =>
    {
        document.getElementById('forward-modal').style.display = 'none';
        selectedMessages = []; // Clear selected messages
    });

    ws.onmessage = (event) =>
    {
        const data = JSON.parse(event.data);
        console.log("Received WebSocket message:", data);

        if (data.type === 'client_update') {
            const clientListContainer = document.getElementById('online-users');
            clientListContainer.innerHTML = '';

            data.clients.forEach(client =>
            {
                const clientItem = document.createElement('li');
                clientItem.textContent = `Client ID: ${client['client-id']}, Public Key: ${client['public-key']}`;
                clientListContainer.appendChild(clientItem);
            });
        }

        else if (data.type === 'public_chat') {
            console.log('Received public chat message:', data.message);
            displayMessage(data.sender, data.message);
        }

        else if (data.type === 'chat') {
            try {
                varifyChat(data.chat);
                console.log('Received chat message:', data.chat);
                console.log('Received symm_keys:', data.symm_keys);
                console.log('Received iv:', data.iv);
                const decryptedMessage = decryptWithAES(data.chat, data.symm_keys[0], data.iv);
                console.log(decryptedMessage);
                console.log('Received chat message:', decryptedMessage);

                updateUsers(decryptedMessage);
            } catch (error) {
                console.error("Error decrypting message:", error);
            }
        }

        else if (data.type === 'client_list') {
            const onlineUsers = data.servers.map(server => server.clients).flat();

            // Store public keys of other users in a dictionary
            onlineUsers.forEach(client =>
            {
                onlineUserList[client["client-id"]] = client["public-key"];
            });
        }
        
        else if (data.type === 'publicKey') {
            serverPublicKeyPem = data.key; // Set the public key
        }

        else if (data.type === 'fileTransfer') {
            // Make sure the fileName and from fields exist in the message
            if (data.fileName && data.from) {
                // Ensure the message is unique before displaying
                const messageId = `${data.from}-${data.fileName}`;
                // if (!processedFileMessages.has(messageId)) {
                if (data.from !== username) {
                    processedFileMessages.push(messageId);
                    console.log("Received file with id: ", messageId);
                    displayFileLink(data.from, `${data.fileName}`, data.fileLink);
                }
            }
        }
    };

    ws.onclose = () =>
    {
        console.log("WebSocket connection closed");
        retryAttempts++;
        setTimeout(initWebSocket, 2000); // Try to reconnect every 2 seconds
    };

    ws.onerror = (error) =>
    {
        console.error("WebSocket error:", error);
    };
}
//#endregion
//#region DOMContentLoaded
document.addEventListener("DOMContentLoaded", () =>
{
    // username = prompt("Enter your name:");
    // generateAESKey(); // Generate AES key when the app loads
    // fetchPublicKey(); // Fetch server's public key
    // initWebSocket(); // Initialize WebSocket connection

    // Handle sending messages

    document.getElementById('username').addEventListener('keydown', async (event) =>
    {
        if (event.key === 'Enter') {
            event.preventDefault();
            document.getElementById('login-btn').click();
        }
    });

    // Handle sending messages
    document.getElementById('login-btn').addEventListener('click', () =>
    {
        username = document.getElementById('username').value.trim();

        if (username) {
            console.log("now initializing websocket");
            document.body.classList.add('logged-in'); // Add class to show online users
            // if (!ws || ws.readyState !== WebSocket.OPEN) {
            initWebSocket();
            // }
            document.getElementById('login-container').style.display = 'none';
            generateAESKey();
        } else {
            alert('Please enter a valid username.');
        }
    });

    document.getElementById('message').addEventListener('keydown', async (event) =>
    {
        if (event.key === 'Enter') {
            event.preventDefault();
            document.getElementById('send-message').click();
        }
    });

    document.getElementById('send-message').addEventListener('click', async (event) =>
    {
        event.preventDefault(); // Prevent default form submission

        const message = document.getElementById('message').value;
        console.log('===Message:', message);
        const recipient = document.getElementById('recipient').value;

        if (message) {
            let messageData;

            if (recipient === 'group') {
                // Prepare message for group chat (no encryption)
                messageData = {
                    type: 'public_chat',
                    sender: publicKey,
                    message: message,
                };
            } else {
                // Encrypt the message and AES key for private chat
                const encryptedMessage = await encryptChatMessage(message, ['sldfjslkdjflr']);
                console.log('---------------Encrypted message:', encryptedMessage);

                const encryptedAESKey = await exportAndEncryptAESKey(); // Encrypt the AES key

                // Prepare message data for private chat
                messageData = {
                    type: 'chat',
                    message: encryptedMessage.encryptedMessage, // Send encrypted message
                    authTag: encryptedMessage.authTag, // Include authentication tag
                    iv: encryptedMessage.iv, // Include initialization vector
                    symm_key: encryptedAESKey, // Include the encrypted AES key
                    to: recipient, // Recipient's public key
                    counter: messageCounter++ // Increment counter
                };

                // Sign the message and include the signature
                const signature = await signMessage(messageData, messageCounter);
                messageData.signature = signature; // Add signature to message data
            }

            // Send the message through WebSocket
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ data: messageData })); // Send the message (group or private)
            } else {
                console.error('WebSocket is not open. Message not sent.');
            }

            // displayMessage('You', message); // Display sent message
            document.getElementById('message').value = ''; // Clear the input field
        }
    });



    document.getElementById('send-file').addEventListener('click', () =>
    {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];

        if (file) {
            const formData = new FormData();
            formData.append('file', file);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
                .then(response =>
                {
                    if (response.ok)
                        return response.json();
                    else if (response.status === 413)
                        console.error('File size too large.');
                    else
                        console.error('File upload failed with status:', response.status);
                })
                .then(data =>
                {
                    if (!data) return;
                    const fileName = data.fileName;  // Ensure your server returns the file name upon successful upload
                    const recipient = document.getElementById('recipient').value;
                    const fileLink = `http://${window.location.host}/files/${fileName}`

                    // Notify the recipient via WebSocket
                    ws.send(JSON.stringify({
                        type: 'fileTransfer',
                        fileName: fileName,
                        from: username,
                        to: recipient,
                        timestamp: new Date().toISOString(),
                        fileLink: fileLink
                    }));

                    displayFileLink('You', fileName, fileLink);
                })
                .catch(error =>
                {
                    console.error('Error uploading file:', error);
                });

        }
    });
});
//#endregion
//#region Display
function displayMessage(from, message)
{
    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.onclick = () => selectMessage(message, checkbox);

    const displayFrom = from === username ? 'You' : from;
    const messageContent = document.createElement('span');
    messageContent.textContent = `${displayFrom}: ${message}`;

    messageDiv.appendChild(checkbox);
    messageDiv.appendChild(messageContent);
    chatMessages.appendChild(messageDiv);
}

function displayFileLink(from, fileName, fileLink)
{
    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');

    // Check if the sender is the current user, if so, use 'You' instead of their username
    const displayFrom = (from === username) ? 'You' : from;

    const textNode = document.createTextNode(`${displayFrom} sent a file: `);
    const link = document.createElement('a');
    link.href = fileLink;
    link.download = fileName;
    link.textContent = fileName;
    link.target = "_blank";
    link.addEventListener('click', () => retrieveFile(fileLink));

    messageDiv.appendChild(textNode);
    messageDiv.appendChild(link);
    chatMessages.appendChild(messageDiv);
}

async function verifySignature(data, counter, signature)
{
    const encoder = new TextEncoder();
    const messageToVerify = encoder.encode(JSON.stringify(data) + counter);

    const publicKey = await importServerPublicKey(serverPublicKeyPem);
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

    return await window.crypto.subtle.verify(
        {
            name: "RSA-PSS",
            saltLength: 32
        },
        publicKey,
        signatureBytes,
        messageToVerify
    );
}

async function retrieveFile(fileUrl)
{
    console
    try {
        const response = await fetch(fileUrl);

        if (response.ok) {
            const blob = await response.blob(); // Get the file as a Blob
            const downloadUrl = URL.createObjectURL(blob);

            // Optionally create an anchor element to download the file
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = 'downloaded-file'; // You can set the default name here
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);

            console.log('File retrieved successfully');
        } else {
            console.error('Failed to retrieve the file:', response.status);
        }
    } catch (error) {
        console.error('Error retrieving file:', error);
    }
}

const varifyChat = (chat) =>
{
    try {
        const decryptedText = chat.toString(CryptoJS.enc.Utf8);
        if (!decryptedText) {
            throw new Error("Decryption yielded empty result.");
        }
        return decryptedText;
    } catch (error) {
        console.error("Failed to convert decrypted data to UTF-8:", error);
        throw new Error("Malformed UTF-8 data. Decryption might have failed.");
    }
}
//#endregion