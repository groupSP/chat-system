let ws;
let username;
let aesKey; // AES key
let iv; // Initialization vector (IV)
let messageCounter = 0; // Message counter
let selectedMessages = []; // Stores selected messages
let onlineUsers = []; // Stores online users

// Server's RSA Public Key (replace with actual PEM key)
let serverPublicKeyPem = ''; // public key
let privateKey; // This should be initialized somewhere in your code

async function loadPrivateKey()
{
    const storedPrivateKey = window.localStorage.getItem('privateKey');
    if (storedPrivateKey) {
        privateKey = await crypto.subtle.importKey(
            'jwk',
            JSON.parse(storedPrivateKey),
            { name: 'RSA-PSS', hash: { name: 'SHA-256' } },
            true,
            ['sign']
        );
    }
}
loadPrivateKey();

async function generateKeys()
{
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
    );
    privateKey = keyPair.privateKey;
    const publicKey = keyPair.publicKey;

    // Optionally store the keys
    const exportedPrivateKey = await crypto.subtle.exportKey('jwk', privateKey);
    window.localStorage.setItem('privateKey', JSON.stringify(exportedPrivateKey));
}
generateKeys();



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

async function sendSignedMessage(data) {
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

let processedMessages = new Set(); // 存储已经处理的消息ID

function displayMessage(from, message)
{
    // 为消息生成一个唯一标识符，例如使用消息内容和发送者
    const messageId = `${from}-${message}`;

    if (processedMessages.has(messageId)) {
        return; // 如果消息已处理，则不重复显示
    }

    processedMessages.add(messageId); // 将消息标记为已处理

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

// Initialize WebSocket connection
function initWebSocket()
{
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log("WebSocket already connected.");
        ws.close();
    }

    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () =>
    {
        console.log("WebSocket connection opened.");
        ws.send(JSON.stringify({
            type: 'hello',
            public_key: serverPublicKeyPem,
            name: username,
            from: username
        }));

        // server hello
        ws.send(JSON.stringify({
            type: 'server_hello',
            sender: window.location.host // Server IP or host
        }));
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

    let processedFileMessages = new Set(); // Store processed file messages

    ws.onmessage = (event) =>
    {
        const data = JSON.parse(event.data);
        console.log("Received WebSocket message:", data);

        if (data.type === 'publicKey') {
            serverPublicKeyPem = data.key; // Set the public key
        }

        // Update the list of online users
        if (data.type === 'onlineUsers') {
            onlineUsers = data.users; // Store the updated list of users
            updateOnlineUsers(onlineUsers);
        }

        // Handle private or group messages
        if (data.type === 'privateMessage' || data.type === 'groupMessage') {
            if (data.from !== username) {
                displayMessage(data.from, data.message); // Show messages from others
            }
        }

        // Handle file transfer messages
        if (data.type === 'fileTransfer') {
            // Make sure the fileName and from fields exist in the message
            if (data.fileName && data.from) {
                // Ensure the message is unique before displaying
                const messageId = `${data.from}-${data.fileName}`;
                // if (!processedFileMessages.has(messageId)) {
                if (data.from !== username) {
                    processedFileMessages.add(messageId);
                    displayFileLink(data.from, `${data.fileName}`, data.fileLink);
                }
            }
        }

        // Handle any other types of messages you may have
    };

    ws.onclose = () =>
    {
        console.log("WebSocket connection closed.");
        setTimeout(initWebSocket, 2000); // Try to reconnect every 2 seconds
    };

    ws.onerror = (error) =>
    {
        console.error("WebSocket error:", error);
    };
}

// Update the online user list in the UI
function updateOnlineUsers(users)
{
    const userListElement = document.getElementById('user-list');
    userListElement.innerHTML = ''; // Clear the current list

    users.forEach(user =>
    {
        const li = document.createElement('li');
        li.textContent = user;
        userListElement.appendChild(li);
    });
}

// Start the chat application
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
        const recipient = document.getElementById('recipient').value;

        if (message) {
            const encryptedMessage = await encryptMessage(message);
            const encryptedAESKey = await exportAndEncryptAESKey();
            messageCounter++;

            // const messageType = recipient === 'group' ? 'groupMessage' : 'privateMessage';

            // // Send message to the WebSocket server
            // const messageObject = {
            //     type: messageType,
            //     message: message,
            //     encryptedMessage: encryptedMessage.encryptedMessage,
            //     authTag: encryptedMessage.authTag,
            //     iv: encryptedMessage.iv,
            //     symm_key: encryptedAESKey,
            //     to: recipient,
            //     counter: messageCounter,
            // };

            const messageData = {
                type: recipient === 'group' ? 'groupMessage' : 'privateMessage',
                message: message,
                to: recipient,
                counter: messageCounter // Example of including the counter
            };

            // Sign the message and include the signature
            const signature = await signMessage(messageData, messageCounter);
            messageData.signature = signature;

            const signedMessage = {
                type: "signed_data",
                data: messageData,
                counter: messageCounter,
                signature: messageData.signature
            };

            // Send the message through WebSocket
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(messageData));
            } else {
                console.error('WebSocket is not open. Message not sent.');
            }

            displayMessage('You', message); // Display sent message
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
                    if(!data) return;
                    const fileName = data.fileName;  // Ensure your server returns the file name upon successful upload
                    const recipient = document.getElementById('recipient').value;
                    const fileLink = `http://localhost:3000/files/${fileName}`

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



function updateOnlineUsers(users = [])
{
    const onlineUsersList = document.getElementById('online-users');
    const recipientDropdown = document.getElementById('recipient');

    onlineUsersList.innerHTML = '';
    recipientDropdown.innerHTML = '<option value="group">Group Chat</option>';

    users.forEach(user =>
    {
        // 检查 user 是否为有效的非空字符串
        if (user && user.trim() !== 'undefined') {
            const li = document.createElement('li');
            li.textContent = user;
            onlineUsersList.appendChild(li);

            const option = document.createElement('option');
            option.value = user;
            option.textContent = user;
            recipientDropdown.appendChild(option);
        }
    });
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