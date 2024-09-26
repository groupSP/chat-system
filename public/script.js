let ws;
let username;
let aesKey; // AES key
let iv; // Initialization vector (IV)
let messageCounter = 0; // Message counter
let selectedMessages = []; // Stores selected messages
let onlineUsers = []; // Stores online users

// Server's RSA Public Key (replace with actual PEM key)
const serverPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApp8DD8yjS8vYmeVxzNpy
MArg20G4QCw4th1Pl9jddcfR1wkCUbLcXzziE1ab8seQrKklCqi7LA2yKGAtslBO
mxyQihfbTwTWtOacgXMngnoKmL6HDLHSvR4/ju4kMu0MBl9D6WECxIWxYic36NCp
vR0bKJDomKsi51MGa2E95+9WrhVNy8Huy/WfXQ4XKapJ4mrtiGsY9GJFC6CmUwsC
OzSY3kmLVlymMkYb2jAX09kCdufY4cg5L24J/u1KMROvSbckF2dfvJJzyKP5rr4g
u62Xbt16mgtW76tuAtfoQgd3iWVgprmCC0Rltjoqp+rIjRIixmL0mrQnU/1Z6LhU
7wIDAQAB
-----END PUBLIC KEY-----`;

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

async function signMessage(data, counter) {
    const encoder = new TextEncoder();
    const messageToSign = encoder.encode(JSON.stringify(data) + counter);

    // Sign the message using the private key
    const signature = await window.crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32
        },
        privateKey,  // You need to have the private key imported
        messageToSign
    );

    return btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
}


async function importServerPublicKey(pemKey) {
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

function generateAESKey() {
    window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    ).then(key => {
        aesKey = key;
        console.log('AES Key Generated', aesKey);
    }).catch(err => {
        console.error('Error generating AES key:', err);
    });
}

function encryptMessage(message) {
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
    ).then(encryptedMessage => {
        const encryptedArray = new Uint8Array(encryptedMessage);
        const ciphertext = encryptedArray.slice(0, -16);
        const authTag = encryptedArray.slice(-16);

        return {
            encryptedMessage: btoa(String.fromCharCode.apply(null, ciphertext)),
            authTag: btoa(String.fromCharCode.apply(null, authTag)),
            iv: btoa(String.fromCharCode.apply(null, iv))
        };
    }).catch(err => {
        console.error('Error encrypting message:', err);
    });
}

async function exportAndEncryptAESKey() {
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

// Forward message functionality
document.getElementById('forward-btn').addEventListener('click', () => {
    const selectedUser = document.getElementById('forward-user-list').value;

    selectedMessages.forEach(message => {
        // Forwarding only text messages
        ws.send(JSON.stringify({
            type: 'forwardMessage',
            data: {
                originalMessage: message,
                forwardTo: selectedUser
            }
        }));
        displayMessage('You (Forwarded)', message);
    });

    document.getElementById('forward-modal').style.display = 'none';
    selectedMessages = [];
});

function selectMessage(message, checkbox) {
    if (checkbox.checked) {
        selectedMessages.push(message);
    } else {
        selectedMessages = selectedMessages.filter(msg => msg !== message);
    }
}

function displayMessage(from, message) {
    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.onclick = () => selectMessage(message, checkbox);

    const messageContent = document.createElement('span');
    messageContent.textContent = from === username ? `You: ${message}` : `${from}: ${message}`;

    messageDiv.appendChild(checkbox);
    messageDiv.appendChild(messageContent);
    chatMessages.appendChild(messageDiv);
}

// // Handle the forward file button click event
// document.getElementById('forward-file').addEventListener('click', () => {
//     const modal = document.getElementById('forward-modal');
//     const forwardList = document.getElementById('forward-user-list');

//     // Clear the previous user list
//     forwardList.innerHTML = '';

//     // Populate the online user list, excluding the current user
//     onlineUsers.forEach(user => {
//         if (user !== username) {
//             const option = document.createElement('option');
//             option.value = user;
//             option.textContent = user;
//             forwardList.appendChild(option);
//         }
//     });

//     // Show the modal to select the user for forwarding
//     modal.style.display = 'block';
// });

// When the user confirms the forward, send the selected file to the chosen user
// document.getElementById('forward-btn').addEventListener('click', () => {
//     const selectedUser = document.getElementById('forward-user-list').value;
//     const fileInput = document.getElementById('file-input');
//     const file = fileInput.files[0];

//     if (file) {
//         const formData = new FormData();
//         formData.append('file', file);

//         // Upload the file to the server
//         fetch('/upload', {
//             method: 'POST',
//             body: formData
//         })
//         .then(response => response.json())
//         .then(data => {
//             const fileName = data.fileName;
//             const fileLink = `http://${window.location.host}/files/${fileName}`;

//             // Send the file to the selected user
//             ws.send(JSON.stringify({
//                 type: 'fileTransfer',
//                 fileName: fileName,
//                 to: selectedUser
//             }));

//             // Display the forwarded file link in the chat
//             displayFileLink('You (Forwarded)', fileName, fileLink);
//         })
//         .catch(error => {
//             console.error('Error uploading file:', error);
//             alert('Error uploading file: ' + error.message);
//         });

//         // Hide the modal after forwarding the file
//         document.getElementById('forward-modal').style.display = 'none';
//     } else {
//         alert('Please select a file to forward.');
//     }
// });

// Initialize WebSocket connection
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () => {
        ws.send(JSON.stringify({
            type: 'hello',
            public_key: serverPublicKeyPem,
            name: username
        }));
    };

// 计算公钥的SHA-256指纹
async function computeFingerprint(publicKeyPem) {
    const keyBuffer = pemToArrayBuffer(publicKeyPem);
    const hash = await window.crypto.subtle.digest('SHA-256', keyBuffer);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(hash)));
}


    // Forward button opens the modal to choose the recipient
document.getElementById('forward-file').addEventListener('click', () => {
    const modal = document.getElementById('forward-modal');
    const forwardList = document.getElementById('forward-user-list');

    // Clear the previous user list
    forwardList.innerHTML = '';

    // Populate the online user list, excluding the current user
    onlineUsers.forEach(user => {
        if (user !== username) {
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
document.getElementById('forward-btn').addEventListener('click', () => {
    const selectedUser = document.getElementById('forward-user-list').value;

    selectedMessages.forEach(message => {
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
document.getElementById('cancel-forward-btn').addEventListener('click', () => {
    document.getElementById('forward-modal').style.display = 'none';
    selectedMessages = []; // Clear selected messages
});


    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        // Update onlineUsers when the server sends the online users list
        if (data.type === 'onlineUsers') {
            onlineUsers = data.users; // Store the updated list of users
            updateOnlineUsers(data.users);
        } 
        
        if (data.type === 'privateMessage' || data.type === 'groupMessage') {
            // displayMessage(data.from, data.message);
            if (data.from !== username) {
                displayMessage(data.from, data.message); // 其他用户的消息
            }
        }

        if (data.type === 'fileTransfer') {
            // displayFileLink(data.from, data.fileName, data.fileLink);
            if (data.from !== username) {
                displayFileLink(data.from, data.fileName, data.fileLink); // 其他用户的文件
            }
        }
    };

    ws.onerror = (error) => {
        console.error("WebSocket error:", error);
    };

    ws.onclose = () => {
        setTimeout(initWebSocket, 2000);
    };
}

function updateOnlineUsers(users) {
    const onlineUsersList = document.getElementById('online-users');
    const recipientDropdown = document.getElementById('recipient');
    
    onlineUsersList.innerHTML = '';
    recipientDropdown.innerHTML = '<option value="group">Group Chat</option>';

    users.forEach(user => {
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsersList.appendChild(li);

        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        recipientDropdown.appendChild(option);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById('login-btn').addEventListener('click', () => {
        username = document.getElementById('username').value.trim();
        if (username) {
            initWebSocket();
            document.getElementById('login-container').style.display = 'none';
            generateAESKey();
        }
    });

    // 绑定发送消息的点击事件
    document.getElementById('send-message').addEventListener('click', async () => {
        const message = document.getElementById('message').value;
        const recipient = document.getElementById('recipient').value;

        if (message) {
            const encryptedMessage = await encryptMessage(message);
            const encryptedAESKey = await exportAndEncryptAESKey();
            messageCounter++;

            const messageType = recipient === 'group' ? 'groupMessage' : 'privateMessage';

            // 发送消息
            ws.send(JSON.stringify({
                type: messageType,
                message: message,
                encryptedMessage: encryptedMessage.encryptedMessage,
                authTag: encryptedMessage.authTag,
                iv: encryptedMessage.iv,
                symm_key: encryptedAESKey,
                to: recipient,
                counter: messageCounter
            }));

            displayMessage('You', message); // 显示发送的消息
            document.getElementById('message').value = ''; // 清空输入框
        }
    });

    document.getElementById('send-file').addEventListener('click', () => {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];
        const recipient = document.getElementById('recipient').value;

        if (file) {
            const formData = new FormData();
            formData.append('file', file);

            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const fileName = data.fileName;
                const fileLink = `http://${window.location.host}/files/${fileName}`;

                ws.send(JSON.stringify({
                    type: 'fileTransfer',
                    fileName: fileName,
                    to: recipient
                }));

                displayFileLink('You', fileName, fileLink);
            })
            .catch(error => {
                alert('Error uploading file: ' + error.message);
            });
        }
    });
});

function updateOnlineUsers(users) {
    const onlineUsersList = document.getElementById('online-users');
    const recipientDropdown = document.getElementById('recipient');
    
    onlineUsersList.innerHTML = '';
    recipientDropdown.innerHTML = '<option value="group">Group Chat</option>';

    users.forEach(user => {
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsersList.appendChild(li);

        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        recipientDropdown.appendChild(option);
    });
}

function displayFileLink(from, fileName, fileLink) {
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
    
    messageDiv.appendChild(textNode);
    messageDiv.appendChild(link);
    chatMessages.appendChild(messageDiv);
}
