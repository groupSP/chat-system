let ws;
let username;
let aesKey; // AES 密钥
let iv; // 初始化向量 (IV)
let messageCounter = 0; // 增加消息计数器

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
// PEM 转为 ArrayBuffer（用于 Web Crypto API）
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

// 使用 Web Crypto API 导入 RSA 公钥
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

// 使用 Web Crypto API 生成 AES 密钥
function generateAESKey() {
    window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256, // 256-bit 密钥
        },
        true, // 可导出
        ["encrypt", "decrypt"] // 允许加密和解密
    ).then(key => {
        aesKey = key;
        console.log('AES Key Generated', aesKey);
    }).catch(err => {
        console.error('Error generating AES key:', err);
    });
}

// 使用 Web Crypto API 加密消息
function encryptMessage(message) {
    iv = window.crypto.getRandomValues(new Uint8Array(12)); // 生成随机的 IV
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
        // 将加密数据拆分成 ciphertext 和 authTag
        const encryptedArray = new Uint8Array(encryptedMessage);
        const ciphertext = encryptedArray.slice(0, -16); // 消息体
        const authTag = encryptedArray.slice(-16); // 最后 16 字节作为 authTag

        return {
            encryptedMessage: btoa(String.fromCharCode.apply(null, ciphertext)), // Base64 编码
            authTag: btoa(String.fromCharCode.apply(null, authTag)), // Base64 编码的 AuthTag
            iv: btoa(String.fromCharCode.apply(null, iv)) // Base64 编码的 IV
        };
    }).catch(err => {
        console.error('Error encrypting message:', err);
    });
}

// 导出 AES 密钥为 base64 格式，并使用服务器的公钥加密
async function exportAndEncryptAESKey() {
    // 导出 AES 密钥
    const rawAESKey = await window.crypto.subtle.exportKey('raw', aesKey);
    
    // 导入服务器公钥
    const publicKey = await importServerPublicKey(serverPublicKeyPem);
    
    // 使用服务器公钥加密 AES 密钥
    const encryptedAESKey = await window.crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'  // 确保使用正确的哈希算法
        },
        publicKey,
        rawAESKey
    );

    // 返回 Base64 编码的加密 AES 密钥
    return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedAESKey)));
}

// Initialize WebSocket connection
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}`); // Connect to the WebSocket server

    ws.onopen = () => {
        console.log("WebSocket connection opened.");
        // 发送 hello 消息，包括用户名和公钥
        ws.send(JSON.stringify({
            type: 'hello',
            public_key: serverPublicKeyPem, // 发送 RSA 公钥以验证身份
            name: username // 发送用户名
        }));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
    
        // Update online users list
        if (data.type === 'onlineUsers') {
            updateOnlineUsers(data.users);
        }
    
        // Display private or group message
        if (data.type === 'privateMessage' || data.type === 'groupMessage') {
            displayMessage(data.from, data.message);
        }
    
        // Handle file transfer
        if (data.type === 'fileTransfer') {
            console.log(`Received file: ${data.fileName} from ${data.from}`);
            displayFileLink(data.from, data.fileName, data.fileLink);
    
            // Create a download link for the received file
            // const fileLink = data.fileLink; // Get the file link sent from the server
            // const messageDiv = document.createElement('div');
            
            // const link = document.createElement('a');
            // link.href = fileLink;  // This should point to /files/:filename
            // link.download = data.fileName;  // Suggest a filename for download
            // link.textContent = `${data.from} sent a file: ${data.fileName}`;  // Display sender and file name
            // link.target = "_blank"; // Optional: prevents opening a new tab
    
            // messageDiv.appendChild(link);
            // document.getElementById('chat-messages').appendChild(messageDiv);
        }
    };

    ws.onerror = (error) => {
        console.error("WebSocket error:", error);
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed. Attempting to reconnect...");
        setTimeout(initWebSocket, 2000); // Reconnect after 2 seconds
    };
}

// Call the WebSocket initialization function on page load
document.addEventListener("DOMContentLoaded", () => {
    // Login button click event
    document.getElementById('login-btn').addEventListener('click', () => {
        username = document.getElementById('username').value.trim(); // 确保用户名不为空
        if (username) {
            initWebSocket(); // Initialize WebSocket connection
            document.getElementById('login-container').style.display = 'none'; // 隐藏登录界面
            generateAESKey(); // Generate AES Key after login
        } else {
            alert("Please enter a valid username!"); // 如果用户名为空，提醒用户
        }
    });

    // Send message button click event
    document.getElementById('send-message').addEventListener('click', async () => {
        const message = document.getElementById('message').value;
        const recipient = document.getElementById('recipient').value; // 获取选定的收件人
    
        if (message) {
            const encryptedMessage = await encryptMessage(message);
            const encryptedAESKey = await exportAndEncryptAESKey();
            messageCounter++; // 增加计数器
    
            // 确定是群组消息还是私人消息
            const messageType = recipient === 'group' ? 'groupMessage' : 'privateMessage';
    
            ws.send(JSON.stringify({
                type: messageType,
                message: message, // 原始消息
                encryptedMessage: encryptedMessage.encryptedMessage,
                authTag: encryptedMessage.authTag,
                iv: encryptedMessage.iv,
                symm_key: encryptedAESKey, // 加密的 AES 密钥
                to: recipient, // 私人消息的收件人
                counter: messageCounter // 添加消息计数器以防止重放攻击
            }));
    
            displayMessage('You', message); // 本地显示消息
            document.getElementById('message').value = ''; // 清空输入框
        }
    });
    
    
    
    // Send file button click event
    document.getElementById('send-file').addEventListener('click', () => {
        const fileInput = document.getElementById('file-input');
        const file = fileInput.files[0];

        if (file) {
            const formData = new FormData();
            formData.append('file', file);

            // Send file to the server using fetch
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                const fileName = data.fileName; // Get the file name returned from the server
                ws.send(JSON.stringify({
                    type: 'fileTransfer',
                    fileName: fileName // Send file name through WebSocket
                }));
                displayMessage('You', `Sent a file: ${fileName}`); // Display the message locally
            })
            .catch(error => {
                console.error('Error uploading file:', error);
                alert('Error uploading file: ' + error.message); // Show error to user
            });
        } else {
            alert('Please select a file to upload.'); // Prompt user to select a file
        }
    });
});

// Update the recipient dropdown with online users
function updateOnlineUsers(users) {
    const onlineUsersList = document.getElementById('online-users');
    const recipientDropdown = document.getElementById('recipient');
    
    onlineUsersList.innerHTML = '';
    recipientDropdown.innerHTML = '<option value="group">Group Chat</option>'; // Reset with Group Chat option

    users.forEach(user => {
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsersList.appendChild(li);

        // Add the user to the recipient dropdown
        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        recipientDropdown.appendChild(option);
    });
}

// Display messages in chat
function displayMessage(from, message) {
    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');

    // Display "You" if the message is from the current user
    messageDiv.textContent = from === username ? `You: ${message}` : `${from}: ${message}`;
    
    chatMessages.appendChild(messageDiv);
}

// Display file download link
function displayFileLink(from, fileName, fileLink) {
    console.log("Displaying file from: ", from, "fileName: ", fileName, "fileLink: ", fileLink); // Debugging log

    const chatMessages = document.getElementById('chat-messages');
    
    // Create a div to hold the message
    const messageDiv = document.createElement('div');
    
    // Create the text node for "b sent a file: "
    const textNode = document.createTextNode(`${from} sent a file: `);
    
    // Create the anchor element for the file link
    const link = document.createElement('a');
    link.href = fileLink;  // Set the file link
    link.download = fileName;  // Suggest a filename for download
    link.textContent = fileName;  // Only the file name is clickable
    link.target = "_blank";  // Open link in a new tab
    
    // Append the text node and the link to the message div
    messageDiv.appendChild(textNode);
    messageDiv.appendChild(link);
    
    // Append the message div to the chat messages
    chatMessages.appendChild(messageDiv);
}
