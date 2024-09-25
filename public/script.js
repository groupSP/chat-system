let ws;
let username;
let aesKey; // AES 密钥
let iv; // 初始化向量 (IV)

// RSA 公钥（假设你已经有服务器的公钥，应该是 PEM 格式）
const serverPublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApp8DD8yjS8vYmeVxzNpy
MArg20G4QCw4th1Pl9jddcfR1wkCUbLcXzziE1ab8seQrKklCqi7LA2yKGAtslBO
mxyQihfbTwTWtOacgXMngnoKmL6HDLHSvR4/ju4kMu0MBl9D6WECxIWxYic36NCp
vR0bKJDomKsi51MGa2E95+9WrhVNy8Huy/WfXQ4XKapJ4mrtiGsY9GJFC6CmUwsC
OzSY3kmLVlymMkYb2jAX09kCdufY4cg5L24J/u1KMROvSbckF2dfvJJzyKP5rr4g
u62Xbt16mgtW76tuAtfoQgd3iWVgprmCC0Rltjoqp+rIjRIixmL0mrQnU/1Z6LhU
7wIDAQAB
-----END PUBLIC KEY-----
`;

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

// 登录按钮点击事件
document.getElementById('login-btn').addEventListener('click', () => {
    username = document.getElementById('username').value;
    if (username) {
        initWebSocket(); // 初始化 WebSocket 连接
        document.getElementById('login-container').style.display = 'none';
        generateAESKey(); // 生成 AES 密钥
    }
});

// 初始化 WebSocket 连接
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () => {
        // 向服务器发送登录信息
        ws.send(JSON.stringify({ type: 'login', name: username }));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        // 更新在线用户列表
        if (data.type === 'onlineUsers') {
            updateOnlineUsers(data.users);
        }

        // 显示接收到的群聊或私聊消息
        if (data.type === 'chat') {
            console.log(`Received chat message from ${data.from}:`, data.message);
            displayMessage(data.from, data.message); // 显示解密的消息
        }
    };
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

// 发送消息按钮点击事件
document.getElementById('send-message').addEventListener('click', async () => {
    const message = document.getElementById('message').value;
    const recipient = document.getElementById('recipient').value; // 获取目标接收者

    if (message) {
        const { encryptedMessage, iv, authTag } = await encryptMessage(message);
        const aesKeyBase64 = await exportAndEncryptAESKey(); // 导出并加密 AES 密钥

        ws.send(JSON.stringify({
            type: 'chat',
            to: recipient, // 目标接收者的用户名
            iv: iv,
            chat: encryptedMessage,
            authTag: authTag,  // 发送认证标签
            symm_keys: [aesKeyBase64]  // 发送加密的 AES 密钥的 Base64 表示
        }));

        displayMessage('You', message);
        document.getElementById('message').value = '';
    }
});

// 更新在线用户列表
function updateOnlineUsers(users) {
    const onlineUsers = document.getElementById('online-users');
    const recipientSelect = document.getElementById('recipient');
    
    // 清空在线用户列表和接收者下拉列表
    onlineUsers.innerHTML = '';
    recipientSelect.innerHTML = '<option value="group">Group Chat</option>'; // 添加群聊选项
    
    // 更新在线用户列表
    users.forEach(user => {
        // 创建新的列表项
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsers.appendChild(li);
        
        // 将用户添加到接收者下拉列表
        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        recipientSelect.appendChild(option);
    });
}

// 显示消息
function displayMessage(from, message) {
    const chatMessages = document.getElementById('chat-messages');
    
    // 创建一个新的 div 来显示消息
    const messageDiv = document.createElement('div');
    messageDiv.textContent = `${from}: ${message}`;
    
    // 将消息 div 添加到消息框中
    chatMessages.appendChild(messageDiv);
    
    // 保持消息框自动滚动到最新消息
    chatMessages.scrollTop = chatMessages.scrollHeight;
}
