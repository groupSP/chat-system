const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// 读取服务器 RSA 私钥
const privateKey = fs.readFileSync('./private.pem', 'utf8');

// 初始化 Express 应用
const app = express();
const server = http.createServer(app);

// 初始化 WebSocket 服务器
const wss = new WebSocket.Server({ server });

// 存储在线用户
let clients = {};

// RSA 解密 AES 密钥函数
function decryptAESKey(encryptedKey) {
  try {
    // 使用私钥解密 AES 密钥
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey, // 使用服务器私钥
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // 使用 OAEP 填充
        oaepHash: 'sha256', // 使用 SHA-256 作为哈希算法
      },
      Buffer.from(encryptedKey, 'base64') // 解密 base64 编码的密钥
    );
    return decrypted;
  } catch (error) {
    console.error('Error decrypting AES key:', error);
    return null;
  }
}

// 广播在线用户列表
function broadcastOnlineUsers() {
  const onlineUsers = Object.keys(clients);
  broadcast({
    type: 'onlineUsers',
    users: onlineUsers
  });
}

// 广播消息给所有客户端或单个客户端
function broadcast(message, recipient = null) {
  if (recipient && clients[recipient]) {
    // 发送消息给特定客户端
    clients[recipient].send(JSON.stringify(message));
  } else {
    // 广播消息给所有客户端
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }
}

// 处理 WebSocket 连接
wss.on('connection', (ws) => {
  let userName = '';

  ws.on('message', (message) => {
    console.log('Received message:', message); // 调试信息，显示接收到的消息
    const data = JSON.parse(message);

    if (data.type === 'login') {
      userName = data.name;
      clients[userName] = ws;
      broadcastOnlineUsers(); // 广播在线用户列表
    }

    // 处理加密的聊天消息
    if (data.type === 'chat') {
      console.log('Encrypted AES Key:', data.symm_keys[0]); // 调试：打印接收到的加密 AES 密钥
      const aesKey = decryptAESKey(data.symm_keys[0]); // 解密 AES 密钥
      if (aesKey) {
        try {
          const iv = Buffer.from(data.iv, 'base64');
          const authTag = Buffer.from(data.authTag, 'base64'); // 确保 authTag 是 base64 编码的

          console.log("IV: ", iv);
          console.log("AuthTag: ", authTag); // 打印 authTag 用于调试

          const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv); // 使用解密的 IV
          decipher.setAuthTag(authTag); // 设置认证标签

          let decryptedMessage = decipher.update(data.chat, 'base64', 'utf8');
          decryptedMessage += decipher.final('utf8');

          console.log(`Decrypted message from ${userName}:`, decryptedMessage);

          // 如果有目标接收者，则发送给特定用户，否则广播
          broadcast({
            type: 'chat',
            from: userName,
            message: decryptedMessage
          }, data.to);
        } catch (err) {
          console.error('Error decrypting message:', err);
        }
      }
    }
  });

  // 当连接关闭时，删除该用户并广播用户列表
  ws.on('close', () => {
    delete clients[userName];
    broadcastOnlineUsers();
  });
});

// 静态资源服务，提供 public 目录中的文件
app.use(express.static(path.join(__dirname, 'public')));

// 启动服务器
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
