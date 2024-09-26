const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');

// Read server RSA private key
const privateKey = fs.readFileSync('./private.pem', 'utf8');

// Initialize Express application
const app = express();
const server = http.createServer(app);

// Initialize WebSocket server
const wss = new WebSocket.Server({ server });

// Set up multer for file uploads
const upload = multer({ dest: 'uploads/' }); // Files will be stored in the "uploads" folder

// Store online users
let clients = {};
let messageCounters = {}; // 存储每个用户的消息计数器

// RSA Decrypt AES Key Function
function decryptAESKey(encryptedKey) {
  try {
    // Decrypt AES key with the server's private key
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey, // Use the server's private key
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Use OAEP padding
        oaepHash: 'sha256', // Use SHA-256 for the hash algorithm
      },
      Buffer.from(encryptedKey, 'base64') // Decrypt base64-encoded key
    );
    return decrypted;
  } catch (error) {
    console.error('Error decrypting AES key:', error);
    return null;
  }
}

// Broadcast the online user list
function broadcastOnlineUsers() {
  const onlineUsers = Object.keys(clients);
  broadcast({
    type: 'onlineUsers',
    users: onlineUsers
  });
}

// Broadcast message to all or a specific client
function broadcast(message, recipient = null) {
  if (recipient && clients[recipient]) {
    // Send message to a specific client
    clients[recipient].send(JSON.stringify(message));
  } else {
    // Broadcast message to all clients
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }
}

// Handle WebSocket connections
wss.on('connection', (ws) => {
  let userName = '';

  ws.on('message', (message) => {
    const data = JSON.parse(message);

    // Handle user login and assign username from hello message
    if (data.type === 'hello') {
      userName = data.name; // 存储用户名
      clients[userName] = ws; // Store WebSocket connection with username as the key
      messageCounters[userName] = 0; // 初始化计数器

      // Notify all users about the updated online user list
      broadcastOnlineUsers(); // Broadcast the online user list
    }

    if (data.counter && data.counter > messageCounters[userName]) {
      messageCounters[userName] = data.counter; // 更新计数器
      
      // 处理私信和群组消息
      if (data.type === 'privateMessage') {
        const recipientWs = clients[data.to];
        if (recipientWs) {
          recipientWs.send(JSON.stringify({
            type: 'privateMessage',
            from: userName,
            message: data.message
          }));
        }
      } else if (data.type === 'groupMessage') {
        broadcast({
          type: 'groupMessage',
          from: userName,
          message: data.message
        });
      }
    }

    // Handle file transfers
    if (data.type === 'fileTransfer') {
      const fileLink = `http://${server.address().address}:${server.address().port}/files/${data.fileName}`;
      broadcast({
        type: 'fileTransfer',
        from: userName,
        fileName: data.fileName,
        fileLink: fileLink // Send a file link instead of the file itself
      });
    }

    // Handle encrypted chat
    if (data.type === 'chat') {
      console.log('Encrypted AES Key:', data.symm_keys[0]); // Debug: Print the received encrypted AES key
      const aesKey = decryptAESKey(data.symm_keys[0]); // Decrypt AES key

      if (aesKey) {
        try {
          const iv = Buffer.from(data.iv, 'base64');
          const authTag = Buffer.from(data.authTag, 'base64'); // Ensure authTag is base64 encoded

          console.log("IV: ", iv);
          console.log("AuthTag: ", authTag); // Debug: Print the authTag for debugging

          const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv); // Use the decrypted IV
          decipher.setAuthTag(authTag); // Set the authentication tag

          let decryptedMessage = decipher.update(data.chat, 'base64', 'utf8');
          decryptedMessage += decipher.final('utf8');

          console.log(`Decrypted message from ${userName}:`, decryptedMessage);

          // Send to the target recipient, or broadcast if no specific recipient
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

  // Handle user disconnection
  ws.on('close', () => {
    delete clients[userName]; // Remove user from the clients object
    broadcastOnlineUsers(); // Broadcast the updated online user list
  });
});

// Serve uploaded files with forced download
app.get('/files/:filename', (req, res) => {
  const fileName = req.params.filename; // Get the filename from the request parameters
  const filePath = path.join(__dirname, 'uploads', fileName); // Create the full path to the file

  // Use res.download to trigger the download
  res.download(filePath, (err) => {
    if (err) {
      console.error('Error sending file:', err);
      res.status(404).send('File not found.');
    }
  });
});

// Serve static resources
app.use(express.static(path.join(__dirname, 'public')));

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  const fileName = req.file.filename; // Use the unique filename generated by multer
  res.send({ fileName }); // Respond with the file name
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
