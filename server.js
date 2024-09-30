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

// Public key
const publicKeyPath = path.join(__dirname, 'public', 'public.pem');
const serverPublicKey = fs.readFileSync(publicKeyPath, 'utf8');

// Set up multer for file uploads
const upload = multer({ dest: 'uploads/' }); // Files will be stored in the "uploads" folder

// Store online users
let clients = {};
let messageCounters = {};

// RSA Decrypt AES Key Function
function decryptAESKey(encryptedKey) {
  try {
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedKey, 'base64')
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
    clients[recipient].send(JSON.stringify(message));
  } else {
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(message));
      }
    });
  }
}

// Handle WebSocket connections
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({ type: 'publicKey', key: serverPublicKey }));
  let userName = '';

  // server hello
  ws.send(JSON.stringify({
    type: 'server_hello',
    sender: server.address().address
  }));

  ws.on('message', async (message) => {
    const data = JSON.parse(message);

    if (data.type === 'server_hello') {
      console.log(`Received server_hello from: ${data.sender}`);
    }

    if (data.type === 'hello') {
      userName = data.name;
      clients[userName] = ws;
      messageCounters[userName] = 0;
      broadcastOnlineUsers();
    }

    if (data.type === 'signed_data') {
      const sender = userName;
      const { data: signedData, counter, signature } = data;
        // Check if the counter is greater than the last known counter
    if (messageCounters[sender] >= counter) {
      console.error('Replay attack detected! Counter is not greater than the last value.');
      return; // Reject the message
    }

    // // Verify the signature
    // const isValid = await verifySignature(signedData, counter, signature, clients[sender].publicKey);
    // if (!isValid) {
    //   console.error('Invalid signature! Rejecting message.');
    //   return; // Reject the message
    // }

    // Update the last known counter
    messageCounters[sender] = counter;

      }

    // Handle forwarding messages (for text only)
    if (data.type === 'forwardMessage') {
      const originalMessage = data.data.originalMessage;
      const forwardTo = data.data.forwardTo;

      if (clients[forwardTo]) {
          clients[forwardTo].send(JSON.stringify({
              type: 'privateMessage',
              from: `${userName} (Forwarded)`,
              message: originalMessage,
          }));
      }
  }

    if (data.counter && data.counter > messageCounters[userName]) {
      messageCounters[userName] = data.counter;

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

    if (data.type === 'fileTransfer') {
      const fileLink = `http://${server.address().address}:${server.address().port}/files/${data.fileName}`;

      if (data.to && clients[data.to]) {
        clients[data.to].send(JSON.stringify({
          type: 'fileTransfer',
          from: userName,
          fileName: data.fileName,
          fileLink: fileLink
        }));
      } else {
        broadcast({
          type: 'fileTransfer',
          from: userName,
          fileName: data.fileName,
          fileLink: fileLink
        });
      }
    }
  });

  ws.on('close', () => {
    delete clients[userName];
    broadcastOnlineUsers();
  });
});

app.get('/public-key', (req, res) => {
  res.json({ key: serverPublicKey });
});

// Serve uploaded files with forced download
app.get('/files/:filename', (req, res) => {
  res.send({ key: serverPublicKey });
  const fileName = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', fileName);

  res.download(filePath, (err) => {
    if (err) {
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
  const fileName = req.file.filename;
  res.send({ fileName });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});