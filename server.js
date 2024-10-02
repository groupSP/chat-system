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
// const publicKeyPath = path.join('public', 'public.pem');
const serverPublicKey = fs.readFileSync(publicKeyPath, 'utf8');

// Set up multer for file uploads
const upload = multer({ dest: 'uploads/' }); // Files will be stored in the "uploads" folder

// Store online users
let clients = {};
let onlineUsers = {};
let offlineUsers = {};
let messageCounters = {};
let PORT = process.env.PORT || 3000;

// RSA Decrypt AES Key Function
function decryptAESKey(encryptedKey)
{
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

// AES Encryption
function encryptWithAES(data, aesKey, iv)
{
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

// AES Decryption
function decryptWithAES(encryptedData, aesKey, iv)
{
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Generate random AES key and IV
function generateAESKey()
{
  return crypto.randomBytes(32); // AES-256 key size
}

function generateIV()
{
  return crypto.randomBytes(16); // AES IV size
}

// Encrypt AES key with RSA public key
function encryptAESKeyWithRSA(aesKey, recipientPublicKey)
{
  return crypto.publicEncrypt(
    {
      key: recipientPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  ).toString('base64');
}

// Broadcast the online user list
function broadcastOnlineUsers()
{
  const onlineUsers = Object.keys(clients);
  broadcast({
    type: 'onlineUsers',
    users: onlineUsers
  });
}

// Broadcast message to all clients in the specified format
function broadcast(message, sender = null)
{
  console.log("---Broadcast start---");
  const aesKey = generateAESKey();
  const iv = generateIV();

  const encryptedMessage = encryptWithAES(JSON.stringify(message), aesKey, iv);

  wss.clients.forEach(client =>
  {
    if (client.readyState === WebSocket.OPEN) {
      const recipientPublicKey = fs.readFileSync(path.join(__dirname, 'public', `public.pem`), 'utf8');
      const encryptedAESKey = encryptAESKeyWithRSA(aesKey, recipientPublicKey);
      const broadcastData = {
        type: 'chat',
        destination_servers: [client.server], // Assume you have server info
        iv: iv.toString('base64'), // Base64 encoded IV
        symm_keys: [encryptedAESKey], // AES key encrypted with the recipient's public RSA key
        chat: encryptedMessage // Base64 encoded AES encrypted message
      };

      console.log(`Sending message to ${client.username}:\n`, broadcastData);
      client.send(JSON.stringify(broadcastData));
    }
  });
  console.log("---Broadcast end---");
}

// Handle WebSocket connections
wss.on('connection', (ws) =>
{
  onlineUsers.add(ws);
  const users = Array.from(onlineUsers);
  const message = JSON.stringify({ type: 'onlineUsers', users });
  onlineUsers.forEach((user) => user.send(message));

  ws.send(JSON.stringify({ type: 'publicKey', key: serverPublicKey }));
  let userName = '';

  // Server hello
  ws.send(JSON.stringify({
    type: 'server_hello',
    sender: server.address().address
  }));

  ws.on('message', async (message) =>
  {
    const data = JSON.parse(message);

    if (data.type === 'server_hello') {
      console.log(`Received server_hello from: ${data.sender} | user: ${data.username}`);
    }

    else if (data.type === 'hello') {
      userName = data.name;
      clients[userName] = ws;
      ws.username = userName;  // Store username in ws object
      messageCounters[userName] = 0;
      broadcastOnlineUsers();
    }

    else if (data.type === 'signed_data') {
      const sender = userName;
      const { data: signedData, counter, signature } = data;
      // Check if the counter is greater than the last known counter
      if (messageCounters[sender] >= counter) {
        console.error('Replay attack detected! Counter is not greater than the last value.');
        return; // Reject the message
      }

      // Update the last known counter
      messageCounters[sender] = counter;
    }

    // Handle forwarding messages (for text only)
    else if (data.type === 'forwardMessage') {
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

    else if (data.type === 'onlineUsers') {
      ws.send(JSON.stringify({ type: 'onlineUsers', users: Array.from(onlineUsers) }));
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

  ws.on('close', () =>
  {
    delete clients[userName];
    broadcastOnlineUsers();
  });
});

function sendToServer(destinationServer, message)
{
  // Encrypt the message
  const iv = crypto.randomBytes(16); // AES IV
  const aesKey = crypto.randomBytes(32); // AES key

  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encryptedMessage = cipher.update(message, 'utf8', 'base64');
  encryptedMessage += cipher.final('base64');

  // Encrypt AES key with server's public RSA key
  const serverPublicKey = fs.readFileSync(`./keys/${destinationServer}-public.pem`, 'utf8');
  const encryptedAESKey = crypto.publicEncrypt(
    {
      key: serverPublicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    aesKey
  );

  // Create the data payload
  const data = {
    type: 'chat',
    destination_servers: [destinationServer], // Send to the correct server
    iv: iv.toString('base64'),
    symm_keys: [encryptedAESKey.toString('base64')],
    chat: encryptedMessage
  };

  // Send the data to the destination server
  sendTo(destinationServer, data);
}

function sendTo(destinationServer, data)
{
  // Example WebSocket sending logic for server-to-server communication
  // Here, make sure the connection to the other server is established
  if (servers[destinationServer]) {
    servers[destinationServer].send(JSON.stringify(data));
  } else {
    console.log(`Server ${destinationServer} is not connected.`);
  }
}

// app.get('/', (req, res) =>
// {
//   res.send('Server is running!');
// });

app.get('/public-key', (req, res) =>
{
  res.json({ key: serverPublicKey });
});

// Serve uploaded files with forced download
app.get('/files/:filename', (req, res) =>
{
  const fileName = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', fileName);

  res.download(filePath, (err) =>
  {
    if (err) {
      res.status(404).send('File not found.');
    }
  });
});

// Serve static resources
app.use(express.static(path.join(__dirname, 'public')));

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) =>
{
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  const fileName = req.file.filename;
  res.send({ fileName });
});

// const startServer = (port) =>
// {
//   return new Promise((resolve, reject) =>
//   {
//     const tempServer = app.listen(port, () =>
//     {
//       console.log(`Server started on port ${port}`);
//       resolve(tempServer);
//     });

//     tempServer.on('error', (err) =>
//     {
//       if (err.code === 'EADDRINUSE') {
//         console.log(`Port ${port} is in use, trying port ${port + 1}...`);
//         reject(port + 1);
//       } else {
//         console.error('Server error:', err);
//         reject(err);
//       }
//     });
//   });
// };

// const runServer = async () =>
// {
//   let serverInstance;
//   while (true) {
//     try {
//       serverInstance = await startServer(PORT);
//       break;
//     } catch (nextPort) {
//       PORT = nextPort;
//     }
//   }
// };

// runServer();

// PORT = 3001;
server.listen(PORT, () =>
{
  console.log(`> Server started on port ${PORT}`);
});
