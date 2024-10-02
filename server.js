//#region Imports
const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const { send } = require('express/lib/response');

const privateKey = fs.readFileSync('./private.pem', 'utf8');
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const publicKeyPath = path.join(__dirname, 'public', 'public.pem');
const serverPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
app.use(express.static(path.join(__dirname, 'public')));
app.use('/files', express.static(UPLOAD_DIR));

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) =>
  {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) =>
  {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname)); // Save the file with a unique name
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }  // 10MB file size limit
});


//#region Variables
let clients = {};
let messageCounters = {};
const neighbourhoodServers = [];
let PORT = process.env.PORT || 3000;
//#endregion

//#region Encryption
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
//#endregion

//#region Functions
// function broadcastOnlineUsers()
// {
//   const onlineUsers = Object.keys(clients);
//   broadcast({
//     type: 'onlineUsers',
//     users: onlineUsers
//   });
// }

// // Broadcast message to all clients in the specified format
// function broadcast(message, sender = null)
// {
//   console.log("---Broadcast start---");
//   const aesKey = generateAESKey();
//   const iv = generateIV();

//   const encryptedMessage = encryptWithAES(JSON.stringify(message), aesKey, iv);

//   wss.clients.forEach(client =>
//   {
//     if (client.ws.readyState === WebSocket.OPEN) {
//       const recipientPublicKey = fs.readFileSync(path.join(__dirname, 'public', `public.pem`), 'utf8');
//       const encryptedAESKey = encryptAESKeyWithRSA(aesKey, recipientPublicKey);
//       const broadcastData = {
//         type: 'chat',
//         destination_servers: [client.ws.server], // Assume you have server info
//         iv: iv.toString('base64'), // Base64 encoded IV
//         symm_keys: [encryptedAESKey], // AES key encrypted with the recipient's public RSA key
//         chat: encryptedMessage // Base64 encoded AES encrypted message
//       };

//       console.log(`Sending message to ${client}:\n`, broadcastData);
//       client.send(JSON.stringify(broadcastData));
//     }
//   });
//   console.log("---Broadcast end---");
// }

function broadcastClientList()
{
  console.log("Now broadcasting client list...");
  const clientUpdateMessage = {
    type: "client_update",
    clients: []
  };

  // Iterate over the clients object and build the list of connected clients
  for (const publicKey in clients) {
    const { "client-id": id } = clients[publicKey]; // Get the client ID
    clientUpdateMessage.clients.push({
      "client-id": id,
      "public-key": publicKey
    });
  }

  sendToNeighbourhoodServers(clientUpdateMessage);
  sendToAllClient(clientUpdateMessage);
}

function sendToAllClient(message)
{
  console.log("Sending message to client: \n[");
  for (const key in clients) {
    console.log('\t', clients[key]['client-id']);
  }
  console.log("]\n");
  const messageString = JSON.stringify(message);
  const clientArray = Object.values(clients);
  clientArray.forEach(c =>
  {
    if (c.ws && c.ws.readyState === WebSocket.OPEN) { // Check if the connection is open
      c.ws.send(messageString); // Send the message
    }
  });
  console.log("Finished sending message to client.\n");
}

function sendToNeighbourhoodServers(message)
{
  console.log("Sending message to neighbourhood servers...\n", neighbourhoodServers, message);
  const messageString = JSON.stringify(message);

  neighbourhoodServers.forEach(serverWs =>
  {
    if (serverWs.readyState === WebSocket.OPEN) { // Check if the connection is open
      serverWs.send(messageString); // Send the message
    } else {
      console.log("WebSocket connection is not open. Cannot send message.");
    }
  });
}

// Example of adding a neighbourhood server connection
function addNeighbourhoodServer(serverUrl)
{
  const serverWs = new WebSocket(serverUrl);

  serverWs.onopen = () =>
  {
    console.log(`Connected to neighbourhood server: ${serverUrl}`);
    neighbourhoodServers.push(serverWs); // Store the WebSocket connection
  };

  serverWs.onclose = () =>
  {
    console.log(`Disconnected from neighbourhood server: ${serverUrl}`);
    // Optionally remove the closed connection from the array
    const index = neighbourhoodServers.indexOf(serverWs);
    if (index > -1) {
      neighbourhoodServers.splice(index, 1);
    }
  };

  serverWs.onerror = (error) =>
  {
    console.error(`WebSocket error: ${error}`);
  };
}

function generateClientId()
{
  const timestamp = Date.now().toString(36); // Convert timestamp to base 36
  const randomNum = Math.random().toString(36).substring(2, 8); // Random base 36 string
  return `${timestamp}-${randomNum}`; // Combine timestamp and random number
}
//#endregion

const wsClient = new WebSocket('ws://localhost:3000');

wsClient.on('open', () =>
{
  console.log('Connected to server on port 3000');

  // You can send messages to server 3000 like this:
  wsClient.send(JSON.stringify({
    data: {
      type: 'server_hello',
      sender: 'server_3001',
      message: 'Hello from server 3001!'
    }
  }));
});

wsClient.on('message', (message) =>
{
  console.log('Received from server 3000:', message);
});

wsClient.on('close', () =>
{
  console.log('Connection closed');
});

//#region WebSocket
wss.on('connection', (ws) =>
{
  // onlineUsers.add(ws);
  // const users = Array.from(onlineUsers);
  // const message = JSON.stringify({ type: 'onlineUsers', users });
  // onlineUsers.forEach((user) => user.send(message));

  // ws.send(JSON.stringify({ type: 'publicKey', key: serverPublicKey }));

  // ws.send(JSON.stringify({
  //   type: 'server_hello',
  //   sender: server.address().address
  // }));

  ws.on('message', async (message) =>
  {
    const parsedMessage = JSON.parse(message);
    console.log('Received message:', parsedMessage);

    if (parsedMessage.type === 'client_update_request') {
      broadcastClientList();
    }

    else if (parsedMessage.type == 'client_update') {
      data.clients.forEach(client =>
      {
        clients[client["public-key"]] = {
          ws: clients[client["public-key"]] ? clients[client["public-key"]].ws : null,
          "client-id": client["client-id"],
        };
      });
    }

    else {
      // Below must have parsedMessage.data
      const data = parsedMessage.data;

      if (!data)
        return;

      else if (data.type === 'server_hello') {
        console.log(`Received server_hello from: ${data.sender} | user: ${data.username}`);
      }

      else if (data.type === 'hello') {
        clients[data.public_key] = {
          ws: ws,
          "client-id": generateClientId(),
        };
        // Broadcast updated client list to all clients
        broadcastClientList();
      }

      else if (data.type == 'public_chat') {
        sendToAllClient({ type: data.type, sender: clients[data.sender]['client-id'], message: data.message });
      }

      // Handle client list requests
      else if (parsedMessage.type === 'client_list_request') {
        ws.send(JSON.stringify({
          type: 'client_list',
          servers: [{
            address: `${server.address().address}:${server.address().port}`,
            serverId: "server-id-" + server.address().port,
            clients: Object.keys(clients).map(publicKey => ({
              "client-id": clients[publicKey]["client-id"],
              "public-key": publicKey
            }))
          }]
        }));
      }
        
      else if (data.type === 'fileTransfer') {
        const fileLink = data.fileLink;

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

      //   else if (data.type === 'signed_data') {
      //     const sender = userName;
      //     const { data: signedData, counter, signature } = data;
      //     // Check if the counter is greater than the last known counter
      //     if (messageCounters[sender] >= counter) {
      //       console.error('Replay attack detected! Counter is not greater than the last value.');
      //       return; // Reject the message
      //     }

      //     // Update the last known counter
      //     messageCounters[sender] = counter;
      //   }

      //   // Handle forwarding messages (for text only)
      //   else if (data.type === 'forwardMessage') {
      //     const originalMessage = data.data.originalMessage;
      //     const forwardTo = data.data.forwardTo;

      //     if (clients[forwardTo]) {
      //       clients[forwardTo].send(JSON.stringify({
      //         type: 'privateMessage',
      //         from: `${userName} (Forwarded)`,
      //         message: originalMessage,
      //       }));
      //     }
      //   }

      //   else if (data.type === 'onlineUsers') {
      //     ws.send(JSON.stringify({ type: 'onlineUsers', users: Array.from(onlineUsers) }));
      //   }

      //   if (data.counter && data.counter > messageCounters[userName]) {
      //     messageCounters[userName] = data.counter;

      //     if (data.type === 'privateMessage') {
      //       const recipientWs = clients[data.to];
      //       if (recipientWs) {
      //         recipientWs.send(JSON.stringify({
      //           type: 'privateMessage',
      //           from: userName,
      //           message: data.message
      //         }));
      //       }
      //     } else if (data.type === 'groupMessage') {
      //       broadcast({
      //         type: 'groupMessage',
      //         from: userName,
      //         message: data.message
      //       });
      //     }
      //   }

      // else if (data.type === 'fileTransfer') {
      //     const fileLink = `http://${server.address().address}:${server.address().port}/files/${data.fileName}`;

      //     if (data.to && clients[data.to]) {
      //       clients[data.to].send(JSON.stringify({
      //         type: 'fileTransfer',
      //         from: userName,
      //         fileName: data.fileName,
      //         fileLink: fileLink
      //       }));
      //     } else {
      //       broadcast({
      //         type: 'fileTransfer',
      //         from: userName,
      //         fileName: data.fileName,
      //         fileLink: fileLink
      //       });
      //     }
      //   }
    }
  });

  ws.on('close', () =>
  {
    // delete clients[userName];
    // broadcastOnlineUsers();
  });

  // console.log('sending client_update_request');
  // serverWs.send(JSON.stringify({ type: "client_update_request" }));
  // console.log('sending server_hello');
  // serverWs.send(JSON.stringify({
  //   data: {
  //     type: "server_hello",
  //     sender: server.address().address,
  // } }));
});


//#region Links
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

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) =>
{
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }
  const fileName = req.file.filename;
  res.send({ fileName });
});

app.post('/api/upload', upload.single('file'), (req, res) =>
{
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }

  // Generate the unique file URL
  const fileLink = `http://${req.headers.host}/files/${req.file.filename}`;
  res.json({ file_url: fileLink });
});
//#endregion

//#region Listen

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
//#endregion
