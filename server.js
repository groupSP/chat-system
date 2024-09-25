// const express = require('express');
// const WebSocket = require('ws');
// const http = require('http');
// const path = require('path');

// // 初始化 Express 应用
// const app = express();
// const server = http.createServer(app);

// // 初始化 WebSocket 服务器
// const wss = new WebSocket.Server({ server });

// // 存储在线用户
// let clients = {};

// // 处理 WebSocket 连接
// wss.on('connection', (ws) => {
//   let userName = '';

//   ws.on('message', (message) => {
//     const data = JSON.parse(message);

//     // 用户登录并设置用户名
//     if (data.type === 'login') {
//       userName = data.name;
//       clients[userName] = ws;

//       // 通知所有用户在线列表更新
//       broadcastOnlineUsers();
//     }

//     // 处理私信
//     if (data.type === 'privateMessage') {
//       const recipientWs = clients[data.to];
//       if (recipientWs) {
//         recipientWs.send(JSON.stringify({
//           type: 'privateMessage',
//           from: userName,
//           message: data.message
//         }));
//       }
//     }

//     // 处理群聊消息
//     if (data.type === 'groupMessage') {
//       broadcast({
//         type: 'groupMessage',
//         from: userName,
//         message: data.message
//       });
//     }

//     // 处理文件传输
//     if (data.type === 'fileTransfer') {
//       console.log(`Received file: ${data.fileName} from ${userName}`);
//       console.log(`File data: ${data.fileData.substring(0, 100)}...`);  // 打印文件数据的一部分
      
//       const recipientWs = clients[data.to];
//       if (recipientWs) {
//         recipientWs.send(JSON.stringify({
//           type: 'fileTransfer',
//           from: userName,
//           fileName: data.fileName,
//           fileData: data.fileData
//         }));
//       }
//     }
//   });

//   ws.on('close', () => {
//     delete clients[userName];
//     broadcastOnlineUsers();
//   });
// });

// // 广播在线用户列表
// function broadcastOnlineUsers() {
//   const onlineUsers = Object.keys(clients);
//   broadcast({
//     type: 'onlineUsers',
//     users: onlineUsers
//   });
// }

// // 广播消息给所有客户端
// function broadcast(message) {
//   wss.clients.forEach(client => {
//     if (client.readyState === WebSocket.OPEN) {
//       client.send(JSON.stringify(message));
//     }
//   });
// }

// // 静态资源服务
// app.use(express.static(path.join(__dirname, 'public')));

// // 启动服务器
// const PORT = process.env.PORT || 3000;
// server.listen(PORT, () => {
//   console.log(`Server started on port ${PORT}`);
// });
const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const multer = require('multer');

// Initialize Express application
const app = express();
const server = http.createServer(app);

// Initialize WebSocket server
const wss = new WebSocket.Server({ server });

// Set up multer for file uploads
const upload = multer({ dest: 'uploads/' }); // Files will be stored in the "uploads" folder

// Store online users
let clients = {};

// Handle WebSocket connections
wss.on('connection', (ws) => {
    let userName = '';

    ws.on('message', (message) => {
        const data = JSON.parse(message);

        // User login and set username
        if (data.type === 'login') {
            userName = data.name;
            clients[userName] = ws;

            // Notify all users about the updated online list
            broadcastOnlineUsers();
        }

        // Handle private messages
        if (data.type === 'privateMessage') {
            const recipientWs = clients[data.to];
            if (recipientWs) {
                recipientWs.send(JSON.stringify({
                    type: 'privateMessage',
                    from: userName,
                    message: data.message
                }));
            }
        }

        // Handle group messages
        if (data.type === 'groupMessage') {
            broadcast({
                type: 'groupMessage',
                from: userName,
                message: data.message
            });
        }

        // Handle file transfers
        if (data.type === 'fileTransfer') {
            const fileLink = `http://${server.address().address}:${server.address().port}/files/${data.fileName}`;
          broadcast({
                type: 'fileTransfer',
                from: userName,
                fileName: data.fileName,
                fileLink: fileLink // Send a file link instead of data
            });
        }
    });

    ws.on('close', () => {
        delete clients[userName];
        broadcastOnlineUsers();
    });
});

// Broadcast online user list
function broadcastOnlineUsers() {
    const onlineUsers = Object.keys(clients);
    broadcast({
        type: 'onlineUsers',
        users: onlineUsers
    });
}

// Broadcast message to all clients
function broadcast(message) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
}

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

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
