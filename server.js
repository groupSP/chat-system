const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

// 初始化 Express 应用
const app = express();
const server = http.createServer(app);

// 初始化 WebSocket 服务器
const wss = new WebSocket.Server({ server });

// 存储在线用户
let clients = {};

// 处理 WebSocket 连接
wss.on('connection', (ws) => {
  let userName = '';

  ws.on('message', (message) => {
    const data = JSON.parse(message);

    // 用户登录并设置用户名
    if (data.type === 'login') {
      userName = data.name;
      clients[userName] = ws;

      // 通知所有用户在线列表更新
      broadcastOnlineUsers();
    }

    // 处理私信
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

    // 处理群聊消息
    if (data.type === 'groupMessage') {
      broadcast({
        type: 'groupMessage',
        from: userName,
        message: data.message
      });
    }

    // 处理文件传输
    if (data.type === 'fileTransfer') {
      console.log(`Received file: ${data.fileName} from ${userName}`);
      console.log(`File data: ${data.fileData.substring(0, 100)}...`);  // 打印文件数据的一部分
      
      const recipientWs = clients[data.to];
      if (recipientWs) {
        recipientWs.send(JSON.stringify({
          type: 'fileTransfer',
          from: userName,
          fileName: data.fileName,
          fileData: data.fileData
        }));
      }
    }
  });

  ws.on('close', () => {
    delete clients[userName];
    broadcastOnlineUsers();
  });
});

// 广播在线用户列表
function broadcastOnlineUsers() {
  const onlineUsers = Object.keys(clients);
  broadcast({
    type: 'onlineUsers',
    users: onlineUsers
  });
}

// 广播消息给所有客户端
function broadcast(message) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
}

// 静态资源服务
app.use(express.static(path.join(__dirname, 'public')));

// 启动服务器
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
