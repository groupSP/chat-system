let ws;
let username;

// 登录按钮点击事件
document.getElementById('login-btn').addEventListener('click', () => {
    username = document.getElementById('username').value;
    if (username) {
        initWebSocket();
        document.getElementById('login-container').style.display = 'none';
    }
});

// 初始化 WebSocket 连接
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'login', name: username }));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        // 更新在线用户列表
        if (data.type === 'onlineUsers') {
            updateOnlineUsers(data.users);
        }

        // 显示私信或群聊消息
        if (data.type === 'privateMessage' || data.type === 'groupMessage') {
            displayMessage(data.from, data.message);
        }

        // 处理文件传输
        if (data.type === 'fileTransfer') {
            console.log(`Received file from ${data.from}: ${data.fileName}`);
            displayDownloadLink(data.fileName, data.fileData);
        }
    };
}

// 更新在线用户列表
function updateOnlineUsers(users) {
    const onlineUsers = document.getElementById('online-users');
    const recipientSelect = document.getElementById('recipient');
    onlineUsers.innerHTML = '';
    recipientSelect.innerHTML = '<option value="group">Group Chat</option>';
    users.forEach(user => {
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsers.appendChild(li);

        const option = document.createElement('option');
        option.value = user;
        option.textContent = user;
        recipientSelect.appendChild(option);
    });
}

// 显示消息
function displayMessage(from, message) {
    const chatMessages = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.textContent = `${from}: ${message}`;
    chatMessages.appendChild(messageDiv);
}

// 发送消息按钮点击事件
document.getElementById('send-message').addEventListener('click', () => {
    const message = document.getElementById('message').value;
    const recipient = document.getElementById('recipient').value;
    if (message) {
        const messageType = recipient === 'group' ? 'groupMessage' : 'privateMessage';
        ws.send(JSON.stringify({ type: messageType, message, to: recipient }));
        displayMessage('You', message);
        document.getElementById('message').value = '';
    }
});

// 文件发送按钮点击事件
document.getElementById('send-file').addEventListener('click', () => {
    const fileInput = document.getElementById('file-input');
    const recipient = document.getElementById('recipient').value;
    const file = fileInput.files[0];

    if (file) {
        const reader = new FileReader();
        reader.onload = function(event) {
            const fileData = event.target.result; // Base64 编码的文件数据
            ws.send(JSON.stringify({
                type: 'fileTransfer',
                fileName: file.name,
                fileData: fileData,
                to: recipient
            }));
            displayMessage('You', `Sent a file: ${file.name}`);
        };
        reader.readAsDataURL(file); // 以 base64 格式读取文件
    }
});

// 显示文件下载链接
function displayDownloadLink(fileName, fileData) {
    const chatMessages = document.getElementById('chat-messages');
    const link = document.createElement('a');

    // 确保 href 使用的是 base64 格式的数据，正确显示文件
    link.href = fileData;  // Base64 数据
    link.download = fileName;  // 设置下载文件名
    link.textContent = `Download ${fileName}`;

    link.onclick = function(event) {
        // 设置打开行为，文件可点击打开
        const fileType = fileData.split(';')[0].split(':')[1]; // 从Base64中提取文件类型
        const win = window.open(fileData, '_blank');
        if (win) {
            win.focus();
        } else {
            alert("Please allow popups for this site.");
        }
    };

    const messageDiv = document.createElement('div');
    messageDiv.appendChild(link);
    chatMessages.appendChild(messageDiv);
}
