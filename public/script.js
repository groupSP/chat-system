let ws;
let username;

// Initialize WebSocket connection
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}`); // Connect to the WebSocket server

    ws.onopen = () => {
        console.log("WebSocket connection opened.");
        ws.send(JSON.stringify({ type: 'login', name: username }));
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
    
            // Create a download link for the received file
            const fileLink = data.fileLink; // Get the file link sent from the server
            const messageDiv = document.createElement('div');
            
            const link = document.createElement('a');
            link.href = fileLink;  // This should point to /files/:filename
            link.download = data.fileName;  // Suggest a filename for download
            link.textContent = `${data.from} sent a file: ${data.fileName}`;  // Display sender and file name
            link.target = "_blank"; // Optional: prevents opening a new tab
    
            messageDiv.appendChild(link);
            document.getElementById('chat-messages').appendChild(messageDiv);
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
        username = document.getElementById('username').value;
        if (username) {
            initWebSocket(); // Initialize WebSocket connection
            document.getElementById('login-container').style.display = 'none';
        }
    });

    // Send message button click event
    document.getElementById('send-message').addEventListener('click', () => {
        const message = document.getElementById('message').value;
        if (message) {
            ws.send(JSON.stringify({ type: 'groupMessage', message }));
            displayMessage('You', message); // Display the message locally
            document.getElementById('message').value = ''; // Clear the input field
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

// Update online users list
function updateOnlineUsers(users) {
    const onlineUsers = document.getElementById('online-users');
    onlineUsers.innerHTML = '';
    users.forEach(user => {
        const li = document.createElement('li');
        li.textContent = user;
        onlineUsers.appendChild(li);
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
function displayFileLink(fileName, fileLink, from) {
    const chatMessages = document.getElementById('chat-messages');
    const link = document.createElement('a');
    
    link.href = fileLink;  // Link to the file
    link.download = fileName;  // Suggest a filename for download
    link.textContent = `${from} sent a file: ${fileName}`;  // Display sender and file name
    link.target = "_blank"; // Open link in a new tab
    
    const messageDiv = document.createElement('div');
    messageDiv.appendChild(link);
    chatMessages.appendChild(messageDiv);
}
