let ws;

function initWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log("WebSocket already connected.");
        return;
    }

    ws = new WebSocket(`ws://${window.location.host}`);

    ws.onopen = () => {
        console.log("WebSocket connection opened.");
        ws.send(JSON.stringify({
            type: 'hello',
            public_key: serverPublicKeyPem,
            name: username
        }));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log("Received WebSocket message:", data);

        if (data.type === 'fileTransfer') {
            handleFileTransfer(data);  // Moved the fileTransfer logic here for clarity
        }
        // Handle other message types...
    };

    ws.onerror = (error) => {
        console.error("WebSocket error:", error);
    };

    ws.onclose = () => {
        console.log("WebSocket connection closed. Attempting to reconnect...");
        setTimeout(initWebSocket, 2000);
    };
}

function handleFileTransfer(data) {
    if (data.fileName && data.from) {
        const fileMessageId = `${data.from}-${data.fileName}`;
        console.log("Generated fileMessageId:", fileMessageId);

        if (!processedFileMessages.has(fileMessageId)) {
            processedFileMessages.add(fileMessageId);

            if (data.from !== username) {
                displayFileLink(data.from, data.fileName, data.fileLink);
            }
        } else {
            console.log(`Duplicate file message ignored: ${fileMessageId}`);
        }
    } else {
        console.error("Missing fileName or from in the fileTransfer message");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        initWebSocket();
    }

    document.getElementById('login-btn').addEventListener('click', () => {
        username = document.getElementById('username').value.trim();

        if (username) {
            document.body.classList.add('logged-in');
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                initWebSocket();
            }
            generateAESKey();
        } else {
            alert('Please enter a valid username.');
        }
    });
});
