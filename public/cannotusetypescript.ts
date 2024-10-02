//#region Types
interface User {
  id: string;
  username: string;
  publicKey: string;
}

interface ChatMessage {
  id: number; // or string, depending on your ID type
  senderId: number; // or string
  content: string;
  timestamp: Date;
  chat: Chat; // Ensure that this property exists
  symm_keys: string[];
  iv: string;
  from: string;
}

interface Chat {
  id: number; // or string
  name: string;
}

interface EncryptedMessage {
  encryptedMessage: string;
  authTag: string;
  iv: string;
}

interface OnlineUsers {
  [id: string]: string; // Mapping of user ID to their public key
}

interface PublicKeyResponse {
  key: string;
}

interface FileTransferMessage {
  from: string;
  fileName: string;
  fileLink: string;
}

interface ForwardListItem {
  value: string;
  textContent: string;
}
//#endregion
//#region Variables
let ws: WebSocket;
let aesKey: CryptoKey;
let iv: Uint8Array;
let retryAttempts = 0;
let username: string;
let serverPublicKeyPem: string = "";
let privateKey: CryptoKey;
let onlineUsers: OnlineUsers = {};
let messageCounter = 0;
let selectedMessages: string[] = [];
let processedMessages: string[] = [];
let processedFileMessages: string[] = [];
//#endregion

//#region Encryption
async function generateKeyPair(): Promise<void> {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: { name: "SHA-256" },
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );
    const publicKeyBase64 = btoa(
      String.fromCharCode(...new Uint8Array(publicKey))
    );

    localStorage.setItem("privateKey", JSON.stringify(keyPair.privateKey));
    localStorage.setItem("publicKey", publicKeyBase64);

    const helloMessage = {
      data: { type: "hello", public_key: publicKeyBase64 },
    };
    ws.send(JSON.stringify(helloMessage));
  } catch (error) {
    console.error("Error generating key pair:", error);
  }
}

async function importServerPublicKey(pemKey: string): Promise<CryptoKey> {
  const keyBuffer = pemToArrayBuffer(pemKey);
  return await window.crypto.subtle.importKey(
    "spki",
    keyBuffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64Lines = pem.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, "");
  const b64 = atob(b64Lines);
  const buffer = new ArrayBuffer(b64.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < b64.length; i++) {
    view[i] = b64.charCodeAt(i);
  }
  return buffer;
}

async function generateAESKey(): Promise<void> {
  try {
    aesKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 128 },
      true,
      ["encrypt", "decrypt"]
    );
    console.log("AES Key Generated:", aesKey);
  } catch (error) {
    console.error("Error generating AES key:", error);
  }
}

async function encryptMessage(
  message: string
): Promise<EncryptedMessage | undefined> {
  try {
    iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedMessage = new TextEncoder().encode(message);
    const encryptedMessage = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      encodedMessage
    );

    const encryptedArray = new Uint8Array(encryptedMessage);
    const ciphertext = encryptedArray.slice(0, -16);
    const authTag = encryptedArray.slice(-16);

    return {
      encryptedMessage: btoa(String.fromCharCode(...ciphertext)),
      authTag: btoa(String.fromCharCode.apply(null, Array.from(authTag))),
      iv: btoa(String.fromCharCode.apply(null, Array.from(iv))),
    };
  } catch (error) {
    console.error("Error encrypting message:", error);
  }
}

function decryptWithAES(encryptedData: string, key: string, iv: string) {
  const decrypted = CryptoJS.AES.decrypt(
    CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(encryptedData),
    }),
    CryptoJS.enc.Hex.parse(key),
    {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  );

  return decrypted.toString(CryptoJS.enc.Utf8);
}
//#endregion

//#region WebSocket
function initWebSocket(): void {
  generateKeyPair();

  if (ws && ws.readyState === WebSocket.OPEN) {
    console.log("WebSocket already connected.");
    ws.close();
  } else if (retryAttempts > 1) {
    console.log("Retry attempts:", retryAttempts);
  }

  ws = new WebSocket(`ws://${window.location.host}`);

  ws.onopen = () => {
    retryAttempts = 0;
    console.log("WebSocket connection opened.");
  };

  ws.onmessage = handleWebSocketMessage;
  ws.onclose = handleWebSocketClose;
  ws.onerror = (error) => console.error("WebSocket error:", error);
}

function handleWebSocketMessage(event: MessageEvent): void {
  const data = JSON.parse(event.data);

  switch (data.type) {
    case "publicKey":
      serverPublicKeyPem = data.key;
      break;

    case "onlineUsers":
      onlineUsers = data.users.reduce((acc: OnlineUsers, user: User) => {
        if (user.username && user.username.trim() !== "undefined") {
          acc[user.id] = user.publicKey;
        }
        return acc;
      }, {});
      updateOnlineUsers(onlineUsers);
      break;

    case "chat":
      processChatMessage(data);
      break;

    case "fileTransfer":
      processFileTransfer(data);
      break;

    case "client_list":
      //   updateClientList(data.servers);
      break;

    default:
      console.log("Unknown message type:", data);
  }
}

function handleWebSocketClose(): void {
  console.log("WebSocket connection closed");
  retryAttempts++;
  setTimeout(initWebSocket, 2000); // Retry every 2 seconds
}
//#endregion
//#region update
async function processChatMessage(data: ChatMessage): Promise<void> {
  try {
    console.log("Received chat message:", data);
    const decryptedMessage = await decryptWithAES(
      data.chat.name,
      data.symm_keys[0],
      data.iv
    );
    displayMessage(data.from, decryptedMessage);
  } catch (error) {
    console.error("Error processing chat message:", error);
  }
}

function displayMessage(from: string, message: string): void {
  const chatMessages = document.getElementById("chat-messages")!;
  const messageDiv = document.createElement("div");

  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.onclick = () => toggleMessageSelection(message, checkbox.checked);

  const displayFrom = from === username ? "You" : from;
  const messageContent = document.createElement("span");
  messageContent.textContent = `${displayFrom}: ${message}`;

  messageDiv.appendChild(checkbox);
  messageDiv.appendChild(messageContent);
  chatMessages.appendChild(messageDiv);
}

function processFileTransfer(data: FileTransferMessage): void {
  const messageId = `${data.from}-${data.fileName}`;
  if (!processedFileMessages.includes(messageId)) {
    processedFileMessages.push(messageId);
    displayFileLink(data.from, data.fileName, data.fileLink);
  }
}

function updateOnlineUsers(users: OnlineUsers): void {
  const forwardList = document.getElementById("forward-user-list")!;
  forwardList.innerHTML = ""; // Clear old users

  Object.keys(users).forEach((id) => {
    if (users[id] !== username) {
      const option = document.createElement("option");
      option.value = users[id];
      option.textContent = users[id];
      forwardList.appendChild(option);
    }
  });
}

function toggleMessageSelection(message: string, selected: boolean): void {
  if (selected) {
    selectedMessages.push(message);
  } else {
    selectedMessages = selectedMessages.filter((msg) => msg !== message);
  }
}

function displayFileLink(
  from: string,
  fileName: string,
  fileLink: string
): void {
  const chatMessages = document.getElementById("chat-messages")!;
  const fileDiv = document.createElement("div");

  const fileLinkElement = document.createElement("a");
  fileLinkElement.href = fileLink;
  fileLinkElement.textContent = `${from}: ${fileName}`;
  fileLinkElement.target = "_blank"; // Open in new tab

  fileDiv.appendChild(fileLinkElement);
  chatMessages.appendChild(fileDiv);
}
//#endregion
