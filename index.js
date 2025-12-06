// index.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const APP_ID = 1894903703; // 你的 AppID
const SERVER_SECRET = '692aec361bc12cee470ce62ba582f300'; // 你的 ServerSecret

// 生成 Zego Token
function generateZegoToken(roomID, userID, effectiveTimeInSeconds = 3600) {
    const nonce = Math.floor(Math.random() * 1000000);
    const ts = Math.floor(Date.now() / 1000);
    const data = `roomID=${roomID}&userID=${userID}&nonce=${nonce}&ts=${ts}&expire=${effectiveTimeInSeconds}`;
    const hmac = crypto.createHmac('sha256', SERVER_SECRET);
    hmac.update(data);
    const token = hmac.digest('base64');
    return token;
}

// 提供 HTTP 接口
app.get('/get_token', (req, res) => {
    const { roomID, userID } = req.query;
    if (!roomID || !userID) return res.status(400).json({ error: 'Missing roomID or userID' });

    const token = generateZegoToken(roomID, userID);
    res.json({ appID: APP_ID, token });
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Zego Token Server running on port ${PORT}`);
});