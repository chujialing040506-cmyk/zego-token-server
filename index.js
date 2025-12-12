// index.js
// ZEGOCLOUD Token Server - 生产安全版
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// 从环境变量读取 APP_ID 和 SERVER_SECRET
const APP_ID = process.env.ZEGO_APP_ID ? Number(process.env.ZEGO_APP_ID) : null;
const SERVER_SECRET = process.env.ZEGO_SERVER_SECRET || null;

if (!APP_ID || !SERVER_SECRET) {
    console.warn('WARNING: ZEGO_APP_ID or ZEGO_SERVER_SECRET not set in environment variables.');
}

/**
 * generateZegoToken
 * - 生成 ZEGOCLOUD token (identity token)
 * - AES-256-CBC 加密 (key = SHA256(serverSecret)) -> iv + ciphertext -> base64
 */
function generateZegoToken(appID, userID, expireSeconds = 3600) {
    if (!appID || !userID) throw new Error('appID and userID are required');

    const ctime = Math.floor(Date.now() / 1000);
    const expire = ctime + Number(expireSeconds || 3600);
    const nonce = Math.floor(Math.random() * 1e9);

    const payloadObj = { app_id: appID, user_id: String(userID), nonce, ctime, expire };
    const payloadStr = JSON.stringify(payloadObj);

    // 使用 SERVER_SECRET SHA256 生成 AES-256 key
    const key = crypto.createHash('sha256').update(String(SERVER_SECRET), 'utf8').digest();
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(payloadStr, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const tokenBuf = Buffer.concat([iv, Buffer.from(encrypted, 'base64')]);
    return tokenBuf.toString('base64');
}

// HTTP 接口：GET /get_token?userID=xxx[&expire=3600]
app.get('/get_token', (req, res) => {
    try {
        const { userID, roomID, expire } = req.query;
        if (!userID) return res.status(400).json({ error: 'Missing userID' });
        if (!APP_ID || !SERVER_SECRET) return res.status(500).json({ error: 'Server not configured' });

        const payloadObj = {
            app_id: APP_ID, user_id: String(userID), nonce: Math.floor(Math.random() * 1e9),
            ctime: Math.floor(Date.now() / 1000),
            expire: Number(expire || 3600),
            room_id: roomID
        };

        const key = crypto.createHash('sha256').update(String(SERVER_SECRET), 'utf8').digest();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(JSON.stringify(payloadObj), 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const tokenBuf = Buffer.concat([iv, Buffer.from(encrypted, 'base64')]);

        return res.json({ appID: APP_ID, token: tokenBuf.toString('base64'), roomID });
    } catch (err) {
        console.error('generate token error:', err);
        return res.status(500).json({ error: 'token generation failed' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Zego Token Server running on port ${PORT}`);
});
