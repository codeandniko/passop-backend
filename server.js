/* global process */

import express from 'express';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import cors from 'cors';
import crypto from 'crypto';
import { Buffer } from 'buffer';

// or as an es module:
// import { MongoClient } from 'mongodb'
dotenv.config()

// Connection URL
const url = process.env.MONGO_URI;
const client = new MongoClient(url);

// Database Namenpm i dotenv


const dbName = 'Passop';
const app = express()
const port = process.env.PORT || 3000;
app.use(bodyParser.json())
app.use(cors())

const ENCRYPTION_KEY = crypto.scryptSync(process.env.SECRET_KEY || 'default_secret', 'salt', 32); // Must be 32 bytes for AES-256
const IV = Buffer.alloc(16, 0); // Initialization vector (can be random but must be 16 bytes)

const encrypt = (text) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

const decrypt = (encrypted) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};


client.connect();


app.get('/', async (req, res) => {
  const db = client.db(dbName);
  const collection = db.collection('passwoards');
  const findResult = await collection.find({}).toArray();

  const decryptedPasswords = findResult.map(item => ({
    ...item,
    password: item.password ? decrypt(item.password) : ''
  }));

  res.json(decryptedPasswords);
});


app.post('/', async (req, res) => {
  try {
    const password = req.body;

    if (password.password) {
      password.password = encrypt(password.password);
    }

    const db = client.db(dbName);
    const collection = db.collection('passwoards');
    const result = await collection.insertOne(password);

    res.send({ success: true, result });
  } catch (error) {
    console.error("Error inserting password:", error);
    res.status(500).send({ success: false, error: "Internal Server Error" });
  }
});


app.delete('/', async (req, res) => {
  const { id } = req.body;
  console.log("Delete request for id:", id); // <-- helpful logging
  const db = client.db(dbName);
  const collection = db.collection('passwoards');
  const result = await collection.deleteOne({ id });
  console.log("Delete result:", result); // <-- shows matched/deleted count
  res.send({ success: true, result });
});


app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
}); 
app.post('/suggest-password', (req, res) => {
  const { site, username } = req.body;

  if (!site || !username) {
    return res.status(400).json({ error: 'Site and username are required' });
  }

  // Create a deterministic password hash (could also use random gen if you prefer)
  const hash = crypto.createHmac('sha256', ENCRYPTION_KEY)
    .update(site + username)
    .digest('base64');

  // Limit the password length and clean it up
  const suggestedPassword = hash
    .replace(/[^a-zA-Z0-9]/g, '')
    .slice(0, 16) // 16-character suggestion
    + '!@'; // add symbols for complexity

  res.json({ password: suggestedPassword });
});
