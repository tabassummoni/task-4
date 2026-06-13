// db.js
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const client = new MongoClient(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/user_management_system');
let db;

// IMPORTANT: Ensure the word 'export' is present right before 'async function'
export async function connectDB() {
  if (db) return db;
  try {
    await client.connect();
    db = client.db('user_management_system');
    
    // Establishing the storage-level unique index constraint
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    
    console.log('Connected to MongoDB and Unique Index established.');
    return db;
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
}

// IMPORTANT: Ensure the word 'export' is present right before 'function'
export function getCollection() {
  return db.collection('users');
}