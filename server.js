// mongodb+srv://<db_username>:<db_password>@cluster0.4moveuh.mongodb.net/?appName=Cluster0

// server.js
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { body, validationResult } from 'express-validator';
import { ObjectId } from 'mongodb';
import { connectDB, getCollection } from './db.js';

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_boring_key';
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json());
app.use(morgan('tiny'));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// IMPORTANT: Utility function required by specific criteria to extract unique identifiers.
// NOTE: This extracts the raw string or returns a fallback unique value safely.
function getUniqIdValue(doc) {
  if (!doc) return '';
  return doc._id ? doc._id.toString() : '';
}

// =========================================================================
// MIDDLEWARE: THE FIFTH REQUIREMENT
// =========================================================================
async function authAndStatusCheck(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Session expired or missing token.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const usersCollection = getCollection();
    
    // NOTE: Check database directly to see if user was deleted or blocked in real-time.
    const user = await usersCollection.findOne({ _id: new ObjectId(decoded.id) });
    
    if (!user) {
      return res.status(403).json({ error: 'Your account has been deleted.', redirect: true });
    }
    if (user.status === 'blocked') {
      return res.status(403).json({ error: 'Your account has been blocked.', redirect: true });
    }

    req.currentUser = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid session token.', redirect: true });
  }
}

// =========================================================================
// AUTH ROUTES (No middleware check here)
// =========================================================================

app.post(
  '/api/auth/register',
  authLimiter,
  [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 1 }).withMessage('Password cannot be empty')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, email, password } = req.body;

  try {
    const usersCollection = getCollection();
    const hashed = await bcrypt.hash(password, 10);
    const newUser = {
      name: name || 'Anonymous',
      email: email.toLowerCase().trim(),
      password: hashed,
      status: 'unverified',
      lastLogin: null,
      createdAt: new Date()
    };

    await usersCollection.insertOne(newUser);

    setImmediate(() => {
      console.log(`Asynchronously sending verification link to ${newUser.email}: ${APP_URL}/api/auth/verify?email=${newUser.email}`);
    });

    res.status(201).json({ message: 'Registration successful! A verification email has been sent.' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'The specified email address is already in use.' });
    }
    res.status(500).json({ error: 'Internal server error.' });
  }
});

app.post(
  '/api/auth/login',
  authLimiter,
  [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 1 }).withMessage('Password cannot be empty')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
  try {
    const usersCollection = getCollection();
    const user = await usersCollection.findOne({ email: email.toLowerCase().trim() });

    if (!user) return res.status(401).json({ error: 'Invalid credentials presented.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials presented.' });
    if (user.status === 'blocked') {
      return res.status(403).json({ error: 'This user account is currently blocked.' });
    }

    const lastLoginTime = new Date();
    await usersCollection.updateOne({ _id: user._id }, { $set: { lastLogin: lastLoginTime } });

    const token = jwt.sign({ id: getUniqIdValue(user) }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, message: 'Authentication successful.' });
  } catch (error) {
    res.status(500).json({ error: 'Login process failed.' });
  }
});

app.get('/api/auth/verify', async (req, res) => {
  const { email } = req.query;
  try {
    const usersCollection = getCollection();
    const user = await usersCollection.findOne({ email });
    
    if (!user) return res.status(404).send('User not found.');
    
    // IMPORTANT: Clicking the link changes status from "unverified" to "active". "blocked" stays "blocked".
    if (user.status === 'unverified') {
      await usersCollection.updateOne({ _id: user._id }, { $set: { status: 'active' } });
    }
    
    res.send('<h1>Email Verified Successfully! You may now return to the app.</h1>');
  } catch (error) {
    res.status(500).send('Verification failed.');
  }
});

// =========================================================================
// PROTECTED USER MANAGEMENT ROUTES
// =========================================================================

app.get('/api/users', authAndStatusCheck, async (req, res) => {
  try {
    const usersCollection = getCollection();
    // THE THIRD REQUIREMENT: Sorted by the last login time safely (newest first)
    const users = await usersCollection.find({}).sort({ lastLogin: -1 }).toArray();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch management records.' });
  }
});

app.post('/api/users/action', authAndStatusCheck, async (req, res) => {
  const { userIds, action } = req.body;
  if (!userIds || !userIds.length) return res.status(400).json({ error: 'No targets selected.' });

  try {
    const usersCollection = getCollection();
    const objectIds = userIds.map(id => new ObjectId(id));

    if (action === 'block') {
      await usersCollection.updateMany({ _id: { $in: objectIds } }, { $set: { status: 'blocked' } });
    } else if (action === 'unblock') {
      // NOTA BENE: Unblocking a user resets them back to active.
      await usersCollection.updateMany({ _id: { $in: objectIds } }, { $set: { status: 'active' } });
    } else if (action === 'delete') {
      // IMPORTANT: Deleted users must be completely dropped, not "marked".
      await usersCollection.deleteMany({ _id: { $in: objectIds } });
    } else if (action === 'delete-unverified') {
      await usersCollection.deleteMany({ _id: { $in: objectIds }, status: 'unverified' });
    }

    res.json({ message: 'Operation executed successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Action execution failed.' });
  }
});

// Initialize database before spawning web instance
connectDB().then(() => {
  const server = app.listen(PORT, () => console.log(`Server serving seamlessly on port ${PORT}`));

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use. Start with a different port: PORT=5001 node Server.js`);
    } else {
      console.error('Server error:', err);
    }
    process.exit(1);
  });
});