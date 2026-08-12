import express from 'express';
import dotenv from 'dotenv';
import { createSecurityMiddleware, globalNonceStore } from './security.js';
import { generateNonce, generateChallengeToken } from '../utils/hmac.js';

dotenv.config();

export const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store for pending/completed transactions
export const transactionsMap = new Map();

// Parse JSON request bodies
app.use(express.json());

// Public Health Check Endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: Date.now()
  });
});

// Protected API Endpoints applying HMAC & Anti-Replay Security
const securityMiddleware = createSecurityMiddleware();

// ----------------------------------------------------
// Challenge-Response Two-Step Transaction Protocol
// ----------------------------------------------------

// Handler for initiating a transaction (Step 1)
const handleCreateTransaction = (req, res) => {
  const transactionId = `tx_${Date.now()}_${Math.floor(Math.random() * 1000000)}`;
  const challengeToken = generateChallengeToken();
  const timestamp = Date.now();
  const nonce = generateNonce();

  const transactionData = {
    transactionId,
    challengeToken,
    timestamp,
    nonce,
    status: 'pending',
    createdAt: timestamp,
    payload: req.body || {}
  };

  transactionsMap.set(transactionId, transactionData);

  res.status(201).json({
    transactionId,
    challengeToken,
    timestamp,
    nonce
  });
};

app.post('/transactions', handleCreateTransaction);
app.post('/api/transactions', handleCreateTransaction);

// Handler for executing/confirming a transaction via PUT (Step 2)
const handleCompleteTransaction = (req, res) => {
  const { id } = req.params;
  const transaction = transactionsMap.get(id);

  if (!transaction) {
    return res.status(404).json({ error: 'Transaction not found' });
  }

  if (transaction.status === 'completed') {
    return res.status(409).json({
      error: 'Conflict: Transaction has already been executed',
      transactionId: id
    });
  }

  transaction.status = 'completed';
  transaction.completedAt = Date.now();
  transaction.resultPayload = req.body;

  res.status(200).json({
    success: true,
    message: 'Transaction executed successfully',
    transactionId: id,
    status: 'completed',
    details: req.body
  });
};

app.put('/transactions/:id', securityMiddleware, handleCompleteTransaction);
app.put('/api/transactions/:id', securityMiddleware, handleCompleteTransaction);

app.post('/api/action', securityMiddleware, (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Action executed successfully',
    payload: req.body,
    processedAt: Date.now()
  });
});

app.post('/api/transaction', securityMiddleware, (req, res) => {
  const { amount, recipient } = req.body || {};
  res.status(200).json({
    success: true,
    message: 'Transaction processed securely',
    transactionId: `tx_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
    details: {
      amount: amount || 0,
      recipient: recipient || 'unknown'
    }
  });
});

// Helper endpoint for testing to reset nonce store and transactions map
app.post('/test/reset-nonces', (req, res) => {
  globalNonceStore.clear();
  transactionsMap.clear();
  res.status(200).json({ success: true, message: 'Nonce store and transactions map cleared' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start listening if run directly
if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}
