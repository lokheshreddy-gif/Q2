import express from 'express';
import dotenv from 'dotenv';
import { createSecurityMiddleware, globalNonceStore } from './security.js';

dotenv.config();

export const app = express();
const PORT = process.env.PORT || 3000;

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

// Helper endpoint for testing to reset nonce store
app.post('/test/reset-nonces', (req, res) => {
  globalNonceStore.clear();
  res.status(200).json({ success: true, message: 'Nonce store cleared' });
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
