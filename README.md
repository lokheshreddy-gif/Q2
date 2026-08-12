# Q2: HMAC Anti-Replay Protection Security Framework

A production-ready Node.js Express security architecture providing cryptographic request authentication via HMAC-SHA256 signatures, request tampering defense, timestamp drift enforcement, and sliding-window nonce replay attack mitigation.

---

## 📁 Repository Structure

```
q2/
├── server/
│   ├── server.js        # Express application & API endpoint handlers
│   └── security.js      # Anti-replay middleware & NonceStore TTL cache
├── tests/
│   └── replay.spec.js   # Automated Playwright test suite for replay attacks
├── utils/
│   └── hmac.js          # Cryptographic SHA256 HMAC signing & verification
├── package.json         # Project manifests and scripts
├── .env.example         # Environment variable blueprint
└── README.md            # System architecture and documentation
```

---

## 🛡️ Threat Model & Security Design

This system protects client-server communication against key web vulnerabilities:

1. **Replay Attacks**: An attacker intercepts a legitimate API payload and re-sends it to repeat an action (e.g., repeating a payment transaction).
   - *Mitigation*: Each request includes a unique cryptographic `x-nonce`. Processed nonces are stored in an in-memory `NonceStore` TTL cache and rejected if seen again.
2. **Request Tampering**: An attacker modifies payload data or path parameters in transit.
   - *Mitigation*: Requests are signed with an HMAC-SHA256 signature calculated over a canonical representation of the method, path, timestamp, nonce, and body.
3. **Timestamp Skew / Stale Requests**: An attacker attempts to replay old requests after the server cache resets.
   - *Mitigation*: Timestamps older than `MAX_TIMESTAMP_DIFF_MS` (default 5 minutes) are rejected automatically.
4. **Timing Attacks**: An attacker uses subtle time differences in string comparison to guess HMAC signatures.
   - *Mitigation*: Verification uses Node.js `crypto.timingSafeEqual()` for constant-time comparison.

---

## 🔑 Canonical String Specification

Before calculating the HMAC signature, client and server build an identical canonical string format:

```
METHOD:PATH:TIMESTAMP:NONCE:BODY_JSON
```

### Example

- **Method**: `POST`
- **Path**: `/api/action`
- **Timestamp**: `1723450000000`
- **Nonce**: `a1b2c3d4e5f67890a1b2c3d4e5f67890`
- **Body**: `{"action":"create_item","itemId":42}`

**Canonical String**:
`POST:/api/action:1723450000000:a1b2c3d4e5f67890a1b2c3d4e5f67890:{"action":"create_item","itemId":42}`

**Signature Calculation**:
```js
HMAC-SHA256(canonicalString, HMAC_SECRET)
```

---

## 🚀 Quick Start Guide

### 1. Installation

```bash
cd q2
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 3. Run Web Server

```bash
npm start
```

Server will run on `http://localhost:3000`.

---

## 🧪 Automated Test Suite

The project uses [Playwright Test](https://playwright.dev/) for automated API verification.

To execute tests:

```bash
npx playwright test
```

### Test Coverage (`tests/replay.spec.js`)

| # | Test Scenario | Expected Outcome |
|---|---------------|------------------|
| 1 | **Legitimate Request** | `200 OK` with valid response body |
| 2 | **Replay Attack** | `409 Conflict` (Nonce already processed) |
| 3 | **Expired Timestamp** | `401 Unauthorized` (Timestamp skew exceeded) |
| 4 | **Tampered Payload** | `401 Unauthorized` (Invalid HMAC signature) |
| 5 | **Tampered Security Header** | `401 Unauthorized` (Invalid HMAC signature) |
| 6 | **Missing Headers** | `400 Bad Request` (Required headers missing) |
| 7 | **Transaction Route Defense** | `200 OK` on first run, `409 Conflict` on replay |

---

## 🛠️ API Reference

### Required Request Headers

- `x-signature`: Hex string of calculated HMAC-SHA256 signature.
- `x-timestamp`: Millisecond Unix timestamp of request creation (`Date.now()`).
- `x-nonce`: Cryptographically unique 16+ byte hex string.

### Protected Endpoints

- `POST /api/action` - Standard action handler.
- `POST /api/transaction` - Protected financial transaction handler.
# Q2
