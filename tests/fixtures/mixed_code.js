// Real application code with secrets mixed in

const express = require('express');
const app = express();

// Configuration — some of these are secrets, some aren't
const config = {
  port: process.env.PORT || 3000,
  host: 'api.acmecorp.internal',
  apiKey: 'sk-proj-realkey123456789012345678901234567890abcdef',
  publicKey: 'pk_test_not_a_secret',  // public keys are not secrets
  webhookSecret: 'whsec_abcdef1234567890abcdef1234567890',

  // Database
  database: {
    host: 'db.acmecorp.internal',
    password: 'Pr0duct10n_DB_P4ss!',
    connectionString: 'mongodb://admin:M0ng0P4ss123@mongo.acmecorp.internal:27017/prod',
  },

  // OAuth
  auth: {
    clientId: 'my-app-client-id',  // not secret
    clientSecret: 'oauth_secret_abcdef123456789012345678901234',
    jwtSecret: 'super-secret-jwt-signing-key-do-not-share',
  },
};

// Headers with auth tokens
const headers = {
  'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123signature',
  'X-API-Key': 'key_live_abcdefghijklmnopqrstuvwxyz123456',
  'Content-Type': 'application/json',  // not a secret
};

// Inline secret in a curl-like command
// fetch('https://hooks.slack.com/services/T0123456/B0123456/xxxxxxxxxxxxxxxxxxx')

// Employee data
const team = [
  { name: 'Pablo Rodriguez', email: 'pablo@acmecorp.com', role: 'lead' },
  { name: 'Sarah Chen', email: 'sarah.chen@acmecorp.com', role: 'cto' },
];

// Error message that happens to contain an IP
console.error(`Connection failed to 10.42.1.100:5432 — retrying in 5s`);

// Completely normal code
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + item.price, 0);
}

module.exports = { config, calculateTotal };
