const crypto = require('crypto');
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}
