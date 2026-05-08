const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('Missing JWT_SECRET');
  }
  return secret;
}

function signToken(payload) {
  return jwt.sign(payload, getJwtSecret(), { expiresIn: '30d' });
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret());
}

function authOptional(req, _res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    req.user = null;
    return next();
  }
  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    return next();
  } catch {
    req.user = null;
    return next();
  }
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Missing Authorization bearer token.' });
  }
  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function createUserId() {
  return uuidv4();
}

module.exports = {
  authOptional,
  authRequired,
  signToken,
  hashPassword,
  verifyPassword,
  createUserId,
};

