'use strict';
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || '';
const COOKIE_NAME = 'bms_session';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const resourceNames = ['customers', 'employees', 'products', 'sales', 'invoices', 'expenses'];
const labels = {
  customers: 'Customers', employees: 'Employees', products: 'Inventory',
  sales: 'Sales', invoices: 'Invoices', expenses: 'Expenses'
};
let client;
let db;

if (process.env.NODE_ENV === 'production' && JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters in production.');
}
if (!process.env.MONGODB_URI || !process.env.MONGODB_DB) {
  throw new Error('Set MONGODB_URI and MONGODB_DB in your .env file.');
}
if (!JWT_SECRET || JWT_SECRET.startsWith('CHANGE_ME')) {
  throw new Error('Set a unique JWT_SECRET in your .env file before starting the server.');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait and try again.' }
});

function cleanText(value, max = 160) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function toPublicUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email, role: user.role };
}
function setSession(res, user) {
  const token = jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '8h', issuer: 'business-management-system' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000, path: '/'
  });
}
function clearSession(res) {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/' });
}
async function requireAuth(req, res, next) {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'business-management-system' });
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(payload.sub), active: true },
      { projection: { passwordHash: 0 } }
    );
    if (!user) {
      clearSession(res);
      return res.status(401).json({ error: 'Your session is no longer valid. Please sign in again.' });
    }
    req.user = user;
    next();
  } catch {
    clearSession(res);
    res.status(401).json({ error: 'Your session is invalid or expired. Please sign in again.' });
  }
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Administrator permission is required.' });
  next();
}
function safeRecord(body, collection) {
  const allowed = {
    customers: ['name', 'email', 'phone', 'company', 'address', 'notes'],
    employees: ['name', 'email', 'phone', 'position', 'department', 'status'],
    products: ['name', 'sku', 'category', 'quantity', 'unitPrice', 'reorderLevel'],
    sales: ['reference', 'customerName', 'amount', 'paymentMethod', 'status', 'notes'],
    invoices: ['invoiceNumber', 'customerName', 'customerEmail', 'amount', 'dueDate', 'status', 'notes'],
    expenses: ['description', 'category', 'amount', 'date', 'paymentMethod', 'notes']
  }[collection];
  const out = {};
  for (const key of allowed) {
    const value = body[key];
    if (['quantity', 'unitPrice', 'reorderLevel', 'amount'].includes(key)) {
      if (value !== undefined && value !== '' && Number.isFinite(Number(value)) && Number(value) >= 0) out[key] = Number(value);
    } else if (value !== undefined) {
      out[key] = cleanText(value, key === 'notes' || key === 'address' ? 2000 : 180);
    }
  }
  if (out.name !== undefined && !out.name) throw new Error('Name is required.');
  if (out.description !== undefined && !out.description) throw new Error('Description is required.');
  if (out.amount !== undefined && !Number.isFinite(out.amount)) throw new Error('Amount must be a valid non-negative number.');
  if (out.email && !validEmail(out.email)) throw new Error('Enter a valid email address.');
  if (out.customerEmail && !validEmail(out.customerEmail)) throw new Error('Enter a valid customer email address.');
  if (collection === 'products' && out.quantity === undefined && body.quantity !== undefined) throw new Error('Quantity must be a non-negative number.');
  if (collection === 'invoices' && out.status && !['pending', 'paid', 'overdue', 'cancelled'].includes(out.status)) throw new Error('Invalid invoice status.');
  if (collection === 'sales' && out.status && !['completed', 'pending', 'refunded'].includes(out.status)) throw new Error('Invalid sale status.');
  if (collection === 'employees' && out.status && !['active', 'inactive', 'on leave'].includes(out.status.toLowerCase())) throw new Error('Invalid employee status.');
  return out;
}
function serialize(doc) {
  if (!doc) return doc;
  const { _id, ...rest } = doc;
  return { id: _id.toString(), ...rest };
}
function validId(id) {
  return typeof id === 'string' && ObjectId.isValid(id) && new ObjectId(id).toString() === id;
}

app.get('/api/health', async (req, res) => {
  try {
    await db.command({ ping: 1 });
    res.json({ status: 'ok', database: 'connected' });
  } catch {
    res.status(503).json({ status: 'error', database: 'disconnected' });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const email = cleanText(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!validEmail(email) || !password || password.length > 200) {
    return res.status(400).json({ error: 'Enter a valid email and password.' });
  }
  const user = await db.collection('users').findOne({ email, active: true });
  const matches = user ? await bcrypt.compare(password, user.passwordHash) : false;
  if (!matches) return res.status(401).json({ error: 'Email or password is incorrect.' });
  setSession(res, user);
  res.json({ user: toPublicUser(user) });
});

app.post('/api/auth/logout', (req, res) => {
  clearSession(res);
  res.status(204).end();
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: toPublicUser(req.user) }));

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
  const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
  const fullUser = await db.collection('users').findOne({ _id: req.user._id });
  if (!fullUser || !(await bcrypt.compare(currentPassword, fullUser.passwordHash))) {
    return res.status(400).json({ error: 'Current password is incorrect.' });
  }
  if (newPassword.length < 12 || newPassword.length > 200) {
    return res.status(400).json({ error: 'New password must be at least 12 characters.' });
  }
  await db.collection('users').updateOne({ _id: req.user._id }, { $set: { passwordHash: await bcrypt.hash(newPassword, 12), updatedAt: new Date() } });
  clearSession(res);
  res.json({ message: 'Password changed. Please sign in again.' });
});

app.get('/api/dashboard', requireAuth, async (req, res) => {
  const count = name => db.collection(name).countDocuments();
  const [customers, employees, products, salesCount, invoices, expenses, salesTotals, invoiceTotals, expenseTotals, lowStock, recentInvoices, recentSales] = await Promise.all([
    count('customers'), count('employees'), count('products'), count('sales'), count('invoices'), count('expenses'),
    db.collection('sales').aggregate([{ $match: { status: { $ne: 'refunded' } } }, { $group: { _id: null, total: { $sum: '$amount' } } }]).toArray(),
    db.collection('invoices').aggregate([{ $match: { status: { $ne: 'cancelled' } } }, { $group: { _id: null, total: { $sum: '$amount' }, outstanding: { $sum: { $cond: [{ $in: ['$status', ['pending', 'overdue']] }, '$amount', 0] } } } }]).toArray(),
    db.collection('expenses').aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]).toArray(),
    db.collection('products').find({ $expr: { $lte: ['$quantity', { $ifNull: ['$reorderLevel', 5] }] } }).sort({ quantity: 1 }).limit(8).toArray(),
    db.collection('invoices').find().sort({ createdAt: -1 }).limit(5).toArray(),
    db.collection('sales').find().sort({ createdAt: -1 }).limit(5).toArray()
  ]);
  res.json({
    metrics: { customers, employees, products, salesCount, invoices, expenses,
      salesRevenue: salesTotals[0]?.total || 0, invoiced: invoiceTotals[0]?.total || 0,
      outstanding: invoiceTotals[0]?.outstanding || 0, expensesTotal: expenseTotals[0]?.total || 0 },
    lowStock: lowStock.map(serialize), recentInvoices: recentInvoices.map(serialize), recentSales: recentSales.map(serialize)
  });
});

app.get('/api/:resource', requireAuth, async (req, res, next) => {
  const name = req.params.resource;
  if (!resourceNames.includes(name)) return next();
  const page = Math.max(1, Math.min(100000, Number.parseInt(req.query.page, 10) || 1));
  const limit = Math.max(1, Math.min(100, Number.parseInt(req.query.limit, 10) || 100));
  const q = cleanText(req.query.q, 100);
  const filter = q ? { $or: [{ name: { $regex: escapeRegex(q), $options: 'i' } }, { email: { $regex: escapeRegex(q), $options: 'i' } }, { invoiceNumber: { $regex: escapeRegex(q), $options: 'i' } }, { sku: { $regex: escapeRegex(q), $options: 'i' } }, { customerName: { $regex: escapeRegex(q), $options: 'i' } }, { description: { $regex: escapeRegex(q), $options: 'i' } }, { reference: { $regex: escapeRegex(q), $options: 'i' } }] } : {};
  const [items, total] = await Promise.all([
    db.collection(name).find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).toArray(),
    db.collection(name).countDocuments(filter)
  ]);
  res.json({ items: items.map(serialize), total, page, limit });
});

app.post('/api/:resource', requireAuth, async (req, res, next) => {
  const name = req.params.resource;
  if (!resourceNames.includes(name)) return next();
  try {
    const record = safeRecord(req.body || {}, name);
    if (name === 'products' && (!record.name || !record.sku)) return res.status(400).json({ error: 'Product name and SKU are required.' });
    if (name === 'invoices' && (!record.invoiceNumber || !record.customerName || record.amount === undefined)) return res.status(400).json({ error: 'Invoice number, customer name, and amount are required.' });
    if (name === 'customers' && !record.name) return res.status(400).json({ error: 'Customer name is required.' });
    if (name === 'employees' && !record.name) return res.status(400).json({ error: 'Employee name is required.' });
    if (name === 'sales' && record.amount === undefined) return res.status(400).json({ error: 'Sale amount is required.' });
    if (name === 'expenses' && (!record.description || record.amount === undefined)) return res.status(400).json({ error: 'Expense description and amount are required.' });
    const now = new Date();
    record.createdAt = now;
    record.updatedAt = now;
    record.createdBy = req.user._id;
    const result = await db.collection(name).insertOne(record);
    await db.collection('auditLogs').insertOne({ actorId: req.user._id, action: 'create', resource: name, recordId: result.insertedId, at: now });
    res.status(201).json({ item: serialize({ _id: result.insertedId, ...record }) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'A record with that unique value already exists.' });
    if (error.message && !error.name?.includes('Mongo')) return res.status(400).json({ error: error.message });
    next(error);
  }
});

app.patch('/api/:resource/:id', requireAuth, async (req, res, next) => {
  const name = req.params.resource;
  if (!resourceNames.includes(name)) return next();
  if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid record ID.' });
  try {
    const patch = safeRecord(req.body || {}, name);
    delete patch.createdAt; delete patch.createdBy;
    if (!Object.keys(patch).length) return res.status(400).json({ error: 'No valid fields supplied.' });
    patch.updatedAt = new Date();
    const result = await db.collection(name).findOneAndUpdate(
      { _id: new ObjectId(req.params.id) }, { $set: patch }, { returnDocument: 'after' }
    );
    const updated = result && (result.value || result);
    if (!updated || !updated._id) return res.status(404).json({ error: 'Record not found.' });
    await db.collection('auditLogs').insertOne({ actorId: req.user._id, action: 'update', resource: name, recordId: updated._id, at: new Date() });
    res.json({ item: serialize(updated) });
  } catch (error) {
    if (error.message && !error.name?.includes('Mongo')) return res.status(400).json({ error: error.message });
    next(error);
  }
});

app.delete('/api/:resource/:id', requireAuth, requireAdmin, async (req, res, next) => {
  const name = req.params.resource;
  if (!resourceNames.includes(name)) return next();
  if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid record ID.' });
  const id = new ObjectId(req.params.id);
  const result = await db.collection(name).deleteOne({ _id: id });
  if (!result.deletedCount) return res.status(404).json({ error: 'Record not found.' });
  await db.collection('auditLogs').insertOne({ actorId: req.user._id, action: 'delete', resource: name, recordId: id, at: new Date() });
  res.status(204).end();
});

app.get('/api/reports/summary', requireAuth, async (req, res) => {
  const [salesByMonth, expensesByMonth, invoicesByStatus] = await Promise.all([
    db.collection('sales').aggregate([{ $match: { status: { $ne: 'refunded' } } }, { $group: { _id: { $dateToString: { format: '%Y-%m', date: '$createdAt' } }, total: { $sum: '$amount' }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }, { $limit: 12 }]).toArray(),
    db.collection('expenses').aggregate([{ $group: { _id: { $dateToString: { format: '%Y-%m', date: '$createdAt' } }, total: { $sum: '$amount' } } }, { $sort: { _id: 1 } }, { $limit: 12 }]).toArray(),
    db.collection('invoices').aggregate([{ $group: { _id: '$status', count: { $sum: 1 }, total: { $sum: '$amount' } } }]).toArray()
  ]);
  res.json({ salesByMonth, expensesByMonth, invoicesByStatus });
});

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await db.collection('users').find({}, { projection: { passwordHash: 0 } }).sort({ createdAt: -1 }).toArray();
  res.json({ items: users.map(toPublicUser) });
});
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const name = cleanText(req.body?.name, 120);
  const email = cleanText(req.body?.email, 254).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const role = req.body?.role === 'admin' ? 'admin' : 'staff';
  if (!name || !validEmail(email) || password.length < 12 || password.length > 200) {
    return res.status(400).json({ error: 'Name, valid email, and a password of at least 12 characters are required.' });
  }
  try {
    const user = { name, email, role, active: true, passwordHash: await bcrypt.hash(password, 12), createdAt: new Date() };
    const result = await db.collection('users').insertOne(user);
    res.status(201).json({ user: toPublicUser({ ...user, _id: result.insertedId }) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'A user with that email already exists.' });
    throw error;
  }
});
app.patch('/api/users/:id/active', requireAuth, requireAdmin, async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid user ID.' });
  if (req.params.id === req.user._id.toString() && req.body?.active === false) return res.status(400).json({ error: 'You cannot deactivate your own account.' });
  const active = req.body?.active === true;
  const result = await db.collection('users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { active, updatedAt: new Date() } });
  if (!result.matchedCount) return res.status(404).json({ error: 'User not found.' });
  res.json({ message: 'User status updated.' });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((error, req, res, next) => {
  console.error(`[${new Date().toISOString()}]`, error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});
function escapeRegex(text) { return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

async function start() {
  client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  db = client.db(process.env.MONGODB_DB);
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  for (const collection of resourceNames) {
    if (collection === 'products') await db.collection(collection).createIndex({ sku: 1 }, { unique: true, sparse: true });
    if (collection === 'invoices') await db.collection(collection).createIndex({ invoiceNumber: 1 }, { unique: true, sparse: true });
  }
  const users = db.collection('users');
  if (await users.countDocuments() === 0) {
    const email = cleanText(process.env.ADMIN_EMAIL, 254).toLowerCase();
    const password = process.env.ADMIN_PASSWORD || '';
    const name = cleanText(process.env.ADMIN_NAME || 'System Administrator', 120);
    if (!validEmail(email) || password.length < 12 || password.startsWith('CHANGE_ME')) {
      throw new Error('For first startup, set ADMIN_EMAIL and a unique ADMIN_PASSWORD of at least 12 characters in .env.');
    }
    await users.insertOne({ name, email, role: 'admin', active: true, passwordHash: await bcrypt.hash(password, 12), createdAt: new Date() });
    console.log(`Initial administrator created: ${email}`);
  }
  app.listen(PORT, () => console.log(`Business Management System running at http://localhost:${PORT}`));
}
start().catch(error => {
  console.error('Startup failed:', error.message);
  process.exit(1);
});
process.on('SIGINT', async () => { if (client) await client.close(); process.exit(0); });
process.on('SIGTERM', async () => { if (client) await client.close(); process.exit(0); });
