const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();

// Security & Middleware
app.use(helmet());
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

const otpLimiter = rateLimit({ windowMs: 60 * 1000, max: 3 });

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// Schemas
const employeeSchema = new mongoose.Schema({
  empId: { type: String, unique: true },
  name: String,
  email: { type: String, unique: true, required: true },
  phone: String,
  dept: String,
  role: String,
  avatar: { type: String, default: '👤' },
  status: { type: String, default: 'Active' },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 300 }
});

const leaveSchema = new mongoose.Schema({
  empId: String,
  empName: String,
  type: String,
  from: Date,
  to: Date,
  days: Number,
  reason: String,
  status: { type: String, default: 'Pending' },
  appliedOn: { type: Date, default: Date.now }
});

const policySchema = new mongoose.Schema({
  name: String,
  category: String,
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const Employee = mongoose.model('Employee', employeeSchema);
const OTP = mongoose.model('OTP', otpSchema);
const Leave = mongoose.model('Leave', leaveSchema);
const Policy = mongoose.model('Policy', policySchema);

// Email Setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'bgus-secret');
    const employee = await Employee.findById(decoded.id);
    if (!employee) return res.status(401).json({ error: 'Invalid token' });
    req.user = employee;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
};

// AUTH ROUTES
app.post('/api/auth/request-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const employee = await Employee.findOne({ email: email.toLowerCase() });
    if (!employee) return res.status(404).json({ error: 'Email not registered' });

    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase() });
    await new OTP({ email: email.toLowerCase(), otp }).save();

    await transporter.sendMail({
      from: `"BGUS HR Portal" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '🔐 Your Login OTP - BGUS HR Portal',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;">
          <div style="background:linear-gradient(135deg,#059669,#047857);padding:20px;border-radius:10px 10px 0 0;">
            <h1 style="color:white;margin:0;">🏢 BGUS HR Portal</h1>
          </div>
          <div style="background:#f8f9fa;padding:30px;border-radius:0 0 10px 10px;">
            <p>Hello <strong>${employee.name}</strong>,</p>
            <p>Your OTP is:</p>
            <div style="background:#1e293b;color:#10b981;font-size:32px;font-weight:bold;text-align:center;padding:20px;border-radius:10px;letter-spacing:8px;">
              ${otp}
            </div>
            <p style="color:#666;font-size:14px;margin-top:20px;">⏰ Valid for 5 minutes only.</p>
          </div>
        </div>
      `
    });

    res.json({ success: true, message: 'OTP sent!' });
  } catch (error) {
    console.error('OTP Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    const otpRecord = await OTP.findOne({ email: email.toLowerCase(), otp });
    if (!otpRecord) return res.status(400).json({ error: 'Invalid or expired OTP' });

    const employee = await Employee.findOne({ email: email.toLowerCase() });
    if (!employee) return res.status(404).json({ error: 'Employee not found' });

    await OTP.deleteMany({ email: email.toLowerCase() });

    const token = jwt.sign(
      { id: employee._id, email: employee.email, isAdmin: employee.isAdmin },
      process.env.JWT_SECRET || 'bgus-secret',
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: employee._id,
        empId: employee.empId,
        name: employee.name,
        email: employee.email,
        dept: employee.dept,
        role: employee.role,
        avatar: employee.avatar,
        isAdmin: employee.isAdmin
      }
    });
  } catch (error) {
    console.error('Verify Error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// EMPLOYEE ROUTES
app.get('/api/employees', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const employees = await Employee.find({ isAdmin: false });
    res.json(employees);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch' });
  }
});

app.post('/api/employees', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const count = await Employee.countDocuments();
    const empId = `BGUS${String(count + 1).padStart(4, '0')}`;
    const employee = new Employee({ ...req.body, empId, email: req.body.email.toLowerCase() });
    await employee.save();
    res.json({ success: true, employee });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add employee' });
  }
});

// LEAVE ROUTES
app.get('/api/leaves', authMiddleware, async (req, res) => {
  try {
    const query = req.user.isAdmin ? {} : { empId: req.user.empId };
    const leaves = await Leave.find(query).sort({ appliedOn: -1 });
    res.json(leaves);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch' });
  }
});

app.post('/api/leaves', authMiddleware, async (req, res) => {
  try {
    const leave = new Leave({ ...req.body, empId: req.user.empId, empName: req.user.name });
    await leave.save();
    res.json({ success: true, leave });
  } catch (error) {
    res.status(500).json({ error: 'Failed to apply' });
  }
});

app.put('/api/leaves/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const leave = await Leave.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ success: true, leave });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update' });
  }
});

// POLICY ROUTES
app.get('/api/policies', authMiddleware, async (req, res) => {
  try {
    const policies = await Policy.find().sort({ createdAt: -1 });
    res.json(policies);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch' });
  }
});

app.post('/api/policies', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const policy = new Policy(req.body);
    await policy.save();
    res.json({ success: true, policy });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create' });
  }
});

// Health Check
app.get('/', (req, res) => {
  res.json({ status: 'BGUS HR API Running', time: new Date() });
});

// Create Admin on Startup
async function seedAdmin() {
  const adminExists = await Employee.findOne({ isAdmin: true });
  if (!adminExists && process.env.ADMIN_EMAIL) {
    await new Employee({
      empId: 'BGUS_ADMIN',
      name: 'HR Admin',
      email: process.env.ADMIN_EMAIL.toLowerCase(),
      role: 'Super Admin',
      dept: 'HR',
      avatar: '👨‍💼',
      isAdmin: true
    }).save();
    console.log('✅ Admin created:', process.env.ADMIN_EMAIL);
  }
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  await seedAdmin();
});
