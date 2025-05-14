
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const { nanoid } = require('nanoid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const http = require('http');
const socketIo = require('socket.io');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const Razorpay = require('razorpay');
const crypto = require('crypto');

// Configuration Constants
const JWT_SECRET = process.env.JWT_SECRET || 'Tanishisagoodb$oy';
const port = process.env.PORT || 5000;
const mongoURI = process.env.MONGO_URI;
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Initialize Razorpay client
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Connect to MongoDB
const connectToMongo = async () => {
  try {
    await mongoose.connect(mongoURI);
    console.log('Successfully Connected to MongoDB Atlas');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
};
connectToMongo();

// SCHEMAS & MODELS
const { Schema } = mongoose;

const UserSchema = new Schema({
  uid: { type: String, default: () => nanoid(), unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  isPremium: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  premiumUsedFeatures: {
    ai: { type: Number, default: 0 },
    voice: { type: Number, default: 0 },
    export: { type: Number, default: 0 },
  },
  date: { type: Date, default: Date.now },
  lastNameChange: { type: Date, default: new Date(0) },
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const NotesSchema = new Schema({
  uid: { type: String, default: () => nanoid(), unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  tag: { type: String, default: 'General' },
  isPublic: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  isFlagged: { type: Boolean, default: false },
  flaggedDate: { type: Date },
  likes: { type: Number, default: 0 },
  comments: [
    {
      user: { type: Schema.Types.ObjectId, ref: 'User' },
      text: String,
      date: { type: Date, default: Date.now },
    },
  ],
  date: { type: Date, default: Date.now },
  likedBy: [{ type: Schema.Types.ObjectId, ref: 'User' }],
});
const Note = mongoose.models.Note || mongoose.model('Note', NotesSchema);

const LogSchema = new Schema({
  action: { type: String, required: true },
  user: { type: String }, // Can be user UID or 'admin'
  timestamp: { type: Date, default: Date.now },
  details: { type: String },
});
const Log = mongoose.models.Log || mongoose.model('Log', LogSchema);

const NotificationSchema = new Schema({
  id: { type: String, default: () => nanoid(), unique: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});
const Notification = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);

const SystemConfigSchema = new Schema({
  enableAI: { type: Boolean, default: false },
  maxNoteSize: { type: Number, default: 5 * 1024 * 1024 }, // 5MB
  allowedTags: [{ type: String }],
  trialLimits: {
    ai: { type: Number, default: 2 },
    voice: { type: Number, default: 2 },
    export: { type: Number, default: 2 },
  },
  language: { type: String, default: 'en' },
  timezone: { type: String, default: 'UTC' },
});
const SystemConfig = mongoose.models.SystemConfig || mongoose.model('SystemConfig', SystemConfigSchema);

const PaymentSchema = new Schema({
  paymentId: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['success', 'failed', 'pending'], default: 'pending' },
});
const Payment = mongoose.models.Payment || mongoose.model('Payment', PaymentSchema);

// Temporary storage for OTPs
const otpStore = new Map();
const resetStore = new Map();

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Function to generate OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
};

// Function to send OTP email
const sendOTPEmail = async (email, otp) => {
  const websiteLink = 'https://www.apninotebook.in';
  const logoUrl = 'https://i.imgur.com/khkAWrT.png';

  const textMessage = `Dear User,

Your OTP for ApniNoteBook is: ${otp}. It expires in 15 minutes.

If you did not request this, please ignore this email.

Best regards,
The ApniNoteBook Team`;

  const htmlTemplate = `
<html>
<head>
<style>
body { font-family: Arial, sans-serif; color: #333; }
.header { background-color: #f2f2f2; padding: 20px; text-align: center; }
.content { padding: 20px; }
.footer { background-color: #f2f2f2; padding: 10px; text-align: center; font-size: 12px; }
</style>
</head>
<body>
<div class="header">
<img src="${logoUrl}" alt="ApniNoteBook Logo" style="max-width: 150px;">
</div>
<div class="content">
<p>Dear User,</p>
<p>Your OTP for ApniNoteBook is: <strong>${otp}</strong>. It expires in 15 minutes.</p>
<p>If you did not request this, please ignore this email.</p>
<p>Best regards,<br>The ApniNoteBook Team</p>
</div>
<div class="footer">
<p>© 2023 ApniNoteBook. All rights reserved.</p>
<p><a href="${websiteLink}">${websiteLink}</a></p>
</div>
</body>
</html>
`;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for ApniNoteBook',
    text: textMessage,
    html: htmlTemplate,
  };

  await transporter.sendMail(mailOptions);
};

// MIDDLEWARE
const fetchUser = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ error: 'Please authenticate using a valid token' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data.user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Please authenticate using a valid token' });
  }
};

const adminAuthMiddleware = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ error: 'Access denied: No token provided' });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.user || !data.user.admin) {
      return res.status(403).json({ error: 'Access denied: Admins only' });
    }
    req.user = data.user;
    next();
  } catch (error) {
    console.error('JWT Verification Error:', error.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const checkPremium = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(401).json({ error: 'User not found' });

  const feature = req.feature;
  if (!user.isPremium && user.premiumUsedFeatures[feature] >= (SystemConfig.trialLimits?.[feature] || 2)) {
    return res.status(403).json({ message: `Free trial for ${feature} exhausted. Upgrade to premium.` });
  }
  next();
};

// INITIALIZE APP & SECURITY MIDDLEWARE
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? ['https://inotebook-react-new.netlify.app', 'https://apninotebook.in']
      : ['http://localhost:3000'],
  },
});

app.use(helmet());
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

const allowedOrigin = process.env.NODE_ENV === 'production'
  ? ['https://inotebook-react-new.netlify.app', 'https://apninotebook.in']
  : ['http://localhost:3000'];
app.use(cors({
  origin: allowedOrigin,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));

app.use(express.json());

// Ensure all responses are JSON
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'application/json');
  next();
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// SOCKET.IO INTEGRATION
io.on('connection', (socket) => {
  console.log('New client connected', socket.id);
  socket.on('noteUpdated', (data) => {
    io.emit('noteUpdated', data);
  });
  socket.on('disconnect', () => {
    console.log('Client disconnected', socket.id);
  });
});

// ROUTES

// AUTHENTICATION ROUTES
const authRouter = express.Router();

authRouter.post(
  '/signup-with-otp',
  [
    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must be at least 5 characters').isLength({ min: 5 }),
  ],
  async (req, res) => {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success, errors: errors.array() });
    try {
      let user = await User.findOne({ email: req.body.email });
      if (user) return res.status(400).json({ success, error: 'User with this email already exists' });

      const otp = generateOTP();
      const otpExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes

      otpStore.set(req.body.email, {
        otp,
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        expiration: otpExpiration,
      });

      await sendOTPEmail(req.body.email, otp);

      success = true;
      res.json({ success, message: 'OTP sent to your email.' });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ error: 'Internal Server Error', message: err.message });
    }
  }
);

authRouter.post('/verify-otp', async (req, res) => {
  const { email, otp, resetToken } = req.body;

  if (resetToken) {
    try {
      const resetData = resetStore.get(resetToken);
      if (!resetData) return res.status(400).json({ error: 'Invalid or expired reset token' });

      if (Date.now() > resetData.expiration) {
        resetStore.delete(resetToken);
        return res.status(400).json({ error: 'Reset token expired' });
      }

      if (resetData.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

      resetData.isVerified = true;
      resetStore.set(resetToken, resetData);

      res.json({ success: true });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  } else if (email) {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success, errors: errors.array() });

    try {
      const storedData = otpStore.get(email);
      if (!storedData) return res.status(400).json({ success, error: 'OTP not found or expired' });

      if (Date.now() > storedData.expiration) {
        otpStore.delete(email);
        return res.status(400).json({ success, error: 'OTP expired' });
      }

      if (storedData.otp !== otp) return res.status(400).json({ success, error: 'Invalid OTP' });

      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(storedData.password, salt);
      const user = new User({
        name: storedData.name,
        email: storedData.email,
        password: secPass,
      });
      await user.save();

      otpStore.delete(email);

      const data = { user: { id: user.id } };
      const authtoken = jwt.sign(data, JWT_SECRET);
      success = true;
      res.json({ success, authtoken, nanoId: user.uid });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ error: 'Internal Server Error', message: err.message });
    }
  } else {
    res.status(400).json({ error: 'Invalid request: provide either email or resetToken' });
  }
});

authRouter.post(
  '/reset-password',
  [
    body('newPassword', 'Password must be at least 5 characters').isLength({ min: 5 }),
    body('resetToken', 'Reset token is required').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { newPassword, resetToken } = req.body;

    try {
      const resetData = resetStore.get(resetToken);
      if (!resetData) return res.status(400).json({ error: 'Invalid or expired reset token' });

      if (Date.now() > resetData.expiration) {
        resetStore.delete(resetToken);
        return res.status(400).json({ error: 'Reset token expired' });
      }

      if (!resetData.isVerified) return res.status(400).json({ error: 'OTP not verified' });

      const user = await User.findById(resetData.userId);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(newPassword, salt);
      user.password = secPass;
      await user.save();

      resetStore.delete(resetToken);

      res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.post(
  '/forgot-password',
  [body('email', 'Enter a valid email').isEmail()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ error: 'User not found' });

      const resetToken = nanoid();
      const otp = generateOTP();
      const expiration = Date.now() + 15 * 60 * 1000; // 15 minutes

      resetStore.set(resetToken, {
        userId: user.id,
        otp,
        isVerified: false,
        expiration,
      });

      await sendOTPEmail(email, otp);

      res.json({ success: true, resetToken });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.post(
  '/login',
  [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists(),
  ],
  async (req, res) => {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    try {
      if (email === process.env.ADMIN_EMAIL) {
        if (password !== process.env.ADMIN_PASSWORD)
          return res.status(400).json({ success, error: 'Invalid admin credentials' });

        const adminData = { user: { id: 'admin', admin: true } };
        const authtoken = jwt.sign(adminData, JWT_SECRET);
        success = true;
        return res.json({ success, authtoken, admin: true });
      }

      let user = await User.findOne({ email });
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });

      const passwordCompare = await bcrypt.compare(password, user.password);
      if (!passwordCompare) return res.status(400).json({ success, error: 'Invalid credentials' });

      const data = { user: { id: user.id, admin: false, isPremium: user.isPremium } };
      const authtoken = jwt.sign(data, JWT_SECRET);

      success = true;

      res.json({
        success,
        authtoken,
        admin: false,
        nanoId: user.uid,
        isPremium: user.isPremium,
      });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.post('/google', async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: 'ID token is required' });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name } = payload;

    let user = await User.findOne({ email });

    if (user) {
      const data = { user: { id: user.id, admin: false, isPremium: user.isPremium } };
      const authtoken = jwt.sign(data, JWT_SECRET);
      return res.json({
        success: true,
        authtoken,
        nanoId: user.uid,
        isPremium: user.isPremium,
      });
    } else {
      user = new User({
        name,
        email,
      });
      await user.save();

      const data = { user: { id: user.id, admin: false, isPremium: user.isPremium } };
      const authtoken = jwt.sign(data, JWT_SECRET);
      return res.json({
        success: true,
        authtoken,
        nanoId: user.uid,
        isPremium: user.isPremium,
      });
    }
  } catch (error) {
    console.error('Google auth error:', error);
    return res.status(401).json({ error: 'Invalid Google token' });
  }
});

authRouter.post('/getuser', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

authRouter.post('/upgrade', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.isPremium) return res.status(400).json({ error: 'User is already premium' });
    user.isPremium = true;
    await user.save();

    await Log.create({
      action: 'User Upgraded',
      user: user.uid,
      details: `User ${user.email} upgraded to premium`,
    });

    res.json({ message: 'User upgraded to premium', user });
  } catch (error) {
    console.error('Upgrade error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

authRouter.post(
  '/change-name',
  fetchUser,
  [body('name', 'Name must be at least 3 characters').isLength({ min: 3 })],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const lastNameChange = user.lastNameChange || new Date(0);
      const daysSinceLastChange = (Date.now() - lastNameChange) / (1000 * 60 * 60 * 24);
      if (daysSinceLastChange < 14) {
        return res.status(400).json({ error: 'You can only change your name every 14 days' });
      }

      user.name = req.body.name;
      user.lastNameChange = Date.now();
      await user.save();

      await Log.create({
        action: 'Name Changed',
        user: user.uid,
        details: `User ${user.email} changed name to ${user.name}`,
      });

      res.json({ success: true, message: 'Name changed successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.post(
  '/change-email',
  fetchUser,
  [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const passwordCompare = await bcrypt.compare(req.body.password, user.password);
      if (!passwordCompare) return res.status(400).json({ error: 'Invalid password' });

      const otp = generateOTP();
      const otpExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes
      otpStore.set(req.body.email, {
        otp,
        expiration: otpExpiration,
        userId: user.id,
        newEmail: req.body.email,
      });

      await sendOTPEmail(req.body.email, otp);

      res.json({ success: true, message: 'OTP sent to new email for verification' });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.post('/verify-email-change', fetchUser, async (req, res) => {
  const { email, otp } = req.body;

  try {
    const storedData = otpStore.get(email);
    if (!storedData) return res.status(400).json({ error: 'OTP not found or expired' });

    if (Date.now() > storedData.expiration) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'OTP expired' });
    }

    if (storedData.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

    const user = await User.findById(storedData.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.email = storedData.newEmail;
    await user.save();

    await Log.create({
      action: 'Email Changed',
      user: user.uid,
      details: `User changed email to ${user.email}`,
    });

    otpStore.delete(email);

    res.json({ success: true, message: 'Email changed successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

authRouter.post(
  '/change-password',
  fetchUser,
  [
    body('currentPassword', 'Current password is required').exists(),
    body('newPassword', 'New password must be at least 5 characters').isLength({ min: 5 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const passwordCompare = await bcrypt.compare(req.body.currentPassword, user.password);
      if (!passwordCompare) return res.status(400).json({ error: 'Invalid current password' });

      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(req.body.newPassword, salt);
      user.password = secPass;
      await user.save();

      await Log.create({
        action: 'Password Changed',
        user: user.uid,
        details: `User ${user.email} changed password`,
      });

      res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

authRouter.delete('/delete-account', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    await Note.deleteMany({ user: req.user.id });
    await User.findByIdAndDelete(req.user.id);

    await Log.create({
      action: 'Account Deleted',
      user: user.uid,
      details: `User ${user.email} deleted their account`,
    });

    res.json({ success: true, message: 'Account deleted successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// NOTES ROUTES
const notesRouter = express.Router();

notesRouter.get('/fetchallnotes', fetchUser, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user.id, isDeleted: false });
    res.json(notes);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.get('/public', fetchUser, async (req, res) => {
  try {
    const publicNotes = await Note.find({ isPublic: true, isDeleted: false })
      .populate('user', 'name')
      .populate('comments.user', 'name');
    const notesWithLikeStatus = publicNotes.map(note => ({
      ...note.toObject(),
      likedByUser: note.likedBy.includes(req.user.id),
    }));
    res.json(notesWithLikeStatus);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
notesRouter.get('/public/:uid', async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid, isPublic: true, isDeleted: false })
      .populate('user', 'name')
      .populate('comments.user', 'name');
    if (!note) return res.status(404).json({ error: 'Public note not found' });
    res.json(note);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.post(
  '/addnote',
  fetchUser,
  [
    body('title', 'Enter a valid title').isLength({ min: 3 }),
    body('description', 'Description must be at least 5 characters').isLength({ min: 5 }),
  ],
  async (req, res) => {
    const { title, description, tag, isPublic } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    try {
      const systemConfig = await SystemConfig.findOne();
      if (tag && systemConfig?.allowedTags && !systemConfig.allowedTags.includes(tag)) {
        return res.status(400).json({ error: `Tag must be one of: ${systemConfig.allowedTags.join(', ')}` });
      }
      if (description.length > (systemConfig?.maxNoteSize || 5 * 1024 * 1024)) {
        return res.status(400).json({ error: 'Note size exceeds maximum limit' });
      }

      const note = new Note({
        title,
        description,
        tag,
        isPublic: isPublic || false,
        user: req.user.id,
      });
      const savedNote = await note.save();

      await Log.create({
        action: 'Note Created',
        user: req.user.id,
        details: `Note ${savedNote.uid} created by user ${req.user.id}`,
      });

      io.emit('noteAdded', savedNote);
      res.json(savedNote);
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

notesRouter.put('/updatenote/:uid', fetchUser, async (req, res) => {
  const { title, description, tag, isPublic } = req.body;
  const newNote = {};
  if (title) newNote.title = title;
  if (description) newNote.description = description;
  if (tag) newNote.tag = tag;
  if (typeof isPublic !== 'undefined') newNote.isPublic = isPublic;
  try {
    const systemConfig = await SystemConfig.findOne();
    if (tag && systemConfig?.allowedTags && !systemConfig.allowedTags.includes(tag)) {
      return res.status(400).json({ error: `Tag must be one of: ${systemConfig.allowedTags.join(', ')}` });
    }
    if (description && description.length > (systemConfig?.maxNoteSize || 5 * 1024 * 1024)) {
      return res.status(400).json({ error: 'Note size exceeds maximum limit' });
    }

    let note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: 'Not allowed' });
    note = await Note.findOneAndUpdate({ uid: req.params.uid }, { $set: newNote }, { new: true });

    await Log.create({
      action: 'Note Updated',
      user: req.user.id,
      details: `Note ${note.uid} updated by user ${req.user.id}`,
    });

    io.emit('noteUpdated', note);
    res.json({ note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.delete('/deletenote/:uid', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: 'Not allowed' });
    note.isDeleted = true;
    await note.save();

    await Log.create({
      action: 'Note Deleted',
      user: req.user.id,
      details: `Note ${note.uid} soft deleted by user ${req.user.id}`,
    });

    io.emit('noteDeleted', note);
    res.json({ success: 'Note has been soft deleted', note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.delete('/:noteUid/comment/:commentId', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.noteUid, isPublic: true });
    if (!note) return res.status(404).json({ error: 'Public note not found' });

    const comment = note.comments.id(req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    if (comment.user.toString() !== req.user.id) {
      return res.status(401).json({ error: 'Not allowed to delete this comment' });
    }

    note.comments.pull({ _id: req.params.commentId });
    await note.save();

    await Log.create({
      action: 'Comment Deleted',
      user: req.user.id,
      details: `Comment ${req.params.commentId} deleted from note ${note.uid} by user ${req.user.id}`,
    });

    io.emit('commentDeleted', { noteUid: note.uid, commentId: req.params.commentId });
    res.json({ success: 'Comment deleted', note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.post('/restore/:uid', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: 'Not allowed' });
    note.isDeleted = false;
    await note.save();

    await Log.create({
      action: 'Note Restored',
      user: req.user.id,
      details: `Note ${note.uid} restored by user ${req.user.id}`,
    });

    io.emit('noteRestored', note);
    res.json({ success: 'Note restored', note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.get('/export/:format/:uid', fetchUser, async (req, res) => {
  const { format, uid } = req.params;
  try {

    const note = await Note.findOne({ uid, user: req.user.id });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isPremium) {
      user.premiumUsedFeatures.export += 1;
      await user.save();
    }

    if (format === 'json') {
      res.json(note);
    } else if (format === 'txt') {
      res.setHeader('Content-Type', 'text/plain');
      res.send(`Title: ${note.title}\nTag: ${note.tag}\nDescription: ${note.description}`);
    } else {
      res.status(400).json({ error: 'Unsupported format' });
    }
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.post('/:uid/like', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid, isPublic: true });
    if (!note) return res.status(404).json({ error: 'Public note not found' });

    const userId = req.user.id;
    const index = note.likedBy.indexOf(userId);

    if (index === -1) {
      // User has not liked the note yet
      note.likedBy.push(userId);
      note.likes += 1;
    } else {
      // User has already liked the note, so unlike it
      note.likedBy.splice(index, 1);
      note.likes -= 1;
    }

    await note.save();

    await Log.create({
      action: index === -1 ? 'Note Liked' : 'Note Unliked',
      user: userId,
      details: `Note ${note.uid} ${index === -1 ? 'liked' : 'unliked'} by user ${userId}`,
    });

    io.emit('noteLiked', { uid: note.uid, likes: note.likes, likedByUser: index === -1 });
    res.json({ success: 'Note like status updated', note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

notesRouter.post('/:uid/comment', fetchUser, async (req, res) => {
  try {
    const { text } = req.body;
    const note = await Note.findOne({ uid: req.params.uid, isPublic: true });
    if (!note) return res.status(404).json({ error: 'Public note not found' });
    const newComment = { user: req.user.id, text, date: new Date() };
    note.comments.push(newComment);
    await note.save();

    const populatedComment = await Note.populate(newComment, { path: 'user', select: 'name' });

    await Log.create({
      action: 'Note Commented',
      user: req.user.id,
      details: `Comment added to note ${note.uid} by user ${req.user.id}`,
    });

    io.emit('noteCommented', { uid: note.uid, comment: populatedComment });
    res.json({ success: 'Comment added', comment: populatedComment });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// AI & VOICE INPUT ROUTES
const aiRouter = express.Router();
const setFeature = (featureName) => (req, res, next) => {
  req.feature = featureName;
  next();
};

aiRouter.post('/generate', fetchUser, setFeature('ai'), checkPremium, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isPremium) {
      user.premiumUsedFeatures.ai += 1;
      await user.save();
    }
    res.json({ message: 'AI-generated content (Not yet implemented)' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

aiRouter.post('/voice/transcribe', fetchUser, setFeature('voice'), checkPremium, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isPremium) {
      user.premiumUsedFeatures.voice += 1;
      await user.save();
    }
    res.json({ message: 'Voice transcription result (Not yet implemented)' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// RAZORPAY PAYMENT ROUTES
const paymentRouter = express.Router();

paymentRouter.post('/create-order', fetchUser, async (req, res) => {
  try {
    const options = {
      amount: 99900, // ₹999 in paise
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1,
    };
    const order = await razorpay.orders.create(options);
    res.json({
      orderId: order.id,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
    });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

paymentRouter.post('/verify', fetchUser, async (req, res) => {
  const { paymentId, orderId, signature } = req.body;

  if (!paymentId || !orderId || !signature) {
    return res.status(400).json({ error: 'Missing payment details' });
  }

  try {
    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');

    if (generatedSignature === signature) {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      if (user.isPremium) {
        return res.json({ success: true, message: 'User is already premium' });
      }
      user.isPremium = true;
      await user.save();

      await Payment.create({
        paymentId,
        user: req.user.id,
        amount: 999,
        status: 'success',
      });

      await Log.create({
        action: 'Payment Verified',
        user: user.uid,
        details: `Payment ${paymentId} verified for user ${user.email}`,
      });

      res.json({ success: true, message: 'Payment verified and user upgraded to premium' });
    } else {
      await Payment.create({
        paymentId,
        user: req.user.id,
        amount: 999,
        status: 'failed',
      });
      res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

paymentRouter.get('/invoice/:paymentId', fetchUser, async (req, res) => {
  try {
    const payment = await Payment.findOne({ paymentId: req.params.paymentId, user: req.user.id });
    if (!payment) return res.status(404).json({ error: 'Payment not found' });
    res.json({
      paymentId: payment.paymentId,
      amount: payment.amount,
      date: payment.date,
      status: payment.status,
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ANALYTICS & LOGGING ROUTES
const analyticsRouter = express.Router();

analyticsRouter.get('/user-activity', fetchUser, async (req, res) => {
  try {
    const logs = await Log.find({ user: req.user.id }).sort({ timestamp: -1 }).limit(50);
    res.json(logs);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// BACKUP & RESTORE ROUTES
const backupRouter = express.Router();

backupRouter.get('/export/all-notes', fetchUser, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user.id, isDeleted: false });
    const user = await User.findById(req.user.id);
    if (!user.isPremium) {
      user.premiumUsedFeatures.export += 1;
      await user.save();
    }
    res.json(notes);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ADMIN ROUTES
const adminRouter = express.Router();

adminRouter.get('/dashboard', adminAuthMiddleware, (req, res) => {
  res.json({ message: 'Welcome to the Admin Dashboard!' });
});

adminRouter.get('/overview', adminAuthMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    const totalNotes = await Note.countDocuments({});
    const premiumUsers = await User.countDocuments({ isPremium: true });
    const freeUsers = totalUsers - premiumUsers;
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const dailySignups = await User.countDocuments({ date: { $gte: oneDayAgo } });
    const dailyNotes = await Note.countDocuments({ date: { $gte: oneDayAgo } });
    res.json({ totalUsers, totalNotes, premiumUsers, freeUsers, dailySignups, dailyNotes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/users', adminAuthMiddleware, async (req, res) => {
  try {
    const users = await User.find({})
      .select('-password')
      .lean()
      .exec();
    const usersWithNotesCount = await Promise.all(
      users.map(async (user) => {
        const notesCount = await Note.countDocuments({ user: user._id });
        return { ...user, notesCount };
      })
    );
    res.json(usersWithNotesCount);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.put('/users/:uid', adminAuthMiddleware, async (req, res) => {
  const { isActive, isPremium, name, email } = req.body;
  try {
    const user = await User.findOne({ uid: req.params.uid });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (typeof isActive !== 'undefined') user.isActive = isActive;
    if (typeof isPremium !== 'undefined') user.isPremium = isPremium;
    if (name) user.name = name;
    if (email) user.email = email;

    await user.save();

    await Log.create({
      action: 'User Updated',
      user: 'admin',
      details: `User ${user.uid} updated: ${JSON.stringify(req.body)}`,
    });

    res.json({ success: true, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.delete('/users/:uid', adminAuthMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.params.uid });
    if (!user) return res.status(404).json({ error: 'User not found' });

    await Note.deleteMany({ user: user._id });
    await User.deleteOne({ uid: req.params.uid });

    await Log.create({
      action: 'User Deleted',
      user: 'admin',
      details: `User ${user.uid} deleted by admin`,
    });

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/notes', adminAuthMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({})
      .populate('user', 'email')
      .lean()
      .exec();
    res.json(notes.map(note => ({ ...note, user: note.user.email })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.put('/notes/:uid', adminAuthMiddleware, async (req, res) => {
  const { isDeleted, isFlagged, title, tag } = req.body;
  try {
    const note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: 'Note not found' });

    if (typeof isDeleted !== 'undefined') note.isDeleted = isDeleted;
    if (typeof isFlagged !== 'undefined') {
      note.isFlagged = isFlagged;
      note.flaggedDate = isFlagged ? new Date() : null;
    }
    if (title) note.title = title;
    if (tag) {
      const systemConfig = await SystemConfig.findOne();
      if (systemConfig?.allowedTags && !systemConfig.allowedTags.includes(tag)) {
        return res.status(400).json({ error: `Tag must be one of: ${systemConfig.allowedTags.join(', ')}` });
      }
      note.tag = tag;
    }

    await note.save();

    await Log.create({
      action: 'Note Updated',
      user: 'admin',
      details: `Note ${note.uid} updated: ${JSON.stringify(req.body)}`,
    });

    io.emit('noteUpdated', note);
    res.json({ success: true, note });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/moderation', adminAuthMiddleware, async (req, res) => {
  try {
    const flaggedNotes = await Note.find({ isFlagged: true })
      .populate('user', 'email')
      .lean()
      .exec();
    res.json(flaggedNotes.map(note => ({ ...note, user: note.user.email })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/logs', adminAuthMiddleware, async (req, res) => {
  try {
    const logs = await Log.find({})
      .sort({ timestamp: -1 })
      .limit(100)
      .lean()
      .exec();
    res.json(logs.map(log => ({ id: log._id, ...log })));
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/reports', adminAuthMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({});
    const totalNotes = await Note.countDocuments({});
    res.json({
      userExport: `Total Users: ${totalUsers}`,
      noteExport: `Total Notes: ${totalNotes}`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/premium', adminAuthMiddleware, async (req, res) => {
  try {
    const totalPremium = await User.countDocuments({ isPremium: true });
    const systemConfig = await SystemConfig.findOne();
    res.json({
      totalPremium,
      freeUsageRemaining: systemConfig?.trialLimits || {
        ai: 2,
        voice: 2,
        export: 2,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.put('/premium', adminAuthMiddleware, async (req, res) => {
  const { freeUsageRemaining } = req.body;
  try {
    let systemConfig = await SystemConfig.findOne();
    if (!systemConfig) {
      systemConfig = new SystemConfig({ trialLimits: freeUsageRemaining });
    } else {
      systemConfig.trialLimits = freeUsageRemaining;
    }
    await systemConfig.save();

    await Log.create({
      action: 'Premium Settings Updated',
      user: 'admin',
      details: `Premium trial limits updated: ${JSON.stringify(freeUsageRemaining)}`,
    });

    res.json({ success: true, systemConfig });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/notifications', adminAuthMiddleware, async (req, res) => {
  try {
    const notifications = await Notification.find({})
      .sort({ timestamp: -1 })
      .limit(50)
      .lean()
      .exec();
    res.json(notifications);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.delete('/notifications/:id', adminAuthMiddleware, async (req, res) => {
  try {
    const notification = await Notification.findOneAndDelete({ id: req.params.id });
    if (!notification) return res.status(404).json({ error: 'Notification not found' });

    await Log.create({
      action: 'Notification Dismissed',
      user: 'admin',
      details: `Notification ${req.params.id} dismissed`,
    });

    res.json({ success: true, message: 'Notification dismissed' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/system', adminAuthMiddleware, async (req, res) => {
  try {
    let systemConfig = await SystemConfig.findOne();
    if (!systemConfig) {
      systemConfig = new SystemConfig({});
      await systemConfig.save();
    }
    res.json(systemConfig);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.put('/system', adminAuthMiddleware, async (req, res) => {
  try {
    const { enableAI, maxNoteSize, allowedTags, trialLimits, language, timezone } = req.body;
    let systemConfig = await SystemConfig.findOne();
    if (!systemConfig) {
      systemConfig = new SystemConfig({});
    }

    if (typeof enableAI !== 'undefined') systemConfig.enableAI = enableAI;
    if (maxNoteSize) systemConfig.maxNoteSize = maxNoteSize;
    if (allowedTags) systemConfig.allowedTags = allowedTags;
    if (trialLimits) systemConfig.trialLimits = trialLimits;
    if (language) systemConfig.language = language;
    if (timezone) systemConfig.timezone = timezone;

    await systemConfig.save();

    await Log.create({
      action: 'System Config Updated',
      user: 'admin',
      details: `System configuration updated: ${JSON.stringify(req.body)}`,
    });

    res.json({ success: true, systemConfig });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/payment', adminAuthMiddleware, async (req, res) => {
  try {
    const payments = await Payment.find({})
      .populate('user', 'email')
      .sort({ date: -1 })
      .lean()
      .exec();
    const lastPayment = payments[0] || null;
    res.json({
      lastPaymentDate: lastPayment ? lastPayment.date : null,
      subscriptionStatus: payments.length > 0 ? 'Active' : 'Inactive',
      transactionHistory: payments.map(payment => ({
        id: payment.paymentId,
        amount: payment.amount,
        date: payment.date,
        status: payment.status,
      })),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.post('/payment/upgrade', adminAuthMiddleware, async (req, res) => {
  try {
    // Placeholder for admin-initiated upgrade
    res.json({ success: true, message: 'Upgrade request processed (Not implemented)' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.get('/security', adminAuthMiddleware, async (req, res) => {
  try {
    // Mock security roles (replace with a proper Role model if needed)
    const roles = [
      { role: 'Admin', permissions: ['read', 'write', 'delete', 'manage_users', 'manage_notes', 'manage_system'] },
      { role: 'User', permissions: ['read', 'create', 'update'] },
    ];
    res.json(roles);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.post('/security', adminAuthMiddleware, async (req, res) => {
  const { role, permissions } = req.body;
  try {
    // Mock implementation (replace with a proper Role model)
    await Log.create({
      action: 'Role Added',
      user: 'admin',
      details: `Role ${role} added with permissions: ${permissions.join(', ')}`,
    });
    res.json({ success: true, role: { role, permissions } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.put('/security/:role', adminAuthMiddleware, async (req, res) => {
  const { permissions } = req.body;
  try {
    // Mock implementation
    await Log.create({
      action: 'Role Updated',
      user: 'admin',
      details: `Role ${req.params.role} updated with permissions: ${permissions.join(', ')}`,
    });
    res.json({ success: true, role: { role: req.params.role, permissions } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

adminRouter.delete('/security/:role', adminAuthMiddleware, async (req, res) => {
  try {
    // Mock implementation
    await Log.create({
      action: 'Role Deleted',
      user: 'admin',
      details: `Role ${req.params.role} deleted`,
    });
    res.json({ success: true, message: 'Role deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// CONTACT ROUTE
app.post(
  '/send-email',
  [
    body('name', 'Name is required').notEmpty(),
    body('email', 'Enter a valid email').isEmail(),
    body('message', 'Message is required').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, message } = req.body;

    if (!process.env.SUPPORT_EMAIL) {
      console.error('SUPPORT_EMAIL is not defined in environment variables.');
      return res.status(500).json({ message: 'Server configuration error: SUPPORT_EMAIL not set' });
    }

    try {
      const supportMailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.SUPPORT_EMAIL,
        subject: `Contact Form Submission from ${name}`,
        text: `Name: ${name}\nEmail: ${email}\nMessage: ${message}`,
        replyTo: email,
      };

      await transporter.sendMail(supportMailOptions);

      const websiteLink = 'https://www.apninotebook.in';
      const logoUrl = 'https://i.imgur.com/khkAWrT.png';

      const textMessage = `Dear ${name},

Thank you for contacting ApniNoteBook. We have received your message and appreciate you reaching out to us. A member of our team will review your inquiry and get back to you as soon as possible.

If you have any urgent questions, feel free to reply to this email or visit our website at ${websiteLink}.

Best regards,
The ApniNoteBook Team`;

      const htmlTemplate = `
<html>
<head>
<style>
body { font-family: Arial, sans-serif; color: #333; }
.header { background-color: #f2f2f2; padding: 20px; text-align: center; }
.content { padding: 20px; }
.footer { background-color: #f2f2f2; padding: 10px; text-align: center; font-size: 12px; }
</style>
</head>
<body>
<div class="header">
<img src="${logoUrl}" alt="ApniNoteBook Logo" style="max-width: 150px;">
</div>
<div class="content">
<p>Dear ${name},</p>
<p>Thank you for contacting ApniNoteBook. We have received your message and appreciate you reaching out to us.</p>
<p>A member of our team will review your inquiry and get back to you as soon as possible.</p>
<p>If you have any urgent questions, feel free to reply to this email or visit our website at <a href="${websiteLink}">${websiteLink}</a>.</p>
<p>Best regards,<br>The ApniNoteBook Team</p>
</div>
<div class="footer">
<p>© 2023 ApniNoteBook. All rights reserved.</p>
</div>
</body>
</html>
`;

      const confirmationMailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "We've received your message",
        text: textMessage,
        html: htmlTemplate,
      };

      try {
        await transporter.sendMail(confirmationMailOptions);
      } catch (confirmationError) {
        console.error('Error sending confirmation email:', confirmationError);
      }

      res.status(200).json({ message: 'Email sent successfully' });
    } catch (supportError) {
      console.error('Error sending support email:', supportError);
      res.status(500).json({ message: 'Failed to send email' });
    }
  }
);

// MOUNT ROUTES
app.use('/api/auth', authRouter);
app.use('/api/notes', notesRouter);
app.use('/api/ai', aiRouter);
app.use('/api/payment', paymentRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/backup', backupRouter);
app.use('/api/admin', adminRouter);

// START SERVER WITH SOCKET.IO
server.listen(port, () => {
  console.log(`ApniNoteBook Backend listening on port ${port}`);
});