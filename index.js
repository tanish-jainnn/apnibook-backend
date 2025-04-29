const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require("dotenv").config();
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
    console.log("Successfully Connected to MongoDB Atlas");
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
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
  premiumUsedFeatures: {
    ai: { type: Number, default: 0 },
    voice: { type: Number, default: 0 },
    export: { type: Number, default: 0 }
  },
  date: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

const NotesSchema = new Schema({
  uid: { type: String, default: () => nanoid(), unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  tag: { type: String, default: "General" },
  isPublic: { type: Boolean, default: false },
  isDeleted: { type: Boolean, default: false },
  likes: { type: Number, default: 0 },
  comments: [{
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    text: String,
    date: { type: Date, default: Date.now }
  }],
  date: { type: Date, default: Date.now }
});
const Note = mongoose.models.Note || mongoose.model('Note', NotesSchema);

// Temporary storage for OTPs
const otpStore = new Map();
const resetStore = new Map();  // Add this line

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
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
  const websiteLink = "https://www.apninotebook..in";
  const logoUrl = "https://i.imgur.com/khkAWrT.png";
  
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
  </div>
  </body>
  </html>
  `;
  
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP for ApniNoteBook",
    text: textMessage,
    html: htmlTemplate,
  };

  await transporter.sendMail(mailOptions);
};

// MIDDLEWARE
const fetchUser = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ error: "Please authenticate using a valid token" });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data.user;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Please authenticate using a valid token" });
  }
};

const adminAuthMiddleware = (req, res, next) => {
  const token = req.header('auth-token');
  if (!token) return res.status(401).json({ error: "Access denied: No token provided" });
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.user || !data.user.admin) {
      return res.status(403).json({ error: "Access denied: Admins only" });
    }
    req.user = data.user;
    next();
  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    return res.status(401).json({ error: "Invalid token" });
  }
};

const checkPremium = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(401).json({ error: "User not found" });

  const feature = req.feature;
  if (!user.isPremium && user.premiumUsedFeatures[feature] >= 2) {
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
    : ['http://localhost:3000']
  }
});

app.use(helmet());
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100 
});
app.use(limiter);

const allowedOrigin = process.env.NODE_ENV === 'production'
  ? ['https://inotebook-react-new.netlify.app', 'https://apninotebook.in']
  : ['http://localhost:3000'];
app.use(cors({
  origin: allowedOrigin,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

app.use(express.json());

// SOCKET.IO INTEGRATION
io.on('connection', (socket) => {
  console.log("New client connected", socket.id);
  socket.on('noteUpdated', (data) => {
    io.emit('noteUpdated', data);
  });
  socket.on('disconnect', () => {
    console.log("Client disconnected", socket.id);
  });
});

// ROUTES

// AUTHENTICATION ROUTES
const authRouter = express.Router();

authRouter.post('/signup-with-otp', [
  body('name', 'Enter a valid name').isLength({ min: 3 }),
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'Password must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
  let success = false;
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success, errors: errors.array() });
  try {
    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).json({ success, error: "User with this email already exists" });
    
    const otp = generateOTP();
    const otpExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes

    // Store OTP and user data temporarily
    otpStore.set(req.body.email, {
      otp,
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      expiration: otpExpiration,
    });

    // Send OTP email
    await sendOTPEmail(req.body.email, otp);

    success = true;
    res.json({ success, message: "OTP sent to your email." });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Internal Server Error", message: err.message });
  }
});

authRouter.post('/verify-otp', async (req, res) => {
  const { email, otp, resetToken } = req.body;
  
  if (resetToken) {
    // Forgot password OTP verification
    try {
      const resetData = resetStore.get(resetToken);
      if (!resetData) return res.status(400).json({ error: "Invalid or expired reset token" });
      
      if (Date.now() > resetData.expiration) {
        resetStore.delete(resetToken);
        return res.status(400).json({ error: "Reset token expired" });
      }
      
      if (resetData.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
      
      // OTP is valid, mark as verified
      resetData.isVerified = true;
      resetStore.set(resetToken, resetData);
      
      res.json({ success: true });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ error: "Internal Server Error" });
    }
  } else if (email) {
    // Signup OTP verification (original code)
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success, errors: errors.array() });
    
    try {
      const storedData = otpStore.get(email);
      if (!storedData) return res.status(400).json({ success, error: "OTP not found or expired" });
      
      if (Date.now() > storedData.expiration) {
        otpStore.delete(email);
        return res.status(400).json({ success, error: "OTP expired" });
      }
      
      if (storedData.otp !== otp) return res.status(400).json({ success, error: "Invalid OTP" });
      
      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(storedData.password, salt);
      const user = new User({
        name: storedData.name,
        email: storedData.email,
        password: secPass
      });
      await user.save();
      
      otpStore.delete(email);
      
      const data = { user: { id: user.id } };
      const authtoken = jwt.sign(data, JWT_SECRET);
      success = true;
      res.json({ success, authtoken, nanoId: user.uid });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ error: "Internal Server Error", message: err.message });
    }
  } else {
    res.status(400).json({ error: "Invalid request: provide either email or resetToken" });
  }
});

authRouter.post('/reset-password', [
  body('newPassword', 'Password must be at least 5 characters').isLength({ min: 5 }),
  body('resetToken', 'Reset token is required').notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { newPassword, resetToken } = req.body;
  
  try {
    const resetData = resetStore.get(resetToken);
    if (!resetData) return res.status(400).json({ error: "Invalid or expired reset token" });
    
    if (Date.now() > resetData.expiration) {
      resetStore.delete(resetToken);
      return res.status(400).json({ error: "Reset token expired" });
    }
    
    if (!resetData.isVerified) return res.status(400).json({ error: "OTP not verified" });
    
    const user = await User.findById(resetData.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(newPassword, salt);
    user.password = secPass;
    await user.save();
    
    resetStore.delete(resetToken);
    
    res.json({ success: true, message: "Password reset successfully" });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
authRouter.post('/forgot-password', [
  body('email', 'Enter a valid email').isEmail(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });
    
    const resetToken = nanoid();
    const otp = generateOTP();
    const expiration = Date.now() + 15 * 60 * 1000; // 15 minutes
    
    resetStore.set(resetToken, {
      userId: user.id,
      otp,
      isVerified: false,
      expiration,
    });
    
    // Send OTP email using existing function
    await sendOTPEmail(email, otp);
    
    res.json({ success: true, resetToken });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

authRouter.post('/login', [
  body('email', 'Enter a valid email').isEmail(),
  body('password', 'Password cannot be blank').exists(),
], async (req, res) => {
  let success = false;
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  const { email, password } = req.body;
  
  try {
    if (email === process.env.ADMIN_EMAIL) {
      if (password !== process.env.ADMIN_PASSWORD)
        return res.status(400).json({ success, error: "Invalid admin credentials" });
      
      const adminData = { user: { id: "admin", admin: true } };
      const authtoken = jwt.sign(adminData, JWT_SECRET);
      success = true;
      return res.json({ success, authtoken, admin: true });
    }
    
    let user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    
    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) return res.status(400).json({ success, error: "Invalid credentials" });
    
    const data = { user: { id: user.id, admin: false, isPremium: user.isPremium } };    
    const authtoken = jwt.sign(data, JWT_SECRET);

    success = true;
    
    res.json({
      success,
      authtoken,
      admin: false,
      nanoId: user.uid,
      isPremium: user.isPremium
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

authRouter.post('/google', async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: "ID token is required" });
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
        isPremium: user.isPremium
      });
    } else {
      user = new User({
        name,
        email
      });
      await user.save();

      const data = { user: { id: user.id, admin: false, isPremium: user.isPremium } };
      const authtoken = jwt.sign(data, JWT_SECRET);
      return res.json({
        success: true,
        authtoken,
        nanoId: user.uid,
        isPremium: user.isPremium
      });
    }
  } catch (error) {
    console.error("Google auth error:", error);
    return res.status(401).json({ error: "Invalid Google token" });
  }
});

authRouter.post('/getuser', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

authRouter.post('/upgrade', fetchUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    user.isPremium = true;
    await user.save();
    res.json({ message: "User upgraded to premium", user });
  } catch (error) {
    console.error("Upgrade error:", error);
    res.status(500).json({ error: "Internal Server Error" });
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
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.post('/addnote', fetchUser, [
  body('title', 'Enter a valid title').isLength({ min: 3 }),
  body('description', 'Description must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
  const { title, description, tag, isPublic } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const note = new Note({
      title,
      description,
      tag,
      isPublic: isPublic || false,
      user: req.user.id
    });
    const savedNote = await note.save();
    io.emit('noteAdded', savedNote);
    res.json(savedNote);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.put('/updatenote/:uid', fetchUser, async (req, res) => {
  const { title, description, tag, isPublic } = req.body;
  const newNote = {};
  if (title) newNote.title = title;
  if (description) newNote.description = description;
  if (tag) newNote.tag = tag;
  if (typeof isPublic !== 'undefined') newNote.isPublic = isPublic;
  try {
    let note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: "Not allowed" });
    note = await Note.findOneAndUpdate({ uid: req.params.uid }, { $set: newNote }, { new: true });
    io.emit('noteUpdated', note);
    res.json({ note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.delete('/deletenote/:uid', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: "Not allowed" });
    note.isDeleted = true;
    await note.save();
    io.emit('noteDeleted', note);
    res.json({ success: "Note has been soft deleted", note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.post('/restore/:uid', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid });
    if (!note) return res.status(404).json({ error: "Note not found" });
    if (note.user.toString() !== req.user.id)
      return res.status(401).json({ error: "Not allowed" });
    note.isDeleted = false;
    await note.save();
    io.emit('noteRestored', note);
    res.json({ success: "Note restored", note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.get('/export/:format/:uid', fetchUser, async (req, res) => {
  const { format, uid } = req.params;
  res.json({ message: `Exporting note ${uid} as ${format}. (Not yet implemented)` });
});

notesRouter.post('/:uid/like', fetchUser, async (req, res) => {
  try {
    const note = await Note.findOne({ uid: req.params.uid, isPublic: true });
    if (!note) return res.status(404).json({ error: "Public note not found" });
    note.likes += 1;
    await note.save();
    io.emit('noteLiked', { uid: note.uid, likes: note.likes });
    res.json({ success: "Note liked", note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

notesRouter.post('/:uid/comment', fetchUser, async (req, res) => {
  try {
    const { text } = req.body;
    const note = await Note.findOne({ uid: req.params.uid, isPublic: true });
    if (!note) return res.status(404).json({ error: "Public note not found" });
    note.comments.push({ user: req.user.id, text });
    await note.save();
    io.emit('noteCommented', { uid: note.uid, comment: text });
    res.json({ success: "Comment added", note });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// AI & VOICE INPUT ROUTES
const aiRouter = express.Router();
const setFeature = (featureName) => (req, res, next) => {
  req.feature = featureName;
  next();
};

aiRouter.post('/generate', fetchUser, setFeature('ai'), checkPremium, async (req, res) => {
  res.json({ message: "AI-generated content (Not yet implemented)" });
});

aiRouter.post('/voice/transcribe', fetchUser, setFeature('voice'), checkPremium, async (req, res) => {
  res.json({ message: "Voice transcription result (Not yet implemented)" });
});

// RAZORPAY PAYMENT ROUTES
const paymentRouter = express.Router();

paymentRouter.post('/create-order', fetchUser, async (req, res) => {
  try {
    const options = {
      amount: 99900, // ₹999 in paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1,
    };
    const order = await razorpay.orders.create(options);
    res.json({
      orderId: order.id,
      razorpayKey: process.env.RAZORPAY_KEY_ID,
    });
  } catch (error) {
    console.error("Error creating Razorpay order:", error);
    res.status(500).json({ error: "Failed to create order" });
  }
});
paymentRouter.post('/verify', fetchUser, async (req, res) => {
  const { paymentId, orderId, signature } = req.body;
  
  if (!paymentId || !orderId || !signature) {
    return res.status(400).json({ error: "Missing payment details" });
  }
  
  try {
    const generatedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');
    
    if (generatedSignature === signature) {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      if (user.isPremium) {
        return res.json({ success: true, message: "User is already premium" });
      }
      user.isPremium = true;
      await user.save();
      res.json({ success: true, message: "Payment verified and user upgraded to premium" });
    } else {
      res.status(400).json({ error: "Invalid signature" });
    }
  } catch (error) {
    console.error("Error verifying payment:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

paymentRouter.get('/invoice/:paymentId', fetchUser, async (req, res) => {
  res.json({ message: "Invoice generated (Not yet implemented)" });
});

// ANALYTICS & LOGGING ROUTES
const analyticsRouter = express.Router();

analyticsRouter.get('/user-activity', fetchUser, async (req, res) => {
  res.json({ message: "User activity analytics (Not yet implemented)" });
});

// BACKUP & RESTORE ROUTES
const backupRouter = express.Router();

backupRouter.get('/export/all-notes', fetchUser, async (req, res) => {
  res.json({ message: "All notes exported as ZIP (Not yet implemented)" });
});

// ADMIN ROUTES
const adminRouter = express.Router();

adminRouter.get('/dashboard', adminAuthMiddleware, (req, res) => {
  res.json({ message: "Welcome to the Admin Dashboard!" });
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
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get('/users', adminAuthMiddleware, async (req, res) => {
  try {
    const users = await User.find({}).select("-password");
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get('/notes', adminAuthMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({});
    res.json(notes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get('/moderation', adminAuthMiddleware, async (req, res) => {
  res.json([]);
});

adminRouter.get('/logs', adminAuthMiddleware, async (req, res) => {
  res.json([]);
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
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get('/premium', adminAuthMiddleware, async (req, res) => {
  try {
    const totalPremium = await User.countDocuments({ isPremium: true });
    const trialLimits = {
      ai: Number(process.env.TRIAL_LIMIT_AI) || 2,
      voice: Number(process.env.TRIAL_LIMIT_VOICE) || 2,
      export: Number(process.env.TRIAL_LIMIT_EXPORT) || 2,
    };
    res.json({ totalPremium, freeUsageRemaining: trialLimits });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

adminRouter.get('/notifications', adminAuthMiddleware, async (req, res) => {
  res.json([]);
});

adminRouter.get('/system', adminAuthMiddleware, async (req, res) => {
  res.json({
    enableAI: process.env.ENABLE_AI === 'true',
    maxNoteSize: process.env.MAX_NOTE_SIZE || "5MB",
    allowedTags: process.env.ALLOWED_TAGS ? process.env.ALLOWED_TAGS.split(",") : ["General", "Work", "Personal"],
    trialLimits: {
      ai: Number(process.env.TRIAL_LIMIT_AI) || 2,
      voice: Number(process.env.TRIAL_LIMIT_VOICE) || 2,
      export: Number(process.env.TRIAL_LIMIT_EXPORT) || 2,
    },
    language: process.env.LANGUAGE || "en",
    timezone: process.env.TIMEZONE || "UTC"
  });
});

adminRouter.get('/payment', adminAuthMiddleware, async (req, res) => {
  res.json({
    lastPaymentDate: null,
    subscriptionStatus: "Not implemented",
    transactionHistory: []
  });
});

adminRouter.get('/security', adminAuthMiddleware, async (req, res) => {
  res.json([
    { role: "Admin", permissions: ["read", "write", "delete"] },
    { role: "User", permissions: ["read", "create", "update"] }
  ]);
});

// CONTACT ROUTE
app.post(
  "/send-email",
  [
    body("name", "Name is required").notEmpty(),
    body("email", "Enter a valid email").isEmail(),
    body("message", "Message is required").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, message } = req.body;

    if (!process.env.SUPPORT_EMAIL) {
      console.error("SUPPORT_EMAIL is not defined in environment variables.");
      return res.status(500).json({ message: "Server configuration error: SUPPORT_EMAIL not set" });
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

      const websiteLink = "https://www.apninotebook.in";
      const logoUrl = "https://i.imgur.com/khkAWrT.png";
      
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
        console.error("Error sending confirmation email:", confirmationError);
      }

      res.status(200).json({ message: "Email sent successfully" });
    } catch (supportError) {
      console.error("Error sending support email:", supportError);
      res.status(500).json({ message: "Failed to send email" });
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