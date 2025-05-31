// File: app.js
// Main application entry point

require('dotenv').config();
require('express-async-errors');

const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// Import middleware and routes
const { errorHandler } = require('./middleware/errorHandler');
const { authMiddleware } = require('./middleware/auth');
const { dynamicModelLoader } = require('./middleware/dynamicModel');

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdn.jsdelivr.net"]
    }
  }
}));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : true,
  credentials: true
}));

// Rate limiting - more permissive for development
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || 200), // Increased to 200 requests per window
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for certain routes
  skip: (req) => {
    // Skip rate limiting for admin dashboard and static assets
    return req.path.startsWith('/admin/dashboard') || 
           req.path.startsWith('/api/auth/me') ||
           req.path.startsWith('/static') ||
           req.path.startsWith('/uploads') ||
           req.path.includes('.')  // Skip for files (css, js, images)
  }
});

// Apply rate limiting only to API routes and auth routes
app.use('/api/', limiter);
app.use('/login', limiter);
app.use('/register', limiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// View engine setup
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => {
  console.log('Connected to MongoDB');
  // Load dynamic models after DB connection
  return require('./services/dynamicModelService').loadExistingModels();
})
.then(() => {
  console.log('Dynamic models loaded');
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Load dynamic models middleware
app.use(dynamicModelLoader);

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', authMiddleware, require('./routes/users'));
app.use('/api/models', authMiddleware, require('./routes/models'));
app.use('/api/permissions', authMiddleware, require('./routes/permissions'));
app.use('/api/files', authMiddleware, require('./routes/files'));

// Web routes
app.use('/', require('./routes/web'));
app.use('/admin', authMiddleware, require('./routes/admin'));

// Dynamic routes for created models
app.use('/api/dynamic', authMiddleware, require('./routes/dynamic'));

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Page Not Found',
    message: 'The page you are looking for does not exist.',
    error: { status: 404 }
  });
});

// Error handling middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});