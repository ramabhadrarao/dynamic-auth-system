// File: routes/web.js
// Web routes for rendering pages

const express = require('express');
const { optionalAuthMiddleware } = require('../middleware/auth');
const ModelSchema = require('../models/ModelSchema');

const router = express.Router();

// Add user context to all routes
router.use(optionalAuthMiddleware);

// Home page
router.get('/', async (req, res) => {
  if (req.user) {
    return res.redirect('/admin/dashboard');
  }
  
  res.render('home', {
    title: 'Dynamic Auth System',
    subtitle: 'Full-stack authentication and authorization with dynamic models',
    user: req.user
  });
});

// Admin redirect
router.get('/admin', (req, res) => {
  res.redirect('/admin/dashboard');
});

// Login page
router.get('/login', (req, res) => {
  if (req.user) {
    return res.redirect('/admin/dashboard');
  }
  
  res.render('auth/login', {
    title: 'Login',
    error: req.query.error,
    user: req.user
  });
});

// Register page
router.get('/register', (req, res) => {
  if (req.user) {
    return res.redirect('/admin/dashboard');
  }
  
  res.render('auth/register', {
    title: 'Register',
    error: req.query.error,
    user: req.user
  });
});

// Forgot password page
router.get('/forgot-password', (req, res) => {
  if (req.user) {
    return res.redirect('/admin/dashboard');
  }
  
  res.render('auth/forgot-password', {
    title: 'Forgot Password',
    user: req.user
  });
});

// About page
router.get('/about', (req, res) => {
  res.render('about', {
    title: 'About',
    user: req.user
  });
});

// Help page
router.get('/help', (req, res) => {
  res.render('help', {
    title: 'Help & Documentation',
    user: req.user
  });
});

// Public API documentation
router.get('/docs', (req, res) => {
  res.render('docs', {
    title: 'API Documentation',
    user: req.user
  });
});

// Error pages
router.get('/error/:code', (req, res) => {
  const code = parseInt(req.params.code);
  const errorMessages = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Page Not Found',
    500: 'Internal Server Error'
  };
  
  res.status(code).render('error', {
    title: `Error ${code}`,
    message: errorMessages[code] || 'An error occurred',
    error: { status: code },
    user: req.user
  });
});

module.exports = router;