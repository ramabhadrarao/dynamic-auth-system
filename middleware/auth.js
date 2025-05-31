// File: middleware/auth.js
// Authentication and authorization middleware

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { Permission, Role, Policy } = require('../models/Permission');

// JWT token verification middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = getTokenFromRequest(req);
    
    if (!token) {
      return handleUnauthorized(req, res, 'Access token required');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password -refreshTokens');
    
    if (!user || !user.isActive) {
      return handleUnauthorized(req, res, 'Invalid or inactive user');
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return handleUnauthorized(req, res, 'Token expired');
    }
    return handleUnauthorized(req, res, 'Invalid token');
  }
};

// Optional authentication middleware (for public routes that can benefit from user context)
const optionalAuthMiddleware = async (req, res, next) => {
  try {
    const token = getTokenFromRequest(req);
    
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId).select('-password -refreshTokens');
      
      if (user && user.isActive) {
        req.user = user;
        req.token = token;
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
      }
    }
  } catch (error) {
    // Ignore errors in optional auth, but clear invalid tokens
    if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
      // For web requests, we might want to clear the token
      if (!req.path.startsWith('/api/')) {
        res.clearCookie('token');
      }
    }
  }
  
  next();
};

// Role-based authorization middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return handleForbidden(req, res, 'Authentication required');
    }

    const userRoles = Array.isArray(req.user.role) ? req.user.role : [req.user.role];
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    
    // Super admin has access to everything
    if (userRoles.includes('super_admin')) {
      return next();
    }

    const hasRole = requiredRoles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      return handleForbidden(req, res, `Requires one of: ${requiredRoles.join(', ')}`);
    }

    next();
  };
};

// Permission-based authorization middleware
const requirePermission = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return handleForbidden(req, res, 'Authentication required');
      }

      // Super admin has all permissions
      if (req.user.role === 'super_admin') {
        return next();
      }

      const hasPermission = await checkUserPermission(req.user, resource, action, {
        resource: req.body || req.params,
        user: req.user,
        clientIp: req.ip
      });

      if (!hasPermission) {
        return handleForbidden(req, res, `Permission denied: ${action} on ${resource}`);
      }

      next();
    } catch (error) {
      console.error('Permission check error:', error);
      return handleForbidden(req, res, 'Permission check failed');
    }
  };
};

// Attribute-based authorization middleware
const requireAttribute = (attributeCheck) => {
  return (req, res, next) => {
    if (!req.user) {
      return handleForbidden(req, res, 'Authentication required');
    }

    // Super admin bypasses attribute checks
    if (req.user.role === 'super_admin') {
      return next();
    }

    const hasAttribute = evaluateAttributeCondition(attributeCheck, req.user, req);
    
    if (!hasAttribute) {
      return handleForbidden(req, res, 'Attribute requirement not met');
    }

    next();
  };
};

// Dynamic resource authorization middleware
const requireResourceAccess = (resourceType) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return handleForbidden(req, res, 'Authentication required');
      }

      // Super admin has all access
      if (req.user.role === 'super_admin') {
        return next();
      }

      const resourceId = req.params.id;
      const action = getActionFromMethod(req.method);

      // Load the resource if ID is provided
      let resource = null;
      if (resourceId && mongoose.models[resourceType]) {
        resource = await mongoose.model(resourceType).findById(resourceId);
        if (!resource) {
          return res.status(404).json({ error: 'Resource not found' });
        }
      }

      const hasAccess = await checkUserPermission(req.user, resourceType, action, {
        resource: resource || req.body,
        user: req.user,
        clientIp: req.ip
      });

      if (!hasAccess) {
        return handleForbidden(req, res, `Access denied to ${resourceType}`);
      }

      req.resource = resource;
      next();
    } catch (error) {
      console.error('Resource access check error:', error);
      return handleForbidden(req, res, 'Access check failed');
    }
  };
};

// Helper function to extract token from request
const getTokenFromRequest = (req) => {
  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  // Check cookie
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }

  // Check query parameter (not recommended for production)
  if (req.query && req.query.token) {
    return req.query.token;
  }

  return null;
};

// Helper function to check user permission
const checkUserPermission = async (user, resource, action, context = {}) => {
  try {
    // Check direct user permissions first
    if (user.permissions && user.permissions.length > 0) {
      for (const permission of user.permissions) {
        if (permission.resource === resource && permission.actions.includes(action)) {
          // Check conditions if any
          if (permission.conditions && Object.keys(permission.conditions).length > 0) {
            return evaluateConditions(permission.conditions, context);
          }
          return true;
        }
      }
    }

    // Check role-based permissions
    const rolePermissions = await getRolePermissions(user.role);
    for (const permission of rolePermissions) {
      if (permission.resource === resource && permission.action === action) {
        return permission.evaluateConditions(context);
      }
    }

    // Check policy-based permissions (ABAC)
    const policies = await Policy.find({ isActive: true }).sort({ priority: -1 });
    for (const policy of policies) {
      const result = policy.evaluate(user, resource, action, context);
      if (result.effect === 'allow') {
        return true;
      } else if (result.effect === 'deny') {
        return false;
      }
    }

    return false;
  } catch (error) {
    console.error('Permission check error:', error);
    return false;
  }
};

// Helper function to get role permissions
const getRolePermissions = async (roleName) => {
  try {
    const role = await Role.findOne({ name: roleName, isActive: true })
      .populate('permissions');
    
    if (!role) return [];
    
    const allPermissions = await role.getAllPermissions();
    return await Permission.find({
      _id: { $in: allPermissions },
      isActive: true
    });
  } catch (error) {
    console.error('Role permission fetch error:', error);
    return [];
  }
};

// Helper function to evaluate conditions
const evaluateConditions = (conditions, context) => {
  for (const [key, value] of Object.entries(conditions)) {
    if (!evaluateCondition(key, value, context)) {
      return false;
    }
  }
  return true;
};

// Helper function to evaluate single condition
const evaluateCondition = (key, value, context) => {
  switch (key) {
    case 'owner':
      if (value === '${user.id}') {
        return context.resource && context.resource.owner && 
               context.resource.owner.toString() === context.user._id.toString();
      }
      return false;
    
    case 'department':
      if (value === '${user.department}') {
        return context.resource && context.resource.department === context.user.department;
      }
      return context.resource && context.resource.department === value;
    
    case 'time_range':
      const now = new Date();
      const startTime = new Date(value.start);
      const endTime = new Date(value.end);
      return now >= startTime && now <= endTime;
    
    default:
      return true;
  }
};

// Helper function to evaluate attribute conditions
const evaluateAttributeCondition = (attributeCheck, user, req) => {
  if (typeof attributeCheck === 'function') {
    return attributeCheck(user, req);
  }
  
  if (typeof attributeCheck === 'object') {
    for (const [key, value] of Object.entries(attributeCheck)) {
      if (user.attributes && user.attributes[key] !== value) {
        return false;
      }
    }
    return true;
  }
  
  return false;
};

// Helper function to get action from HTTP method
const getActionFromMethod = (method) => {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'read';
    case 'POST':
      return 'create';
    case 'PUT':
    case 'PATCH':
      return 'update';
    case 'DELETE':
      return 'delete';
    default:
      return 'execute';
  }
};

// Helper function to handle unauthorized requests
const handleUnauthorized = (req, res, message) => {
  // Check if it's an API request
  if (req.path.startsWith('/api/') || 
      (req.headers.accept && req.headers.accept.includes('application/json'))) {
    return res.status(401).json({ error: message, code: 'UNAUTHORIZED' });
  } else {
    // For web requests, redirect to login
    return res.redirect('/login?error=' + encodeURIComponent(message));
  }
};

// Helper function to handle forbidden requests
const handleForbidden = (req, res, message) => {
  // Check if it's an API request
  if (req.path.startsWith('/api/') || 
      (req.headers.accept && req.headers.accept.includes('application/json'))) {
    return res.status(403).json({ error: message, code: 'FORBIDDEN' });
  } else {
    // For web requests, show error page
    return res.status(403).render('error', {
      title: 'Access Denied',
      message: message,
      error: { status: 403 }
    });
  }
};

module.exports = {
  authMiddleware,
  optionalAuthMiddleware,
  requireRole,
  requirePermission,
  requireAttribute,
  requireResourceAccess,
  checkUserPermission
};