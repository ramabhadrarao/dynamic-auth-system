# Dynamic Auth System

A comprehensive Node.js application with dynamic model creation, multi-user authentication, and attribute-based access control (ABAC). Built with Express.js, MongoDB, Pug templates, and Tabler UI.

## 🚀 Features

### Core Features
- **JWT Authentication** with access and refresh tokens
- **Role-Based Access Control (RBAC)** and **Attribute-Based Access Control (ABAC)**
- **Dynamic Model Creation** - Create data models through UI without coding
- **Multi-User Management** with granular permissions
- **File Upload & Management** with metadata storage
- **RESTful API** with automatic CRUD operations
- **Responsive Admin Panel** built with Tabler UI

### Security Features
- Password hashing with bcrypt
- Rate limiting and security headers
- Input validation and sanitization
- CORS protection
- Session management
- Token blacklisting

### Dynamic System Features
- **Model Builder** - Visual interface for creating data models
- **Auto-Generated APIs** - Automatic REST endpoints for created models
- **Dynamic Views** - Auto-generated list, form, and detail pages
- **Permission Management** - Assign permissions per model and field
- **Field-Level Security** - Control access to individual fields
- **Data Filtering** - Row-level security based on user attributes

## 📋 Prerequisites

- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn

## 🛠️ Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd dynamic-auth-system
```

2. **Install dependencies**
```bash
npm install
```

3. **Environment Setup**
Copy `.env.example` to `.env` and configure:
```bash
cp .env.example .env
```

Edit `.env` file:
```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/dynamic_auth_system

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_REFRESH_SECRET=your-super-secret-refresh-key-change-this-in-production
JWT_EXPIRE=30m
JWT_REFRESH_EXPIRE=7d

# Admin Configuration
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin@123456
```

4. **Start MongoDB**
Make sure MongoDB is running on your system.

5. **Seed the database**
```bash
npm run seed
```

6. **Start the application**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 🎯 Quick Start

1. **Access the application**
   - Web interface: http://localhost:3000
   - Admin panel: http://localhost:3000/admin
   - API documentation: http://localhost:3000/docs

2. **Login with admin credentials**
   - Email: admin@example.com
   - Password: Admin@123456

3. **Create your first dynamic model**
   - Go to Admin Panel → Models
   - Click "Create New Model"
   - Define fields and permissions
   - Activate the model

## 📁 Project Structure

```
dynamic-auth-system/
├── app.js                     # Main application file
├── package.json              # Dependencies and scripts
├── .env                      # Environment variables
├── README.md                 # This file
│
├── middleware/               # Custom middleware
│   ├── auth.js              # Authentication & authorization
│   ├── dynamicModel.js      # Dynamic model handling
│   └── errorHandler.js      # Error handling
│
├── models/                  # Mongoose models
│   ├── User.js             # User model
│   ├── ModelSchema.js      # Dynamic model definitions
│   ├── Attachment.js       # File attachment model
│   └── Permission.js       # Permission, Role, Policy models
│
├── routes/                 # Route handlers
│   ├── auth.js            # Authentication routes
│   ├── users.js           # User management routes
│   ├── models.js          # Model management routes
│   ├── dynamic.js         # Dynamic model API routes
│   ├── admin.js           # Admin panel routes
│   └── web.js             # Public web routes
│
├── services/              # Business logic services
│   └── dynamicModelService.js  # Dynamic model creation
│
├── views/                 # Pug templates
│   ├── layout.pug         # Main layout
│   ├── auth/              # Authentication pages
│   ├── admin/             # Admin panel pages
│   └── components/        # Reusable components
│
├── public/               # Static assets
│   ├── css/             # Custom stylesheets
│   ├── js/              # Client-side JavaScript
│   └── images/          # Images and icons
│
├── uploads/             # File upload directory
└── scripts/             # Utility scripts
    └── seed.js          # Database seeding script
```

## 🔐 Authentication & Authorization

### Authentication Flow
1. User login with email/username and password
2. Server validates credentials and issues JWT access token (30 min) and refresh token (7 days)
3. Access token stored in memory, refresh token in httpOnly cookie
4. Automatic token refresh before expiry
5. Secure logout with token blacklisting

### Permission System
- **RBAC**: Role-based permissions (super_admin, admin, manager, user)
- **ABAC**: Attribute-based conditions (owner, department, time-based)
- **Resource-Level**: Permissions per model (create, read, update, delete)
- **Field-Level**: Control access to individual model fields
- **Row-Level**: Filter data based on user attributes

### Permission Examples
```javascript
// User can only access their own records
{
  role: 'user',
  resource: 'Product',
  action: 'read',
  conditions: { owner: '${user.id}' }
}

// Manager can access department records
{
  role: 'manager',
  resource: 'Product',
  action: 'update',
  conditions: { department: '${user.department}' }
}
```

## 🎨 Dynamic Model System

### Creating Models
1. **Define Model Structure**
   - Model name and display name
   - Field definitions with types and validation
   - UI configuration for forms and lists

2. **Set Permissions**
   - CRUD permissions per role
   - Attribute-based conditions
   - Field-level visibility

3. **Activate Model**
   - Generates Mongoose schema
   - Creates API endpoints
   - Generates admin interface

### Supported Field Types
- **String**: Text, email, password, URL, textarea
- **Number**: Integer, decimal with min/max validation
- **Date**: Date, datetime, time
- **Boolean**: Checkbox, radio buttons
- **ObjectId**: References to other models
- **Array**: Multiple values
- **Mixed**: Any data type

### Field Configuration Options
- **Validation**: Required, unique, min/max length, regex patterns
- **UI**: Input type, placeholder, help text, options
- **Display**: Show in list/form/detail views
- **Search**: Searchable, sortable, filterable fields
- **Security**: Field-level permissions

## 📊 API Documentation

### Authentication Endpoints
```
POST /api/auth/register     # Register new user
POST /api/auth/login        # User login
POST /api/auth/logout       # User logout
POST /api/auth/refresh      # Refresh access token
GET  /api/auth/me          # Get current user profile
PUT  /api/auth/me          # Update user profile
```

### Dynamic Model API
```
GET    /api/dynamic/:model        # List records
GET    /api/dynamic/:model/:id    # Get single record
POST   /api/dynamic/:model        # Create record
PUT    /api/dynamic/:model/:id    # Update record
DELETE /api/dynamic/:model/:id    # Delete record
POST   /api/dynamic/:model/bulk   # Bulk operations
```

### Model Management API
```
GET    /api/models           # List model schemas
POST   /api/models           # Create model schema
GET    /api/models/:id       # Get model schema
PUT    /api/models/:id       # Update model schema
DELETE /api/models/:id       # Delete model schema
POST   /api/models/:id/activate    # Activate model
POST   /api/models/:id/deactivate  # Deactivate model
```

## 🎨 UI Components

### Tabler UI Integration
- Responsive design with Bootstrap-based components
- Clean and modern interface
- Dark/light theme support
- Mobile-friendly navigation

### Admin Panel Features
- **Dashboard**: Statistics and recent activities
- **User Management**: Create, edit, view users
- **Model Builder**: Visual model creation interface
- **Permission Manager**: Role and permission assignment
- **File Manager**: Upload and organize files
- **Settings**: System configuration

## 🔧 Configuration

### Environment Variables
```env
# Server
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/dynamic_auth_system

# Security
JWT_SECRET=your-jwt-secret
JWT_REFRESH_SECRET=your-refresh-secret
SESSION_SECRET=your-session-secret
BCRYPT_ROUNDS=12

# File Upload
MAX_FILE_SIZE=10485760
UPLOAD_PATH=./uploads

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
```

### Security Best Practices
- Use strong, unique secrets in production
- Enable HTTPS in production
- Configure proper CORS settings
- Set up rate limiting
- Regular security audits
- Monitor for suspicious activities

## 🚀 Deployment

### Production Setup
1. **Environment Configuration**
```env
NODE_ENV=production
PORT=80
MONGODB_URI=mongodb://your-production-db
JWT_SECRET=your-strong-production-secret
```

2. **Process Management**
```bash
# Using PM2
npm install -g pm2
pm2 start app.js --name "dynamic-auth-system"
pm2 startup
pm2 save
```

3. **Reverse Proxy (Nginx)**
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run specific test file
npm test -- --grep "Authentication"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Express.js](https://expressjs.com/) - Web framework
- [MongoDB](https://www.mongodb.com/) - Database
- [Mongoose](https://mongoosejs.com/) - ODM
- [Tabler](https://tabler.io/) - UI framework
- [Pug](https://pugjs.org/) - Template engine
- [JWT](https://jwt.io/) - Authentication tokens

## 📞 Support

For support, email support@example.com or create an issue on GitHub.