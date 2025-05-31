// File: scripts/seed.js
// Database seeding script

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const ModelSchema = require('../models/ModelSchema');
const { Permission, Role, Policy } = require('../models/Permission');
const dynamicModelService = require('../services/dynamicModelService');

async function seedDatabase() {
  try {
    console.log('Connecting to database...');
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // Clear existing data
    console.log('Clearing existing data...');
    await User.deleteMany({});
    await ModelSchema.deleteMany({});
    await Permission.deleteMany({});
    await Role.deleteMany({});
    await Policy.deleteMany({});

    // Create admin user
    console.log('Creating admin user...');
    const adminUser = new User({
      username: 'admin',
      email: process.env.ADMIN_EMAIL || 'admin@example.com',
      password: process.env.ADMIN_PASSWORD || 'Admin@123456',
      firstName: 'System',
      lastName: 'Administrator',
      role: 'super_admin',
      isActive: true
    });
    await adminUser.save();
    console.log('Admin user created:', adminUser.email);

    // Create sample users
    console.log('Creating sample users...');
    const sampleUsers = [
      {
        username: 'john_doe',
        email: 'john@example.com',
        password: 'Password@123',
        firstName: 'John',
        lastName: 'Doe',
        role: 'manager',
        department: 'Sales',
        phone: '+1234567890'
      },
      {
        username: 'jane_smith',
        email: 'jane@example.com',
        password: 'Password@123',
        firstName: 'Jane',
        lastName: 'Smith',
        role: 'user',
        department: 'Marketing',
        phone: '+1234567891'
      },
      {
        username: 'bob_wilson',
        email: 'bob@example.com',
        password: 'Password@123',
        firstName: 'Bob',
        lastName: 'Wilson',
        role: 'user',
        department: 'IT',
        phone: '+1234567892'
        }
    ];

    for (const userData of sampleUsers) {
      const user = new User(userData);
      await user.save();
      console.log('Sample user created:', user.email);
    }

    // Create basic permissions
    console.log('Creating basic permissions...');
    const basicPermissions = [
      {
        name: 'read_users',
        displayName: 'Read Users',
        resource: 'User',
        action: 'read',
        createdBy: adminUser._id
      },
      {
        name: 'create_users',
        displayName: 'Create Users',
        resource: 'User',
        action: 'create',
        createdBy: adminUser._id
      },
      {
        name: 'update_users',
        displayName: 'Update Users',
        resource: 'User',
        action: 'update',
        createdBy: adminUser._id
      },
      {
        name: 'delete_users',
        displayName: 'Delete Users',
        resource: 'User',
        action: 'delete',
        createdBy: adminUser._id
      },
      {
        name: 'manage_models',
        displayName: 'Manage Models',
        resource: 'ModelSchema',
        action: 'manage',
        createdBy: adminUser._id
      }
    ];

    const createdPermissions = [];
    for (const permData of basicPermissions) {
      const permission = new Permission(permData);
      await permission.save();
      createdPermissions.push(permission);
      console.log('Permission created:', permission.name);
    }

    // Create basic roles
    console.log('Creating basic roles...');
    const managerRole = new Role({
      name: 'manager',
      displayName: 'Manager',
      description: 'Can manage users and view reports',
      permissions: createdPermissions.slice(0, 3).map(p => p._id), // read, create, update
      level: 2,
      createdBy: adminUser._id
    });
    await managerRole.save();

    const userRole = new Role({
      name: 'user',
      displayName: 'User',
      description: 'Basic user access',
      permissions: [createdPermissions[0]._id], // read only
      level: 1,
      createdBy: adminUser._id
    });
    await userRole.save();

    console.log('Roles created');

    // Create sample model schema
    console.log('Creating sample model schema...');
    const productSchema = new ModelSchema({
      name: 'Product',
      displayName: 'Products',
      description: 'Product catalog management',
      fields: [
        {
          name: 'name',
          type: 'String',
          required: true,
          label: 'Product Name',
          placeholder: 'Enter product name',
          inputType: 'text',
          showInList: true,
          showInForm: true,
          showInDetail: true,
          searchable: true,
          sortable: true,
          displayOrder: 10
        },
        {
          name: 'description',
          type: 'String',
          label: 'Description',
          placeholder: 'Enter product description',
          inputType: 'textarea',
          showInList: false,
          showInForm: true,
          showInDetail: true,
          searchable: true,
          displayOrder: 20
        },
        {
          name: 'price',
          type: 'Number',
          required: true,
          label: 'Price',
          placeholder: 'Enter price',
          inputType: 'number',
          min: 0,
          showInList: true,
          showInForm: true,
          showInDetail: true,
          sortable: true,
          filterable: true,
          displayOrder: 30
        },
        {
          name: 'category',
          type: 'String',
          required: true,
          label: 'Category',
          inputType: 'select',
          enum: ['Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports'],
          options: [
            { label: 'Electronics', value: 'Electronics' },
            { label: 'Clothing', value: 'Clothing' },
            { label: 'Books', value: 'Books' },
            { label: 'Home & Garden', value: 'Home & Garden' },
            { label: 'Sports', value: 'Sports' }
          ],
          showInList: true,
          showInForm: true,
          showInDetail: true,
          filterable: true,
          displayOrder: 40
        },
        {
          name: 'inStock',
          type: 'Boolean',
          label: 'In Stock',
          inputType: 'checkbox',
          default: true,
          showInList: true,
          showInForm: true,
          showInDetail: true,
          filterable: true,
          displayOrder: 50
        },
        {
          name: 'sku',
          type: 'String',
          required: true,
          unique: true,
          label: 'SKU',
          placeholder: 'Enter SKU',
          inputType: 'text',
          showInList: true,
          showInForm: true,
          showInDetail: true,
          searchable: true,
          displayOrder: 60
        },
        {
          name: 'owner',
          type: 'ObjectId',
          ref: 'User',
          label: 'Owner',
          showInList: false,
          showInForm: false,
          showInDetail: true,
          displayOrder: 100
        }
      ],
      permissions: {
        create: [
          { role: 'super_admin' },
          { role: 'admin' },
          { role: 'manager' }
        ],
        read: [
          { role: 'super_admin' },
          { role: 'admin' },
          { role: 'manager' },
          { role: 'user' }
        ],
        update: [
          { role: 'super_admin' },
          { role: 'admin' },
          { role: 'manager', conditions: { owner: '${user.id}' } }
        ],
        delete: [
          { role: 'super_admin' },
          { role: 'admin' }
        ]
      },
      ui: {
        icon: 'ti-package',
        color: 'primary',
        listView: {
          sortBy: 'name',
          sortOrder: 'asc',
          pageSize: 10
        }
      },
      status: 'active',
      createdBy: adminUser._id
    });

    await productSchema.save();
    console.log('Product schema created');

    // Create the dynamic model
    await dynamicModelService.createModel(productSchema);
    console.log('Product model activated');

    // Create sample products
    console.log('Creating sample products...');
    const Product = mongoose.models.Product;
    const sampleProducts = [
      {
        name: 'Laptop Pro 15"',
        description: 'High-performance laptop for professionals',
        price: 1299.99,
        category: 'Electronics',
        inStock: true,
        sku: 'LP-001',
        owner: adminUser._id
      },
      {
        name: 'Wireless Headphones',
        description: 'Premium noise-canceling wireless headphones',
        price: 199.99,
        category: 'Electronics',
        inStock: true,
        sku: 'WH-002',
        owner: adminUser._id
      },
      {
        name: 'Running Shoes',
        description: 'Comfortable running shoes for daily training',
        price: 89.99,
        category: 'Sports',
        inStock: true,
        sku: 'RS-003',
        owner: adminUser._id
      },
      {
        name: 'Programming Book',
        description: 'Complete guide to modern web development',
        price: 49.99,
        category: 'Books',
        inStock: false,
        sku: 'PB-004',
        owner: adminUser._id
      }
    ];

    for (const productData of sampleProducts) {
      const product = new Product(productData);
      await product.save();
      console.log('Sample product created:', product.name);
    }

    // Create basic policies
    console.log('Creating basic policies...');
    const basicPolicy = new Policy({
      name: 'department_access',
      displayName: 'Department Access Policy',
      description: 'Users can only access records from their department',
      type: 'abac',
      rules: [
        {
          subject: 'user',
          resource: '*',
          action: 'read',
          effect: 'allow',
          conditions: {
            department: '${user.department}'
          }
        }
      ],
      priority: 1,
      createdBy: adminUser._id
    });
    await basicPolicy.save();
    console.log('Basic policy created');

    console.log('\n=== Seeding completed successfully! ===');
    console.log('\nAdmin credentials:');
    console.log(`Email: ${adminUser.email}`);
    console.log(`Password: ${process.env.ADMIN_PASSWORD || 'Admin@123456'}`);
    console.log('\nSample user credentials:');
    console.log('Email: john@example.com, Password: Password@123 (Manager)');
    console.log('Email: jane@example.com, Password: Password@123 (User)');
    console.log('Email: bob@example.com, Password: Password@123 (User)');
    console.log('\nYou can now start the application with: npm start');

  } catch (error) {
    console.error('Seeding failed:', error);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
  }
}

// Run seeding if this file is executed directly
if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;