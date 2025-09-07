const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Environment variables with fallbacks
const JWT_SECRET = process.env.JWT_SECRET || 'clubops-jwt-secret-2025-production-change-this';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://clubops-frontend.vercel.app';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security warning for production
if (NODE_ENV === 'production' && JWT_SECRET === 'clubops-jwt-secret-2025-production-change-this') {
  console.warn('⚠️ WARNING: Using default JWT secret in production! Please set JWT_SECRET environment variable.');
}

// CORS headers with environment-specific origins
const corsHeaders = {
  'Access-Control-Allow-Origin': NODE_ENV === 'production' ? FRONTEND_URL : '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Credentials': 'true',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};

// Mock Database (In production, use a real database)
const mockDatabase = {
  clubs: [
    {
      id: 1,
      name: "Elite Gentleman's Club",
      address: "123 Main St, City, State",
      phone: "(555) 123-4567",
      settings: {
        barFeeSplitPercentage: 70,
        vipRoomHourlyRate: 150,
        timezone: "America/New_York"
      }
    }
  ],
  users: [
    {
      id: 1,
      email: "admin@eliteclub.com",
      password: "$2a$10$8K1p3YQ8Z7X9.nKJ2L0FZeBHvJ6QV1WUO2R3HM4N5.ZY7Q8K1p3YQ", // admin123
      firstName: "Club",
      lastName: "Manager",
      role: "manager",
      clubId: 1
    }
  ],
  dancers: [
    {
      id: 1,
      name: "Sophia",
      email: "sophia@example.com",
      phone: "(555) 987-6543",
      clubId: 1,
      licenseNumber: "DL123456",
      licenseExpiryDate: "2025-12-31",
      isActive: true,
      contractSigned: true,
      emergencyContact: {
        name: "Sarah Johnson",
        phone: "(555) 123-7890"
      }
    },
    {
      id: 2,
      name: "Isabella",
      email: "isabella@example.com",
      phone: "(555) 456-7890",
      clubId: 1,
      licenseNumber: "DL789012",
      licenseExpiryDate: "2025-11-15",
      isActive: true,
      contractSigned: true,
      emergencyContact: {
        name: "Mike Wilson",
        phone: "(555) 987-1234"
      }
    }
  ],
  stages: [
    { id: 1, name: "Main Stage", clubId: 1, isActive: true },
    { id: 2, name: "Private Stage", clubId: 1, isActive: true }
  ],
  vipRooms: [
    { id: 1, name: "VIP Room 1", clubId: 1, isOccupied: false, hourlyRate: 150 },
    { id: 2, name: "VIP Room 2", clubId: 1, isOccupied: false, hourlyRate: 200 },
    { id: 3, name: "Champagne Room", clubId: 1, isOccupied: true, hourlyRate: 300 }
  ],
  djQueue: [],
  checkedInDancers: [],
  financialRecords: []
};

// Authentication helper
const authenticateToken = (authHeader) => {
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return { error: 'Access token required', status: 401 };
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    return { user };
  } catch (error) {
    console.error('Token verification error:', error.message);
    return { error: 'Invalid or expired token', status: 403 };
  }
};

// Helper to get request body with error handling
const getBody = (req) => {
  return new Promise((resolve, reject) => {
    if (req.method === 'GET') {
      resolve({});
      return;
    }
    
    let body = '';
    let chunks = 0;
    const maxChunks = 1e6; // Prevent large payloads
    
    req.on('data', chunk => {
      chunks++;
      if (chunks > maxChunks) {
        reject(new Error('Request entity too large'));
        return;
      }
      body += chunk.toString();
    });
    
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        console.error('JSON parse error:', e.message);
        reject(new Error('Invalid JSON in request body'));
      }
    });
    
    req.on('error', (error) => {
      console.error('Request body error:', error.message);
      reject(error);
    });
  });
};

// Route handlers
const handleAuth = async (req, res, path) => {
  try {
    const body = await getBody(req);

    if (path === '/auth/login' && req.method === 'POST') {
      console.log(`${new Date().toISOString()} - Login attempt for:`, body.email);
      
      const { email, password } = body;

      // Input validation
      if (!email || !password) {
        console.log('Login failed: Missing email or password');
        return res.status(400).json({ error: 'Email and password are required' });
      }

      if (typeof email !== 'string' || typeof password !== 'string') {
        console.log('Login failed: Invalid email or password format');
        return res.status(400).json({ error: 'Invalid email or password format' });
      }

      const user = mockDatabase.users.find(u => u.email === email);
      if (!user) {
        console.log('Login failed: User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        console.log('Login failed: Invalid password');
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const club = mockDatabase.clubs.find(c => c.id === user.clubId);
      if (!club) {
        console.log('Login failed: User club not found');
        return res.status(500).json({ error: 'User club configuration error' });
      }

      const token = jwt.sign(
        { 
          userId: user.id, 
          clubId: user.clubId, 
          role: user.role,
          iat: Math.floor(Date.now() / 1000)
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      console.log('Login successful for:', email);

      // Return the correct structure that frontend expects
      return res.status(200).json({
        token,
        user: {
          id: user.id.toString(),
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          clubs: [{  // ✅ Return clubs array instead of club object
            id: club.id.toString(),
            name: club.name,
            role: user.role
          }]
        }
      });
    }

    if (path === '/auth/me' && req.method === 'GET') {
      const auth = authenticateToken(req.headers.authorization);
      if (auth.error) {
        console.log('Auth/me failed:', auth.error);
        return res.status(auth.status).json({ error: auth.error });
      }

      const user = mockDatabase.users.find(u => u.id === auth.user.userId);
      const club = mockDatabase.clubs.find(c => c.id === auth.user.clubId);
      
      if (!user) {
        console.log('Auth/me failed: User not found');
        return res.status(404).json({ error: 'User not found' });
      }

      if (!club) {
        console.log('Auth/me failed: Club not found');
        return res.status(404).json({ error: 'User club not found' });
      }

      console.log('Auth/me successful for user:', user.email);

      // Return the correct structure that frontend expects
      return res.status(200).json({
        user: {
          id: user.id.toString(),
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          clubs: [{  // ✅ Return clubs array instead of club object
            id: club.id.toString(),
            name: club.name,
            role: user.role
          }]
        }
      });
    }

    return res.status(404).json({ error: 'Auth endpoint not found' });
    
  } catch (error) {
    console.error('Auth handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

const handleAPI = async (req, res, path) => {
  const auth = authenticateToken(req.headers.authorization);
  if (auth.error) {
    return res.status(auth.status).json({ error: auth.error });
  }

  try {
    const body = await getBody(req);

    // Dancers endpoints
    if (path === '/api/dancers' && req.method === 'GET') {
      const dancers = mockDatabase.dancers.filter(d => d.clubId === auth.user.clubId);
      return res.status(200).json(dancers);
    }

    if (path === '/api/dancers' && req.method === 'POST') {
      const newDancer = {
        id: mockDatabase.dancers.length + 1,
        ...body,
        clubId: auth.user.clubId,
        isActive: true,
        contractSigned: false
      };
      
      mockDatabase.dancers.push(newDancer);
      return res.status(201).json(newDancer);
    }

    if (path === '/api/dancers/alerts' && req.method === 'GET') {
      const twoWeeksFromNow = new Date();
      twoWeeksFromNow.setDate(twoWeeksFromNow.getDate() + 14);

      const alerts = mockDatabase.dancers
        .filter(d => d.clubId === auth.user.clubId)
        .filter(d => {
          const expiryDate = new Date(d.licenseExpiryDate);
          return expiryDate <= twoWeeksFromNow;
        })
        .map(d => ({
          dancerId: d.id,
          name: d.name,
          licenseNumber: d.licenseNumber,
          expiryDate: d.licenseExpiryDate,
          daysUntilExpiry: Math.ceil((new Date(d.licenseExpiryDate) - new Date()) / (1000 * 60 * 60 * 24)),
          severity: new Date(d.licenseExpiryDate) < new Date() ? 'expired' : 'warning'
        }));

      return res.status(200).json(alerts);
    }

    // VIP Rooms endpoints
    if (path === '/api/vip-rooms' && req.method === 'GET') {
      const rooms = mockDatabase.vipRooms.filter(r => r.clubId === auth.user.clubId);
      return res.status(200).json(rooms);
    }

    // Dashboard endpoint
    if (path === '/api/dashboard' && req.method === 'GET') {
      const clubDancers = mockDatabase.dancers.filter(d => d.clubId === auth.user.clubId);
      const clubRooms = mockDatabase.vipRooms.filter(r => r.clubId === auth.user.clubId);
      const clubRecords = mockDatabase.financialRecords.filter(r => r.clubId === auth.user.clubId);
      
      const dashboard = {
        stats: {
          totalDancers: clubDancers.length,
          activeDancers: clubDancers.filter(d => d.isActive).length,
          occupiedVipRooms: clubRooms.filter(r => r.isOccupied).length,
          totalVipRooms: clubRooms.length,
          todayRevenue: clubRecords
            .filter(r => new Date(r.timestamp).toDateString() === new Date().toDateString())
            .reduce((sum, r) => sum + r.amount, 0)
        },
        recentActivity: clubRecords.slice(-10).reverse(),
        licenseAlerts: clubDancers
          .filter(d => {
            const expiryDate = new Date(d.licenseExpiryDate);
            const twoWeeksFromNow = new Date();
            twoWeeksFromNow.setDate(twoWeeksFromNow.getDate() + 14);
            return expiryDate <= twoWeeksFromNow;
          })
          .length
      };
      
      return res.status(200).json(dashboard);
    }

    // Financial endpoints
    if (path === '/api/financial/summary' && req.method === 'GET') {
      const records = mockDatabase.financialRecords.filter(r => r.clubId === auth.user.clubId);
      
      const summary = {
        totalRevenue: records.reduce((sum, r) => sum + r.amount, 0),
        barFees: records.filter(r => r.type === 'bar_fee').reduce((sum, r) => sum + r.amount, 0),
        vipRevenue: records.filter(r => r.type === 'vip_room').reduce((sum, r) => sum + r.amount, 0),
        recordCount: records.length
      };
      
      return res.status(200).json(summary);
    }

    if (path === '/api/financial/bar-fee' && req.method === 'POST') {
      const record = {
        id: mockDatabase.financialRecords.length + 1,
        ...body,
        type: 'bar_fee',
        clubId: auth.user.clubId,
        timestamp: new Date().toISOString()
      };
      
      mockDatabase.financialRecords.push(record);
      return res.status(201).json(record);
    }

    return res.status(404).json({ error: 'API endpoint not found' });
    
  } catch (error) {
    console.error('API handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Main handler
module.exports = async (req, res) => {
  // Set CORS headers
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;

    console.log(`${new Date().toISOString()} - ${req.method} ${path} - User-Agent: ${req.headers['user-agent']?.substring(0, 50) || 'unknown'}`);

    // Health check
    if (path === '/health') {
      return res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.1',
        platform: 'Vercel Serverless',
        environment: NODE_ENV
      });
    }

    // Authentication routes
    if (path.startsWith('/auth/')) {
      return await handleAuth(req, res, path);
    }

    // API routes
    if (path.startsWith('/api/')) {
      return await handleAPI(req, res, path);
    }

    // 404 for unknown routes
    console.log(`404 - Route not found: ${path}`);
    return res.status(404).json({ error: 'Endpoint not found' });
    
  } catch (error) {
    console.error('Main handler error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};