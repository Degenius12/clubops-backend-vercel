# ClubOps Backend API - Vercel Serverless

## 🚀 Professional Club Management Backend

ClubOps is a complete SaaS platform for managing gentlemen's clubs, featuring dancer management, DJ queue control, VIP room tracking, and financial reporting.

## ⚡ Features

- **Authentication**: JWT-based login system
- **Dancer Management**: License tracking with compliance alerts  
- **DJ Queue**: Real-time queue management for multiple stages
- **VIP Rooms**: Room booking and session tracking
- **Financial Tracking**: Revenue monitoring and reporting
- **Dashboard**: Real-time analytics and insights

## 🛠 Tech Stack

- **Platform**: Vercel Serverless Functions
- **Runtime**: Node.js 18+
- **Authentication**: JWT + bcryptjs
- **Architecture**: RESTful API with CORS support

## 📡 API Endpoints

### Authentication
- `POST /auth/login` - User login
- `GET /auth/me` - Get current user info

### Dancers
- `GET /api/dancers` - List all dancers
- `POST /api/dancers` - Add new dancer
- `GET /api/dancers/alerts` - Get license expiry alerts

### Dashboard
- `GET /api/dashboard` - Get dashboard statistics

### VIP Rooms
- `GET /api/vip-rooms` - List all VIP rooms

### Financial
- `GET /api/financial/summary` - Financial summary
- `POST /api/financial/bar-fee` - Record bar fee payment

### Health Check
- `GET /health` - API health status

## 🔐 Demo Credentials

**Email**: admin@eliteclub.com  
**Password**: admin123

## 🚀 Deployment

This API is automatically deployed to Vercel. Simply connect your GitHub repository to Vercel and it will deploy automatically.

## 🔗 Frontend Integration

The backend is designed to work seamlessly with the ClubOps React frontend deployed at:
https://clubops-saas-platform.vercel.app

---

*ClubOps - Revolutionizing Club Management*