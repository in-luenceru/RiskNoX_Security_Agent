#!/bin/bash

# RiskNoX Admin UI Test Script
echo "🚀 Starting RiskNoX Admin UI Development Server..."

# Check if we're in the correct directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found. Please run this script from the admin-ui directory."
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Build the project
echo "🔨 Building the project..."
npm run build

echo "✅ Build completed successfully!"
echo ""
echo "📋 Summary of new features added:"
echo "   • ✅ Antivirus Scanner page with scan controls and scheduling"
echo "   • ✅ Web Blocking page with URL management"
echo "   • ✅ Enhanced Schedules page with antivirus scan scheduling"
echo "   • ✅ Improved Patch Management with available patches display"
echo "   • ✅ Enhanced Dashboard with proper agent status tracking"
echo "   • ✅ Events page with real-time updates"
echo ""
echo "🌐 To start the development server, run:"
echo "   npm start"
echo ""
echo "🐳 To start with Docker, run from the manager directory:"
echo "   docker-compose up"