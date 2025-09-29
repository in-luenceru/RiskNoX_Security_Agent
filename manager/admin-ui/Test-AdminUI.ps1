# RiskNoX Admin UI Test Script
Write-Host "🚀 Starting RiskNoX Admin UI Development Server..." -ForegroundColor Green

# Check if we're in the correct directory
if (-not (Test-Path "package.json")) {
    Write-Host "❌ Error: package.json not found. Please run this script from the admin-ui directory." -ForegroundColor Red
    exit 1
}

# Install dependencies if node_modules doesn't exist
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
    npm install
}

# Build the project
Write-Host "🔨 Building the project..." -ForegroundColor Yellow
npm run build

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Summary of new features added:" -ForegroundColor Cyan
    Write-Host "   • ✅ Antivirus Scanner page with scan controls and scheduling" -ForegroundColor White
    Write-Host "   • ✅ Web Blocking page with URL management" -ForegroundColor White
    Write-Host "   • ✅ Enhanced Schedules page with antivirus scan scheduling" -ForegroundColor White
    Write-Host "   • ✅ Improved Patch Management with available patches display" -ForegroundColor White
    Write-Host "   • ✅ Enhanced Dashboard with proper agent status tracking" -ForegroundColor White
    Write-Host "   • ✅ Events page with real-time updates" -ForegroundColor White
    Write-Host ""
    Write-Host "🌐 To start the development server, run:" -ForegroundColor Cyan
    Write-Host "   npm start" -ForegroundColor White
    Write-Host ""
    Write-Host "🐳 To start with Docker, run from the manager directory:" -ForegroundColor Cyan
    Write-Host "   docker-compose up" -ForegroundColor White
} else {
    Write-Host "❌ Build failed! Please check the error messages above." -ForegroundColor Red
    exit 1
}