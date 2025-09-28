# RiskNoX Admin UI

A comprehensive React-based administrative interface for the RiskNoX Security Agent Management System.

## Features

### 🎯 Agent Management
- **Global Agents List**: View all security agents with search and filtering capabilities
- **Agent Details**: Deep dive into individual agent health, scan history, and patch status
- **Real-time Status**: Live WebSocket updates for agent connectivity and command progress
- **Tag-based Organization**: Filter and manage agents by custom tags

### 📅 Scheduling System
- **Automated Scans**: Schedule quick or full security scans with cron-like expressions
- **Flexible Targeting**: Target specific agents by tags or groups
- **Schedule Management**: Create, edit, enable/disable automated schedules

### 🚀 Patch Rollout Controls
- **Canary Deployments**: Gradual rollouts with configurable canary percentages
- **Real-time Monitoring**: Track rollout progress with success rates and agent counts
- **Rollback Capabilities**: Quick rollback on failure detection
- **Auto-promotion**: Automatic progression from canary to full deployment

### 📊 System Monitoring
- **Real-time Events**: Live stream of system activities and alerts
- **Event Filtering**: Filter by level, source, and custom search terms
- **Dashboard Overview**: System health metrics and agent statistics

## Technology Stack

- **React 18.2.0** with TypeScript for type-safe development
- **Tailwind CSS 3.3.6** for responsive, utility-first styling
- **Tanstack React Query 5.8.4** for efficient data fetching and caching
- **Socket.io Client 4.7.4** for real-time WebSocket communications
- **React Router DOM 6.18.0** for client-side navigation
- **Axios 1.6.1** for HTTP API requests
- **Lucide React** for modern, consistent icons

## Getting Started

### Prerequisites
- Node.js 16+ and npm
- RiskNoX Manager Backend running on `localhost:8001`

### Installation

1. **Install Dependencies**
   ```bash
   cd admin-ui
   npm install
   ```

2. **Configure Environment**
   Create `.env` file (optional):
   ```env
   REACT_APP_API_URL=http://localhost:8001
   ```

3. **Start Development Server**
   ```bash
   npm start
   ```

4. **Build for Production**
   ```bash
   npm run build
   ```

## Architecture

### Component Structure
```
src/
├── components/
│   ├── Layout.tsx          # Main layout with navigation
│   └── pages/              # Page components
│       ├── Dashboard.tsx   # System overview
│       ├── AgentsList.tsx  # Agent management
│       ├── AgentDetail.tsx # Individual agent details
│       ├── SchedulesPage.tsx # Schedule management
│       ├── PatchRolloutPage.tsx # Rollout controls
│       └── EventsPage.tsx  # System events
├── services/
│   ├── api.ts             # REST API client
│   └── websocket.ts       # WebSocket service
├── types/
│   └── index.ts           # TypeScript definitions
└── App.tsx                # Main application
```

### API Integration

The Admin UI communicates with the RiskNoX Manager through:
- **REST API**: CRUD operations for agents, schedules, patches
- **WebSocket**: Real-time updates for agent status, command progress, events

### Data Flow
1. **React Query** manages server state and caching
2. **WebSocket Service** provides real-time updates
3. **API Service** handles all HTTP requests
4. **TypeScript Types** ensure type safety across the application

## Key Features Implementation

### Real-time Updates
- WebSocket connection established on app startup
- Subscribe to specific event types (agent_status, command_progress, new_event)
- Automatic query invalidation triggers UI updates

### Responsive Design
- Mobile-first approach with Tailwind CSS
- Adaptive layouts for different screen sizes
- Touch-friendly interface elements

### Error Handling
- HTTP interceptors for authentication and error responses
- Graceful degradation for offline scenarios
- User-friendly error messages

### Performance Optimization
- React Query caching reduces unnecessary API calls
- Code splitting with React.lazy (ready for implementation)
- Optimized re-renders with proper dependency arrays

## Security Considerations

- **Authentication**: Bearer token support in API requests
- **Authorization**: Automatic redirect on 401 responses
- **Input Validation**: TypeScript types prevent invalid data
- **HTTPS Ready**: Production builds support secure connections

## Development

### Code Style
- TypeScript strict mode enabled
- ESLint and Prettier configurations
- Consistent component patterns and naming conventions

### Testing (Ready for Implementation)
- Jest and React Testing Library setup ready
- Component testing patterns established
- API mocking capabilities prepared

## Production Deployment

1. **Build the application**
   ```bash
   npm run build
   ```

2. **Serve static files** using nginx, Apache, or CDN

3. **Configure reverse proxy** to backend API at `/api/*`

4. **Set environment variables** for production API URLs

## Integration with RiskNoX Manager

The Admin UI expects the following API endpoints on the Manager:

- `GET /api/v1/agents` - List agents
- `GET /api/v1/agents/:id` - Get agent details
- `POST /api/v1/commands` - Create commands
- `GET /api/v1/schedules` - List schedules
- `POST /api/v1/schedules` - Create schedules
- `GET /api/v1/patch-rollouts` - List rollouts
- `POST /api/v1/patch-rollouts` - Create rollouts
- `GET /api/v1/events` - List events
- WebSocket connection at `/socket.io`

## Future Enhancements

- [ ] Advanced filtering and search capabilities
- [ ] Custom dashboard widgets
- [ ] Export functionality for reports
- [ ] Multi-tenant support
- [ ] Advanced role-based access control
- [ ] Audit logging interface
- [ ] Performance metrics visualization

## Support

For issues and questions:
1. Check the Manager backend logs
2. Verify WebSocket connectivity
3. Review browser console for errors
4. Ensure API endpoints are accessible

The Admin UI provides a comprehensive, modern interface for managing the RiskNoX Security Agent ecosystem with real-time monitoring, intuitive controls, and enterprise-grade features.