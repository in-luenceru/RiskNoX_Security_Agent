import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout';
import {
  Dashboard,
  AgentsList,
  AgentDetail,
  SchedulesPage,
  PatchRolloutPage,
  EventsPage,
  WebBlockingPage,
  AntivirusScannerPage
} from './components/pages';
import webSocketService from './services/websocket';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  React.useEffect(() => {
    // Connect to WebSocket on app start
    webSocketService.connect();
    
    return () => {
      webSocketService.disconnect();
    };
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/agents" element={<AgentsList />} />
            <Route path="/agents/:agentId" element={<AgentDetail />} />
            <Route path="/antivirus" element={<AntivirusScannerPage />} />
            <Route path="/web-blocking" element={<WebBlockingPage />} />
            <Route path="/schedules" element={<SchedulesPage />} />
            <Route path="/patches" element={<PatchRolloutPage />} />
            <Route path="/events" element={<EventsPage />} />
          </Routes>
        </Layout>
      </Router>
    </QueryClientProvider>
  );
}

export default App;