import React from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Shield, Activity, AlertTriangle } from 'lucide-react';
import { agentApi, systemApi, eventApi } from '../../services/api';
import webSocketService from '../../services/websocket';

const Dashboard: React.FC = () => {
  const queryClient = useQueryClient();
  
  const { data: agents, isLoading: agentsLoading, error: agentsError } = useQuery({
    queryKey: ['agents', { per_page: 1000 }],
    queryFn: () => agentApi.getAgents({ per_page: 1000 }),
  });

  // Subscribe to real-time agent updates
  React.useEffect(() => {
    const unsubscribeAgentsUpdate = webSocketService.subscribe('agents_update', (data) => {
      console.log('Agents update received:', data);
      // Update the agents query cache with real-time data
      queryClient.setQueryData(['agents', { per_page: 1000 }], {
        items: data.agents || [],
        total: data.agents ? data.agents.length : 0,
        page: 1,
        per_page: 1000
      });
    });

    const unsubscribeAgentStatus = webSocketService.subscribe('agent_status', (data) => {
      console.log('Agent status update received:', data);
      // Invalidate and refetch agents data to get fresh status
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    });

    const unsubscribeAgentConnect = webSocketService.subscribe('agent_connected', (data) => {
      console.log('Agent connected:', data);
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    });

    const unsubscribeAgentDisconnect = webSocketService.subscribe('agent_disconnected', (data) => {
      console.log('Agent disconnected:', data);
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    });

    return () => {
      unsubscribeAgentsUpdate();
      unsubscribeAgentStatus();
      unsubscribeAgentConnect();
      unsubscribeAgentDisconnect();
    };
  }, [queryClient]);

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: recentEvents } = useQuery({
    queryKey: ['events', { per_page: 5 }],
    queryFn: () => eventApi.getEvents({ per_page: 5 }),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const agentStats = React.useMemo(() => {
    if (!agents?.items || !Array.isArray(agents.items)) {
      console.log('No agents data or not an array:', agents);
      return { online: 0, offline: 0, error: 0, total: 0 };
    }
    
    const stats = agents.items.reduce((acc, agent) => {
      acc.total++;
      
      // Debug log for agent status
      console.log(`Agent ${agent.hostname}: status=${agent.status}, last_seen=${agent.last_seen}`);
      
      // Use the agent's explicit status field as primary indicator
      // The backend should be setting this correctly based on WebSocket connections
      switch (agent.status?.toLowerCase()) {
        case 'online':
        case 'connected':
        case 'active':
          acc.online++;
          break;
        case 'error':
        case 'failed':
          acc.error++;
          break;
        case 'offline':
        case 'disconnected':
        case 'inactive':
        default:
          // For offline agents, also check last_seen as backup
          if (agent.last_seen) {
            const lastSeen = new Date(agent.last_seen);
            const now = new Date();
            const timeDiff = (now.getTime() - lastSeen.getTime()) / 1000; // seconds
            
            // If seen very recently but marked offline, might be a status update delay
            if (timeDiff < 60) { // Less than 1 minute ago
              acc.online++;
            } else {
              acc.offline++;
            }
          } else {
            acc.offline++;
          }
          break;
      }
      
      return acc;
    }, { online: 0, offline: 0, error: 0, total: 0 });
    
    console.log('Agent stats calculated:', stats);
    return stats;
  }, [agents]);

  const cards = [
    {
      title: 'Total Agents',
      value: agentStats.total,
      icon: Shield,
      color: 'bg-primary-500',
    },
    {
      title: 'Online Agents', 
      value: agentStats.online,
      icon: Activity,
      color: 'bg-success-500',
    },
    {
      title: 'Offline Agents',
      value: agentStats.offline,
      icon: Shield,
      color: 'bg-gray-500',
    },
    {
      title: 'Error Agents',
      value: agentStats.error,
      icon: AlertTriangle,
      color: 'bg-danger-500',
    },
  ];

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-gray-600">Overview of your RiskNoX security infrastructure</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div key={card.title} className="bg-white rounded-lg shadow p-6">
              <div className="flex items-center">
                <div className={`${card.color} rounded-md p-3`}>
                  <Icon className="h-6 w-6 text-white" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">{card.title}</p>
                  <p className="text-2xl font-bold text-gray-900">{card.value}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* System Health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">System Health</h2>
          {health ? (
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Status</span>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                  health.status === 'healthy' 
                    ? 'bg-success-100 text-success-800'
                    : 'bg-danger-100 text-danger-800'
                }`}>
                  {health.status}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Database</span>
                <span className="text-sm text-gray-900">
                  {health.database?.status || 'Unknown'}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Redis</span>
                <span className="text-sm text-gray-900">
                  {health.redis?.status || 'Unknown'}
                </span>
              </div>
            </div>
          ) : (
            <div className="animate-pulse">
              <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
              <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
              <div className="h-4 bg-gray-200 rounded w-2/3"></div>
            </div>
          )}
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h2>
          {recentEvents?.items && recentEvents.items.length > 0 ? (
            <div className="space-y-3">
              {recentEvents.items.map((event) => {
                const levelColor = {
                  'info': 'bg-primary-500',
                  'success': 'bg-success-500', 
                  'warning': 'bg-warning-500',
                  'error': 'bg-danger-500'
                }[event.level] || 'bg-gray-500';

                const timeAgo = new Date().getTime() - new Date(event.timestamp).getTime();
                const minutesAgo = Math.floor(timeAgo / (1000 * 60));
                const hoursAgo = Math.floor(timeAgo / (1000 * 60 * 60));
                const timeDisplay = hoursAgo > 0 ? `${hoursAgo}h ago` : `${minutesAgo}m ago`;

                return (
                  <div key={event.id} className="flex items-start space-x-3">
                    <div className="flex-shrink-0">
                      <div className={`w-2 h-2 ${levelColor} rounded-full mt-2`}></div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-gray-900">{event.message}</p>
                      <p className="text-xs text-gray-500">{timeDisplay}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-sm text-gray-500">No recent activity</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;