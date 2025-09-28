import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Shield, Activity, AlertTriangle } from 'lucide-react';
import { agentApi, systemApi } from '../../services/api';

const Dashboard: React.FC = () => {
  const { data: agents } = useQuery({
    queryKey: ['agents', { per_page: 1000 }],
    queryFn: () => agentApi.getAgents({ per_page: 1000 }),
  });

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const agentStats = React.useMemo(() => {
    if (!agents?.items) return { online: 0, offline: 0, error: 0, total: 0 };
    
    const stats = agents.items.reduce((acc, agent) => {
      acc.total++;
      acc[agent.status]++;
      return acc;
    }, { online: 0, offline: 0, error: 0, total: 0 });
    
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
          <div className="space-y-3">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-success-500 rounded-full mt-2"></div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-900">Agent enrollment completed</p>
                <p className="text-xs text-gray-500">2 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-primary-500 rounded-full mt-2"></div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-900">Scheduled scan completed</p>
                <p className="text-xs text-gray-500">5 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0">
                <div className="w-2 h-2 bg-warning-500 rounded-full mt-2"></div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-900">Patch rollout paused</p>
                <p className="text-xs text-gray-500">10 minutes ago</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;