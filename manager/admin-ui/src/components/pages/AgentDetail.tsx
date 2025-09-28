import React from 'react';
import { useParams } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { 
  Shield, 
  Play, 
  Calendar, 
  Package, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Clock,
  Tag,
  RefreshCw
} from 'lucide-react';
import { agentApi, commandApi, patchApi } from '../../services/api';
import { Agent, Command } from '../../types';
import webSocketService from '../../services/websocket';

const AgentDetail: React.FC = () => {
  const { agentId } = useParams<{ agentId: string }>();
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [scheduleModalOpen, setScheduleModalOpen] = React.useState(false);

  // Query for agent details
  const { data: agent, refetch } = useQuery({
    queryKey: ['agent', agentId],
    queryFn: () => agentApi.getAgent(agentId!),
    enabled: !!agentId,
  });

  // Query for agent commands
  const { data: commands } = useQuery({
    queryKey: ['agent-commands', agentId],
    queryFn: () => commandApi.getCommands({ agent_id: agentId!, page: 1, per_page: 10 }),
    enabled: !!agentId,
  });

  // Query for agent patches
  const { data: patches } = useQuery({
    queryKey: ['agent-patches', agentId],
    queryFn: () => patchApi.getPatches({ page: 1, per_page: 10 }),
    enabled: !!agentId,
  });

  // Mutations
  const runScanMutation = useMutation({
    mutationFn: (scanType: 'quick' | 'full') =>
      commandApi.runScan(agentId!, scanType),
    onSuccess: () => {
      refetch();
    },
  });

  // Subscribe to real-time updates
  React.useEffect(() => {
    if (!agentId) return;

    const unsubscribeAgent = webSocketService.subscribe('agent_status', (data) => {
      if (data.agent_id === agentId) {
        refetch();
      }
    });

    const unsubscribeCommand = webSocketService.subscribe('command_progress', (data) => {
      if (data.agent_id === agentId) {
        refetch();
      }
    });

    return () => {
      unsubscribeAgent();
      unsubscribeCommand();
    };
  }, [agentId, refetch]);

  if (!agent) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="h-4 bg-gray-200 rounded w-1/2 mb-8"></div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map(i => (
              <div key={i} className="bg-white rounded-lg shadow p-6">
                <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                <div className="h-8 bg-gray-200 rounded w-1/2"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const getStatusIcon = (status: Agent['status']) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="h-5 w-5 text-success-500" />;
      case 'offline':
        return <XCircle className="h-5 w-5 text-gray-500" />;
      case 'error':
        return <AlertTriangle className="h-5 w-5 text-danger-500" />;
    }
  };

  const getCommandStatusIcon = (status: Command['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-success-500" />;
      case 'failed':
        return <XCircle className="h-4 w-4 text-danger-500" />;
      case 'running':
        return <RefreshCw className="h-4 w-4 text-primary-500 animate-spin" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    return date.toLocaleString();
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="h-8 w-8 text-gray-400" />
            <div>
              <h1 className="text-3xl font-bold text-gray-900">{agent.hostname}</h1>
              <div className="flex items-center space-x-4 mt-2">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(agent.status)}
                  <span className="text-sm text-gray-600 capitalize">{agent.status}</span>
                </div>
                <span className="text-gray-400">•</span>
                <span className="text-sm text-gray-600">{agent.ip_address}</span>
                <span className="text-gray-400">•</span>
                <span className="text-sm text-gray-600">Last seen: {formatLastSeen(agent.last_seen)}</span>
              </div>
            </div>
          </div>
          
          {/* Action Buttons */}
          <div className="flex space-x-3">
            <button
              onClick={() => runScanMutation.mutate('quick')}
              disabled={runScanMutation.isPending}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
            >
              <Play className="h-4 w-4 mr-2" />
              Quick Scan
            </button>
            <button
              onClick={() => runScanMutation.mutate('full')}
              disabled={runScanMutation.isPending}
              className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
            >
              <Shield className="h-4 w-4 mr-2" />
              Full Scan
            </button>
            <button
              onClick={() => setScheduleModalOpen(true)}
              className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Calendar className="h-4 w-4 mr-2" />
              Schedule
            </button>
          </div>
        </div>
      </div>

      {/* Agent Info Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* System Info */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">System Information</h3>
          <dl className="space-y-3">
            <div>
              <dt className="text-sm font-medium text-gray-500">Operating System</dt>
              <dd className="text-sm text-gray-900">{agent.os_info}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Agent Version</dt>
              <dd className="text-sm text-gray-900">v{agent.agent_version}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Architecture</dt>
              <dd className="text-sm text-gray-900">{agent.architecture || 'Unknown'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Enrolled</dt>
              <dd className="text-sm text-gray-900">{agent.enrolled_at ? formatLastSeen(agent.enrolled_at) : 'Unknown'}</dd>
            </div>
          </dl>
        </div>

        {/* Health Status */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Health Status</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Connection</span>
              <div className="flex items-center space-x-2">
                {getStatusIcon(agent.status)}
                <span className="text-sm capitalize">{agent.status}</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Last Scan</span>
              <span className="text-sm text-gray-900">
                {agent.last_scan ? formatLastSeen(agent.last_scan) : 'Never'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Pending Updates</span>
              <span className="text-sm text-gray-900">
                {patches?.items?.filter(p => p.status === 'pending').length || 0}
              </span>
            </div>
          </div>
        </div>

        {/* Tags */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Tags</h3>
          {agent.tags.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {agent.tags.map((tag) => (
                <span
                  key={tag}
                  className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800"
                >
                  <Tag className="h-3 w-3 mr-1" />
                  {tag}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No tags assigned</p>
          )}
        </div>
      </div>

      {/* Recent Commands and Patches */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Commands */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Recent Commands</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {commands?.items?.length ? (
              commands.items.map((command) => (
                <div key={command.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getCommandStatusIcon(command.status)}
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          {command.command_type}
                        </p>
                        <p className="text-sm text-gray-500">
                          {formatLastSeen(command.created_at)}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm capitalize text-gray-900">{command.status}</p>
                      {command.progress !== undefined && (
                        <p className="text-sm text-gray-500">{command.progress}%</p>
                      )}
                    </div>
                  </div>
                  {command.result && (
                    <div className="mt-2">
                      <p className="text-sm text-gray-600 truncate">
                        {command.result}
                      </p>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center">
                <Activity className="mx-auto h-8 w-8 text-gray-400" />
                <p className="mt-2 text-sm text-gray-500">No recent commands</p>
              </div>
            )}
          </div>
        </div>

        {/* Installed Patches */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Patches</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {patches?.items?.length ? (
              patches.items.map((patch) => (
                <div key={patch.id} className="px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {patch.patch_id}
                      </p>
                      <p className="text-sm text-gray-500">
                        {patch.description}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        patch.status === 'installed' ? 'bg-success-100 text-success-800' :
                        patch.status === 'pending' ? 'bg-warning-100 text-warning-800' :
                        'bg-danger-100 text-danger-800'
                      }`}>
                        {patch.status}
                      </span>
                      <p className="text-sm text-gray-500 mt-1">
                        {formatLastSeen(patch.installed_at || patch.created_at)}
                      </p>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="px-6 py-8 text-center">
                <Package className="mx-auto h-8 w-8 text-gray-400" />
                <p className="mt-2 text-sm text-gray-500">No patches found</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AgentDetail;