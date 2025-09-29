import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, Play, Square, Clock, AlertTriangle, CheckCircle, Folder, HardDrive, Terminal } from 'lucide-react';
import { agentApi, commandApi, scheduleApi, scanApi } from '../../services/api';
import webSocketService from '../../services/websocket';

interface ScanResult {
  id: string;
  agent_id: string;
  scan_type: 'quick' | 'full' | 'directory';
  path?: string;
  status: 'running' | 'completed' | 'failed';
  threats_found: number;
  files_scanned: number;
  started_at: string;
  completed_at?: string;
}

interface ScheduleModalProps {
  onClose: () => void;
  onSchedule: (data: {
    name: string;
    scan_type: string;
    cron_expression: string;
    target_tags: string[];
  }) => void;
  isLoading: boolean;
}

interface LiveLogsModalProps {
  scanId: string;
  logs: string[];
  onClose: () => void;
}

const AntivirusScannerPage: React.FC = () => {
  const [selectedAgents, setSelectedAgents] = React.useState<string[]>([]);
  const [scanType, setScanType] = React.useState<'quick' | 'full' | 'directory'>('quick');
  const [scanPath, setScanPath] = React.useState('');
  const [showScheduleModal, setShowScheduleModal] = React.useState(false);
  const [showLiveLogsModal, setShowLiveLogsModal] = React.useState(false);
  const [selectedScanId, setSelectedScanId] = React.useState<string | null>(null);
  const [liveLogs, setLiveLogs] = React.useState<string[]>([]);
  const queryClient = useQueryClient();

  // Get agents
  const { data: agentsData } = useQuery({
    queryKey: ['agents', { per_page: 1000 }],
    queryFn: () => agentApi.getAgents({ per_page: 1000 }),
  });

  // Get schedules
  const { data: schedulesData } = useQuery({
    queryKey: ['schedules'],
    queryFn: () => scheduleApi.getSchedules({ per_page: 100 }),
  });

  // Get real scan results from API
  const { data: scanResults, refetch: refetchScans } = useQuery<ScanResult[]>({
    queryKey: ['scan-results'],
    queryFn: async () => {
      try {
        console.log('Fetching scan results from API...');
        const response = await scanApi.getScanResults({ per_page: 100 });
        console.log('Scan results API response:', response);
        return response.items || [];
      } catch (error) {
        console.error('Failed to fetch scan results:', error);
        // Return empty array instead of mock data to show real state
        return [];
      }
    },
    refetchInterval: 5000, // Refresh every 5 seconds for live updates
  });

  // WebSocket subscription for real-time scan updates
  React.useEffect(() => {
    const unsubscribeScanUpdate = webSocketService.subscribe('scan_update', (data) => {
      console.log('Scan update received:', data);
      refetchScans();
    });

    const unsubscribeScanLogs = webSocketService.subscribe('scan_logs', (data) => {
      if (data.scan_id === selectedScanId) {
        setLiveLogs(prev => [...prev, data.log_line]);
      }
    });

    return () => {
      unsubscribeScanUpdate();
      unsubscribeScanLogs();
    };
  }, [refetchScans, selectedScanId]);

  // Start scan mutation
  const startScanMutation = useMutation({
    mutationFn: async ({ agentIds, type, path }: { agentIds: string[]; type: 'quick' | 'full'; path?: string }) => {
      return commandApi.runScanMultiple(agentIds, type, path);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-results'] });
      setSelectedAgents([]);
    },
  });

  // Create schedule mutation
  const createScheduleMutation = useMutation({
    mutationFn: async (scheduleData: {
      name: string;
      scan_type: string;
      cron_expression: string;
      target_tags: string[];
      path?: string;
    }) => {
      return scheduleApi.createSchedule({
        name: scheduleData.name,
        description: `Scheduled ${scheduleData.scan_type} scan`,
        command_template: {
          command_type: 'scan',
          scan_type: scheduleData.scan_type,
          path: scheduleData.path,
        },
        cron_expression: scheduleData.cron_expression,
        target_tags: scheduleData.target_tags,
        is_active: true,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      setShowScheduleModal(false);
    },
  });

  const agents = agentsData?.items || [];
  const schedules = schedulesData?.items?.filter(s => 
    s.command_template?.command_type === 'scan'
  ) || [];

  const handleStartScan = () => {
    if (selectedAgents.length === 0) return;
    
    const type = scanType === 'directory' ? 'full' : scanType; // Map directory to full for API
    startScanMutation.mutate({ 
      agentIds: selectedAgents, 
      type,
      path: scanType === 'directory' ? scanPath : undefined 
    });
  };

  const getStatusBadge = (status: string) => {
    const styles = {
      running: 'bg-blue-100 text-blue-800',
      completed: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
    };
    
    const icons = {
      running: Play,
      completed: CheckCircle,
      failed: AlertTriangle,
    };

    const Icon = icons[status as keyof typeof icons];
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[status as keyof typeof styles]}`}>
        <Icon className="w-3 h-3 mr-1" />
        {status}
      </span>
    );
  };

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'quick': return <Shield className="w-4 h-4" />;
      case 'full': return <HardDrive className="w-4 h-4" />;
      case 'directory': return <Folder className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Antivirus Scanner</h1>
        <p className="mt-2 text-gray-600">Run scans and manage antivirus protection</p>
      </div>

      {/* Scan Control Panel */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          <Play className="inline-block w-5 h-5 mr-2" />
          Start New Scan
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Scan Type
              </label>
              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="radio"
                    name="scanType"
                    value="quick"
                    checked={scanType === 'quick'}
                    onChange={(e) => setScanType(e.target.value as any)}
                    className="mr-2"
                  />
                  <Shield className="w-4 h-4 mr-2" />
                  Quick Scan (Critical areas)
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    name="scanType"
                    value="full"
                    checked={scanType === 'full'}
                    onChange={(e) => setScanType(e.target.value as any)}
                    className="mr-2"
                  />
                  <HardDrive className="w-4 h-4 mr-2" />
                  Full System Scan
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    name="scanType"
                    value="directory"
                    checked={scanType === 'directory'}
                    onChange={(e) => setScanType(e.target.value as any)}
                    className="mr-2"
                  />
                  <Folder className="w-4 h-4 mr-2" />
                  Directory Scan
                </label>
              </div>
            </div>

            {scanType === 'directory' && (
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Directory Path
                </label>
                <input
                  type="text"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                  placeholder="e.g., C:\\Users\\Username\\Downloads"
                  value={scanPath}
                  onChange={(e) => setScanPath(e.target.value)}
                />
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target Agents
            </label>
            <div className="border border-gray-300 rounded-md p-3 max-h-48 overflow-y-auto">
              <div className="mb-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    className="mr-2"
                    checked={selectedAgents.length === agents.length}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedAgents(agents.map(a => a.id));
                      } else {
                        setSelectedAgents([]);
                      }
                    }}
                  />
                  <span className="text-sm font-medium">All Agents</span>
                </label>
              </div>
              {agents.map((agent) => (
                <label key={agent.id} className="flex items-center mb-1">
                  <input
                    type="checkbox"
                    className="mr-2"
                    checked={selectedAgents.includes(agent.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedAgents([...selectedAgents, agent.id]);
                      } else {
                        setSelectedAgents(selectedAgents.filter(id => id !== agent.id));
                      }
                    }}
                  />
                  <span className="text-sm">{agent.hostname} ({agent.status})</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 flex gap-4">
          <button
            onClick={handleStartScan}
            disabled={selectedAgents.length === 0 || startScanMutation.isPending}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-400"
          >
            <Play className="inline-block w-4 h-4 mr-2" />
            {startScanMutation.isPending ? 'Starting...' : 'Start Scan'}
          </button>
          
          <button
            onClick={() => setShowScheduleModal(true)}
            className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
          >
            <Clock className="inline-block w-4 h-4 mr-2" />
            Schedule Scan
          </button>
        </div>
      </div>

      {/* Active Scans */}
      <div className="bg-white rounded-lg shadow mb-6">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            <Shield className="inline-block w-5 h-5 mr-2" />
            Recent Scans
          </h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Agent
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Progress
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Threats
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Started
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {scanResults?.map((scan) => {
                const agent = agents.find(a => a.id === scan.agent_id);
                return (
                  <tr key={scan.id}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="text-sm font-medium text-gray-900">
                        {agent?.hostname || 'Unknown'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getScanTypeIcon(scan.scan_type)}
                        <span className="ml-2 text-sm text-gray-900 capitalize">
                          {scan.scan_type}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(scan.status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">
                        {scan.files_scanned.toLocaleString()} files
                      </div>
                      {scan.status === 'running' && (
                        <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                          <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{ width: '45%' }}></div>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`text-sm font-medium ${scan.threats_found > 0 ? 'text-red-600' : 'text-green-600'}`}>
                        {scan.threats_found}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <div className="flex items-center space-x-2">
                        <span>{new Date(scan.started_at).toLocaleString()}</span>
                        {scan.status === 'running' && (
                          <button
                            onClick={() => {
                              setSelectedScanId(scan.id);
                              setLiveLogs([]);
                              setShowLiveLogsModal(true);
                            }}
                            className="inline-flex items-center px-2 py-1 text-xs font-medium text-blue-600 bg-blue-100 rounded hover:bg-blue-200"
                          >
                            <Terminal className="w-3 h-3 mr-1" />
                            Live Logs
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {(!scanResults || scanResults.length === 0) && (
          <div className="text-center py-8">
            <Shield className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No scans yet</h3>
            <p className="mt-1 text-sm text-gray-500">
              Start your first antivirus scan.
            </p>
          </div>
        )}
      </div>

      {/* Scheduled Scans */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            <Clock className="inline-block w-5 h-5 mr-2" />
            Scheduled Scans
          </h2>
        </div>
        
        <div className="p-6">
          {schedules.length > 0 ? (
            <div className="space-y-4">
              {schedules.map((schedule) => (
                <div key={schedule.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900">{schedule.name}</h3>
                    <p className="text-sm text-gray-500">
                      {schedule.command_template?.scan_type} scan • {schedule.cron_expression}
                    </p>
                  </div>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    schedule.is_active 
                      ? 'bg-green-100 text-green-800'
                      : 'bg-gray-100 text-gray-800'
                  }`}>
                    {schedule.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <Clock className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No scheduled scans</h3>
              <p className="mt-1 text-sm text-gray-500">
                Create your first scheduled scan.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Schedule Modal */}
      {showScheduleModal && (
        <ScheduleScanModal
          onClose={() => setShowScheduleModal(false)}
          onSubmit={(data) => createScheduleMutation.mutate(data)}
          isLoading={createScheduleMutation.isPending}
        />
      )}

      {/* Live Logs Modal */}
      {showLiveLogsModal && selectedScanId && (
        <LiveLogsModal
          scanId={selectedScanId}
          logs={liveLogs}
          onClose={() => {
            setShowLiveLogsModal(false);
            setSelectedScanId(null);
            setLiveLogs([]);
          }}
        />
      )}
    </div>
  );
};

interface ScheduleScanModalProps {
  onClose: () => void;
  onSubmit: (data: any) => void;
  isLoading: boolean;
}

interface LiveLogsModalProps {
  scanId: string;
  logs: string[];
  onClose: () => void;
}

const ScheduleScanModal: React.FC<ScheduleScanModalProps> = ({ onClose, onSubmit, isLoading }) => {
  const [name, setName] = React.useState('');
  const [scanType, setScanType] = React.useState('quick');
  const [schedule, setSchedule] = React.useState('0 2 * * *'); // Daily at 2 AM
  const [tags, setTags] = React.useState<string[]>(['all']);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({
      name,
      scan_type: scanType,
      cron_expression: schedule,
      target_tags: tags,
    });
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Schedule New Scan</h3>
        
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="quick">Quick Scan</option>
              <option value="full">Full System Scan</option>
            </select>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">Schedule</label>
            <select
              value={schedule}
              onChange={(e) => setSchedule(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="0 2 * * *">Daily at 2:00 AM</option>
              <option value="0 2 * * 1">Weekly on Monday at 2:00 AM</option>
              <option value="0 2 1 * *">Monthly on 1st at 2:00 AM</option>
              <option value="0 */6 * * *">Every 6 hours</option>
            </select>
          </div>

          <div className="flex justify-end gap-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-md hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-400"
            >
              {isLoading ? 'Creating...' : 'Create Schedule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const LiveLogsModal: React.FC<LiveLogsModalProps> = ({ scanId, logs, onClose }) => {
  const logsEndRef = React.useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  React.useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg w-full max-w-4xl h-3/4 flex flex-col">
        <div className="flex items-center justify-between p-4 border-b">
          <h3 className="text-lg font-semibold text-gray-900 flex items-center">
            <Terminal className="w-5 h-5 mr-2" />
            Live Scan Logs - {scanId}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <span className="sr-only">Close</span>
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="flex-1 p-4 overflow-hidden">
          <div className="bg-black text-green-400 font-mono text-sm p-4 rounded h-full overflow-y-auto">
            {logs.length === 0 ? (
              <div className="text-gray-500">Waiting for logs...</div>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="mb-1">
                  {log}
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>
        
        <div className="p-4 border-t bg-gray-50">
          <div className="flex justify-between items-center text-sm text-gray-600">
            <span>{logs.length} log entries</span>
            <span>Auto-refreshing...</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AntivirusScannerPage;