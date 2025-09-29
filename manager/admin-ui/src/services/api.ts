import axios from 'axios';
import { Agent, Command, Schedule, Patch, PatchRollout, Event, ApiResponse, PaginatedResponse } from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for authentication
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const agentApi = {
  // Get all agents with filtering and pagination
  getAgents: async (params?: {
    page?: number;
    per_page?: number;
    status?: string;
    tags?: string[];
    search?: string;
  }): Promise<PaginatedResponse<Agent>> => {
    try {
      const response = await apiClient.get('/api/v1/ui/agents', { params });
      console.log('Agent API response structure:', response.data);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch agents:', error);
      throw error;
    }
  },

  // Get single agent details
  getAgent: async (id: string): Promise<Agent> => {
    const response = await apiClient.get(`/api/v1/ui/agents/${id}`);
    return response.data;
  },

  // Update agent tags
  updateAgentTags: async (id: string, tags: string[]): Promise<Agent> => {
    const response = await apiClient.patch(`/api/v1/agents/${id}`, { tags });
    return response.data;
  },

  // Get agent events/logs
  getAgentEvents: async (id: string, params?: {
    page?: number;
    per_page?: number;
    event_type?: string;
  }): Promise<PaginatedResponse<Event>> => {
    const response = await apiClient.get(`/api/v1/agents/${id}/events`, { params });
    return response.data;
  },
};

export const commandApi = {
  // Get all commands with filtering
  getCommands: async (params?: {
    page?: number;
    per_page?: number;
    agent_id?: string;
    status?: string;
    command_type?: string;
  }): Promise<PaginatedResponse<Command>> => {
    const response = await apiClient.get('/api/v1/commands', { params });
    return response.data;
  },

  // Create new command
  createCommand: async (commandData: {
    agent_id?: string;
    target_tags?: string[];
    command_type: string;
    command_data: Record<string, any>;
    priority?: string;
  }): Promise<Command> => {
    const response = await apiClient.post('/api/v1/commands', commandData);
    return response.data;
  },

  // Get command details
  getCommand: async (id: string): Promise<Command> => {
    const response = await apiClient.get(`/api/v1/commands/${id}`);
    return response.data;
  },

  // Cancel command
  cancelCommand: async (id: string): Promise<ApiResponse<null>> => {
    const response = await apiClient.post(`/api/v1/commands/${id}/cancel`);
    return response.data;
  },

  // Run scan on agent
  runScan: async (agentId: string, scanType: 'quick' | 'full'): Promise<any> => {
    try {
      // Map scan types to the agent action format
      const scanData = {
        path: scanType === 'full' ? 'SYSTEM_SCAN' : 'QUICK_SYSTEM_SCAN',
        scan_type: scanType === 'full' ? 'system' : 'quick_system',
        agent_id: agentId
      };
      
      const response = await apiClient.post('/api/antivirus/scan', scanData);
      return response.data;
    } catch (error) {
      // Fallback to generic command creation
      console.warn('Agent action scan endpoint not available, using generic command creation');
      return commandApi.createCommand({
        agent_id: agentId,
        command_type: 'scan',
        command_data: {
          scan_type: scanType,
          path: scanType === 'full' ? 'SYSTEM_SCAN' : 'QUICK_SYSTEM_SCAN'
        },
        priority: 'high'
      });
    }
  },

  // Run scan on multiple agents
  runScanMultiple: async (agentIds: string[], scanType: 'quick' | 'full', path?: string): Promise<any> => {
    try {
      // Run scans on multiple agents individually using the agent action endpoint
      const results = await Promise.all(
        agentIds.map(async agentId => {
          const scanData = {
            path: path || (scanType === 'full' ? 'SYSTEM_SCAN' : 'QUICK_SYSTEM_SCAN'),
            scan_type: path ? 'directory' : (scanType === 'full' ? 'system' : 'quick_system'),
            agent_id: agentId
          };
          
          try {
            const response = await apiClient.post('/api/antivirus/scan', scanData);
            return { agent_id: agentId, success: true, data: response.data };
          } catch (error) {
            return { agent_id: agentId, success: false, error: error };
          }
        })
      );
      return { results };
    } catch (error) {
      // Fallback to creating individual commands
      console.warn('Agent action bulk scan not available, creating individual commands');
      const commands = await Promise.all(
        agentIds.map(agentId => 
          commandApi.createCommand({
            agent_id: agentId,
            command_type: 'scan',
            command_data: {
              scan_type: scanType,
              path: path || (scanType === 'full' ? 'SYSTEM_SCAN' : 'QUICK_SYSTEM_SCAN')
            },
            priority: 'high'
          })
        )
      );
      return { commands };
    }
  },

  // Trigger patch management
  runPatchCommand: async (agentIds: string[], action: 'install' | 'check' | 'rollback', patchIds: string[] = []): Promise<any> => {
    try {
      if (action === 'install' && patchIds.length > 0) {
        // Use the new agent action endpoint for patch installation
        const results = await Promise.all(
          agentIds.map(async agentId => {
            const data = { patch_ids: patchIds, agent_id: agentId };
            
            try {
              const response = await apiClient.post('/api/patch-management/install', data);
              return { agent_id: agentId, success: true, data: response.data };
            } catch (error) {
              return { agent_id: agentId, success: false, error: error };
            }
          })
        );
        return { results };
      } else {
        // For check and rollback, fall back to generic commands for now
        const response = await apiClient.post('/api/v1/commands/patch', {
          agent_ids: agentIds,
          action: action,
          patch_ids: patchIds,
          options: {
            auto_reboot: false,
            backup_before_install: true,
            rollback_on_failure: true
          },
          priority: 2
        });
        return response.data;
      }
    } catch (error) {
      // Fallback to generic command creation
      console.warn('Agent action patch management not available, using generic commands');
      const response = await apiClient.post('/api/v1/commands/patch', {
        agent_ids: agentIds,
        action: action,
        patch_ids: patchIds,
        options: {
          auto_reboot: false,
          backup_before_install: true,
          rollback_on_failure: true
        },
        priority: 2
      });
      return response.data;
    }
  },

  // Trigger web blocking
  runWebBlockCommand: async (agentIds: string[], action: 'block' | 'unblock', urls: string[]): Promise<any> => {
    try {
      // Use the new agent action endpoints for web blocking
      const results = await Promise.all(
        urls.flatMap(url => 
          agentIds.map(async agentId => {
            const endpoint = action === 'block' ? '/api/web-blocking/block' : '/api/web-blocking/unblock';
            const data = { url, agent_id: agentId };
            
            try {
              const response = await apiClient.post(endpoint, data);
              return { agent_id: agentId, url, success: true, data: response.data };
            } catch (error) {
              return { agent_id: agentId, url, success: false, error: error };
            }
          })
        )
      );
      return { results };
    } catch (error) {
      // Fallback to generic command creation
      console.warn('Agent action web blocking not available, using generic commands');
      const response = await apiClient.post('/api/v1/commands/web-block', {
        agent_ids: agentIds,
        action: action,
        urls: urls,
        priority: 5
      });
      return response.data;
    }
  },

  // Get system info
  runSystemInfoCommand: async (agentIds: string[]): Promise<any> => {
    try {
      // Use the new agent action endpoint for system status
      const results = await Promise.all(
        agentIds.map(async agentId => {
          try {
            const response = await apiClient.get(`/api/system/status?agent_id=${agentId}`);
            return { agent_id: agentId, success: true, data: response.data };
          } catch (error) {
            return { agent_id: agentId, success: false, error: error };
          }
        })
      );
      return { results };
    } catch (error) {
      // Fallback to generic command creation
      console.warn('Agent action system info not available, using generic commands');
      const response = await apiClient.post('/api/v1/commands/system-info', agentIds);
      return response.data;
    }
  },
};

// Scan Results API
export const scanApi = {
  // Get scan results
  getScanResults: async (params?: {
    page?: number;
    per_page?: number;
    agent_id?: string;
    status?: string;
  }): Promise<PaginatedResponse<any>> => {
    try {
      const response = await apiClient.get('/api/v1/scans', { params });
      return response.data;
    } catch (error) {
      console.warn('Scans API not available, returning empty results');
      return {
        items: [],
        total: 0,
        page: params?.page || 1,
        per_page: params?.per_page || 20,
        pages: 0
      };
    }
  },

  // Get scan status for a specific session
  getScanStatus: async (sessionId: string): Promise<any> => {
    try {
      const response = await apiClient.get(`/api/antivirus/status/${sessionId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch scan status:', error);
      return { success: false, session: {} };
    }
  },

  // Get scan progress for a specific session
  getScanProgress: async (sessionId: string): Promise<any> => {
    try {
      const response = await apiClient.get(`/api/antivirus/scan-progress/${sessionId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch scan progress:', error);
      return { success: false, progress: {} };
    }
  },

  // Get scan logs
  getScanLogs: async (scanId: string): Promise<any> => {
    try {
      const response = await apiClient.get(`/api/v1/scans/${scanId}/logs`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch scan logs:', error);
      return { logs: [] };
    }
  },
};

// Web Blocking API
export const webBlockingApi = {
  // Get blocked URLs from agents
  getBlockedUrls: async (params?: {
    page?: number;
    per_page?: number;
    category?: string;
  }): Promise<PaginatedResponse<any>> => {
    try {
      const response = await apiClient.get('/api/web-blocking/urls', { params });
      
      // Transform the response to match the expected paginated format
      if (response.data && response.data.urls) {
        return {
          items: response.data.urls,
          total: response.data.total || response.data.urls.length,
          page: params?.page || 1,
          per_page: params?.per_page || 20,
          pages: Math.ceil((response.data.total || response.data.urls.length) / (params?.per_page || 20))
        };
      }
      
      return response.data;
    } catch (error) {
      console.warn('Web blocking API not available, using fallback');
      return {
        items: [],
        total: 0,
        page: params?.page || 1,
        per_page: params?.per_page || 20,
        pages: 0
      };
    }
  },

  // Add blocked URL to agents
  addBlockedUrl: async (data: {
    url: string;
    category?: string;
    agent_ids: string[];
  }): Promise<any> => {
    try {
      // Block URL on each specified agent
      const results = await Promise.all(
        data.agent_ids.map(async agentId => {
          try {
            const response = await apiClient.post('/api/web-blocking/block', {
              url: data.url,
              agent_id: agentId
            });
            return { agent_id: agentId, success: true, data: response.data };
          } catch (error) {
            return { agent_id: agentId, success: false, error: error };
          }
        })
      );
      return { results };
    } catch (error) {
      // Fallback to old API
      console.warn('Agent action web blocking not available, using fallback');
      const response = await apiClient.post('/api/v1/web-blocking/urls', data);
      return response.data;
    }
  },

  // Remove blocked URL from agents
  removeBlockedUrl: async (url: string, agentIds: string[]): Promise<any> => {
    try {
      // Unblock URL on each specified agent
      const results = await Promise.all(
        agentIds.map(async agentId => {
          try {
            const response = await apiClient.post('/api/web-blocking/unblock', {
              url: url,
              agent_id: agentId
            });
            return { agent_id: agentId, success: true, data: response.data };
          } catch (error) {
            return { agent_id: agentId, success: false, error: error };
          }
        })
      );
      return { results };
    } catch (error) {
      // Fallback to old API
      console.warn('Agent action web unblocking not available, using fallback');
      const response = await apiClient.delete(`/api/v1/web-blocking/urls/${encodeURIComponent(url)}`, {
        data: { agent_ids: agentIds }
      });
      return response.data;
    }
  },
};

export const scheduleApi = {
  // Get all schedules
  getSchedules: async (params?: {
    page?: number;
    per_page?: number;
    is_active?: boolean;
  }): Promise<PaginatedResponse<Schedule>> => {
    const response = await apiClient.get('/api/v1/schedules', { params });
    return response.data;
  },

  // Create schedule
  createSchedule: async (scheduleData: {
    name: string;
    description?: string;
    command_template: Record<string, any>;
    cron_expression: string;
    target_tags: string[];
    is_active: boolean;
  }): Promise<Schedule> => {
    const response = await apiClient.post('/api/v1/schedules', scheduleData);
    return response.data;
  },

  // Update schedule
  updateSchedule: async (id: string, scheduleData: Partial<Schedule>): Promise<Schedule> => {
    const response = await apiClient.patch(`/api/v1/schedules/${id}`, scheduleData);
    return response.data;
  },

  // Delete schedule
  deleteSchedule: async (id: string): Promise<ApiResponse<null>> => {
    const response = await apiClient.delete(`/api/v1/schedules/${id}`);
    return response.data;
  },

  // Toggle schedule active status
  toggleSchedule: async (id: string, is_active: boolean): Promise<Schedule> => {
    const response = await apiClient.patch(`/api/v1/schedules/${id}`, { is_active });
    return response.data;
  },
};

export const patchApi = {
  // Get all patches
  getPatches: async (params?: {
    page?: number;
    per_page?: number;
    severity?: string;
    category?: string;
    target_os?: string;
  }): Promise<PaginatedResponse<Patch>> => {
    try {
      const response = await apiClient.get('/api/v1/patches', { params });
      return response.data;
    } catch (error) {
      // Fallback to mock data if API is not available
      console.warn('Patches API not available, using mock data');
      return {
        items: [
          {
            id: '1',
            name: 'Windows Security Update KB5028166',
            version: '1.0.0',
            description: 'Critical security update for Windows Defender',
            severity: 'critical' as const,
            category: 'Security',
            target_os: ['windows'],
            file_url: 'https://example.com/patch1.msu',
            file_hash: 'abc123',
            signature: 'def456',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          {
            id: '2', 
            name: 'Office 365 Feature Update',
            version: '2.1.3',
            description: 'Performance improvements and bug fixes',
            severity: 'medium' as const,
            category: 'Feature',
            target_os: ['windows'],
            file_url: 'https://example.com/patch2.msp',
            file_hash: 'ghi789',
            signature: 'jkl012',
            created_at: new Date(Date.now() - 86400000).toISOString(),
            updated_at: new Date(Date.now() - 86400000).toISOString(),
          },
          {
            id: '3',
            name: '.NET Framework Security Update',
            version: '4.8.1',
            description: 'Fixes vulnerabilities in .NET Framework',
            severity: 'high' as const,
            category: 'Security',
            target_os: ['windows'],
            file_url: 'https://example.com/patch3.exe',
            file_hash: 'mno345',
            signature: 'pqr678',
            created_at: new Date(Date.now() - 172800000).toISOString(),
            updated_at: new Date(Date.now() - 172800000).toISOString(),
          }
        ],
        total: 3,
        page: params?.page || 1,
        per_page: params?.per_page || 20,
        pages: 1
      };
    }
  },

  // Get patch management info from agents
  getPatchInfo: async (agentId?: string): Promise<any> => {
    try {
      const url = agentId 
        ? `/api/patch-management/info?agent_id=${agentId}`
        : '/api/patch-management/info';
      const response = await apiClient.get(url);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch patch info:', error);
      return {
        success: false,
        pending_count: 0,
        installed_patches: [],
        pending_updates: [],
        update_history: []
      };
    }
  },

  // Create patch rollout
  createRollout: async (rolloutData: {
    patch_id: string;
    name: string;
    target_tags: string[];
    rollout_strategy: string;
    canary_percentage?: number;
    phase_delay_hours?: number;
  }): Promise<PatchRollout> => {
    const response = await apiClient.post('/api/v1/patch-rollouts', rolloutData);
    return response.data;
  },

  // Get rollouts
  getRollouts: async (params?: {
    page?: number;
    per_page?: number;
    status?: string;
  }): Promise<PaginatedResponse<PatchRollout>> => {
    const response = await apiClient.get('/api/v1/patch-rollouts', { params });
    return response.data;
  },

  // Control rollout (pause, resume, cancel)
  controlRollout: async (id: string, action: 'pause' | 'resume' | 'cancel'): Promise<PatchRollout> => {
    const response = await apiClient.post(`/api/v1/patch-rollouts/${id}/${action}`);
    return response.data;
  },

  // Get patches for specific agent
  getAgentPatches: async (agentId: string, params?: {
    page?: number;
    per_page?: number;
  }): Promise<PaginatedResponse<Patch>> => {
    const response = await apiClient.get(`/api/v1/agents/${agentId}/patches`, { params });
    return response.data;
  },

  // Pause rollout
  pauseRollout: async (id: string): Promise<PatchRollout> => {
    const response = await apiClient.post(`/api/v1/patch-rollouts/${id}/pause`);
    return response.data;
  },

  // Resume rollout
  resumeRollout: async (id: string): Promise<PatchRollout> => {
    const response = await apiClient.post(`/api/v1/patch-rollouts/${id}/resume`);
    return response.data;
  },

  // Rollback rollout
  rollbackRollout: async (id: string): Promise<PatchRollout> => {
    const response = await apiClient.post(`/api/v1/patch-rollouts/${id}/rollback`);
    return response.data;
  },
};

export const systemApi = {
  // Get system health
  getHealth: async (): Promise<any> => {
    const response = await apiClient.get('/health');
    return response.data;
  },

  // Get system metrics
  getMetrics: async (): Promise<any> => {
    const response = await apiClient.get('/api/v1/metrics');
    return response.data;
  },

  // Get system statistics for UI
  getStats: async (): Promise<{
    total_agents: number;
    active_agents: number;
    pending_commands: number;
    recent_threats: number;
    system_health: string;
  }> => {
    try {
      const response = await apiClient.get('/api/v1/ui/system/stats');
      console.log('System stats API response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch system stats:', error);
      // Return fallback data
      return {
        total_agents: 0,
        active_agents: 0,
        pending_commands: 0,
        recent_threats: 0,
        system_health: 'unknown'
      };
    }
  },
};

export const eventApi = {
  // Get events
  getEvents: async (params?: {
    page?: number;
    per_page?: number;
    level?: string;
    source?: string;
    search?: string;
  }): Promise<PaginatedResponse<Event>> => {
    const response = await apiClient.get('/api/v1/events', { params });
    return response.data;
  },
};

export default apiClient;