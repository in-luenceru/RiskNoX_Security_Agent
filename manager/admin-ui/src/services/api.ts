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
    const response = await apiClient.get('/api/v1/ui/agents', { params });
    return response.data;
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
  runScan: async (agentId: string, scanType: 'quick' | 'full'): Promise<Command> => {
    const response = await apiClient.post('/api/v1/commands', {
      agent_id: agentId,
      command_type: scanType === 'quick' ? 'quick_scan' : 'full_scan',
      command_data: { scan_type: scanType },
    });
    return response.data;
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
    const response = await apiClient.get('/api/v1/patches', { params });
    return response.data;
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
    const response = await apiClient.get('/api/v1/ui/system/stats');
    return response.data;
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