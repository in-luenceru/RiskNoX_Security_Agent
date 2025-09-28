export interface Agent {
  id: string;
  hostname: string;
  ip_address: string;
  os_info: string;
  agent_version: string;
  status: 'online' | 'offline' | 'error';
  last_seen: string;
  tags: string[];
  certificate_status: 'valid' | 'expired' | 'revoked';
  agent_metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
  architecture?: string;
  enrolled_at?: string;
  last_scan?: string;
}

export interface Command {
  id: string;
  agent_id: string;
  command_type: 'scan' | 'patch' | 'config' | 'custom';
  command_data: Record<string, any>;
  status: 'pending' | 'sent' | 'acknowledged' | 'running' | 'completed' | 'failed' | 'expired';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  created_by: string;
  created_at: string;
  sent_at?: string;
  completed_at?: string;
  response_data?: Record<string, any>;
  signature?: string;
  progress?: number;
  result?: string;
}

export interface Schedule {
  id: string;
  name: string;
  description?: string;
  command_template: Record<string, any>;
  cron_expression: string;
  target_tags: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_run?: string;
  next_run: string;
  command_type?: string;
  enabled?: boolean; // for backwards compatibility
}

export interface Patch {
  id: string;
  name: string;
  version: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  target_os: string[];
  file_url: string;
  file_hash: string;
  signature: string;
  created_at: string;
  updated_at: string;
  status?: 'pending' | 'deployed' | 'failed' | 'rollback' | 'installed';
  patch_id?: string;
  installed_at?: string;
}

export interface PatchRollout {
  id: string;
  patch_id?: string;
  patches: Patch[];
  name: string;
  target_tags: string[];
  strategy: 'immediate' | 'canary' | 'phased';
  rollout_strategy?: 'immediate' | 'canary' | 'phased'; // backwards compatibility
  canary_percentage: number;
  canary_size: number;
  canary_completed: number;
  canary_wait_time: number;
  phase_delay_hours?: number;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'rolling_back' | 'rolled_back';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  success_count: number;
  failure_count: number;
  total_targets: number;
  total_agents: number;
  completed_agents: number;
  progress: number;
  success_rate?: number;
  success_threshold: number;
  rollback_on_failure: boolean;
  auto_promote: boolean;
}

export interface Event {
  id: string;
  agent_id?: string;
  event_type: string;
  event_data?: Record<string, any>;
  level: 'info' | 'warning' | 'error' | 'success';
  source: string;
  message: string;
  details?: string | Record<string, any>;
  timestamp: string;
  created_at: string;
  user_id?: string;
  command_id?: string;
  scan_id?: string;
}

export interface ApiResponse<T> {
  data: T;
  message?: string;
  status: 'success' | 'error';
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

export interface WebSocketMessage {
  type: 'agent_status' | 'command_update' | 'event' | 'patch_rollout_update';
  data: any;
  timestamp: string;
}