import { io, Socket } from 'socket.io-client';
import { WebSocketMessage } from '../types';

class WebSocketService {
  private socket: Socket | null = null;
  private listeners: Map<string, Set<(data: any) => void>> = new Map();

  connect(url: string = 'http://localhost:8000') {
    if (this.socket?.connected) {
      return;
    }

    this.socket = io(url, {
      transports: ['websocket'],
      autoConnect: true,
    });

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
    });

    this.socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
    });

    this.socket.on('message', (message: WebSocketMessage) => {
      this.handleMessage(message);
    });

    this.socket.on('agent_status', (data) => {
      this.notifyListeners('agent_status', data);
    });

    this.socket.on('command_update', (data) => {
      this.notifyListeners('command_update', data);
    });

    this.socket.on('event', (data) => {
      this.notifyListeners('event', data);
    });

    this.socket.on('patch_rollout_update', (data) => {
      this.notifyListeners('patch_rollout_update', data);
    });

    this.socket.on('agents_update', (data) => {
      this.notifyListeners('agents_update', data);
    });

    this.socket.on('system_event', (data) => {
      this.notifyListeners('system_event', data);
    });

    // Additional event types for enhanced functionality
    this.socket.on('agent_connected', (data) => {
      this.notifyListeners('agent_connected', data);
    });

    this.socket.on('agent_disconnected', (data) => {
      this.notifyListeners('agent_disconnected', data);
    });

    this.socket.on('scan_update', (data) => {
      this.notifyListeners('scan_update', data);
    });

    this.socket.on('scan_logs', (data) => {
      this.notifyListeners('scan_logs', data);
    });

    this.socket.on('web_block_update', (data) => {
      this.notifyListeners('web_block_update', data);
    });

    this.socket.on('rollout_progress', (data) => {
      this.notifyListeners('rollout_progress', data);
    });

    this.socket.on('new_event', (data) => {
      this.notifyListeners('new_event', data);
    });

    this.socket.on('manager_action', (data) => {
      this.notifyListeners('manager_action', data);
    });
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  subscribe(eventType: string, callback: (data: any) => void) {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(callback);

    // Return unsubscribe function
    return () => {
      const eventListeners = this.listeners.get(eventType);
      if (eventListeners) {
        eventListeners.delete(callback);
        if (eventListeners.size === 0) {
          this.listeners.delete(eventType);
        }
      }
    };
  }

  private handleMessage(message: WebSocketMessage) {
    this.notifyListeners(message.type, message.data);
  }

  private notifyListeners(eventType: string, data: any) {
    const eventListeners = this.listeners.get(eventType);
    if (eventListeners) {
      eventListeners.forEach(callback => callback(data));
    }
  }

  isConnected(): boolean {
    return this.socket?.connected || false;
  }
}

export const webSocketService = new WebSocketService();
export default webSocketService;