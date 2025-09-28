import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  XCircle,
  Filter,
  Calendar,
  User,
  Tag
} from 'lucide-react';
import { eventApi } from '../../services/api';
import { Event } from '../../types';
import webSocketService from '../../services/websocket';

const EventsPage: React.FC = () => {
  const [filters, setFilters] = React.useState({
    level: '',
    source: '',
    search: '',
    page: 1,
  });

  // Query for events
  const { data: eventsData, refetch } = useQuery({
    queryKey: ['events', filters],
    queryFn: () => eventApi.getEvents({
      page: filters.page,
      per_page: 50,
      level: filters.level || undefined,
      source: filters.source || undefined,
      search: filters.search || undefined,
    }),
  });

  // Subscribe to real-time events
  React.useEffect(() => {
    const unsubscribe = webSocketService.subscribe('new_event', (data) => {
      console.log('New event received:', data);
      refetch();
    });

    return unsubscribe;
  }, [refetch]);

  const events = eventsData?.items || [];
  const totalPages = eventsData?.pages || 1;

  const getLevelIcon = (level: Event['level']) => {
    switch (level) {
      case 'error':
        return <XCircle className="h-5 w-5 text-danger-500" />;
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-warning-500" />;
      case 'success':
        return <CheckCircle className="h-5 w-5 text-success-500" />;
      case 'info':
      default:
        return <Info className="h-5 w-5 text-primary-500" />;
    }
  };

  const getLevelColor = (level: Event['level']) => {
    switch (level) {
      case 'error':
        return 'bg-danger-100 text-danger-800 border-danger-200';
      case 'warning':
        return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'success':
        return 'bg-success-100 text-success-800 border-success-200';
      case 'info':
      default:
        return 'bg-primary-100 text-primary-800 border-primary-200';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    if (diffMins < 10080) return `${Math.floor(diffMins / 1440)}d ago`;
    
    return date.toLocaleDateString();
  };

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: 1, // Reset to first page when filtering
    }));
  };

  const clearFilters = () => {
    setFilters({
      level: '',
      source: '',
      search: '',
      page: 1,
    });
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">System Events</h1>
        <p className="mt-2 text-gray-600">Monitor real-time system activities and alerts</p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search events..."
              className="block w-full pr-10 pl-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-primary-500 focus:border-primary-500"
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
            />
          </div>

          {/* Level Filter */}
          <div>
            <select
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
              value={filters.level}
              onChange={(e) => handleFilterChange('level', e.target.value)}
            >
              <option value="">All Levels</option>
              <option value="error">Error</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="success">Success</option>
            </select>
          </div>

          {/* Source Filter */}
          <div>
            <select
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
              value={filters.source}
              onChange={(e) => handleFilterChange('source', e.target.value)}
            >
              <option value="">All Sources</option>
              <option value="agent">Agent</option>
              <option value="manager">Manager</option>
              <option value="scanner">Scanner</option>
              <option value="patch_system">Patch System</option>
            </select>
          </div>

          {/* Clear Filters */}
          <div>
            <button
              onClick={clearFilters}
              className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Filter className="h-4 w-4 mr-2" />
              Clear
            </button>
          </div>
        </div>
      </div>

      {/* Events List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {events.map((event) => (
            <li key={event.id} className="px-6 py-4">
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 mt-1">
                  {getLevelIcon(event.level)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getLevelColor(event.level)}`}>
                        {event.level}
                      </span>
                      <span className="text-sm text-gray-500 capitalize">
                        {event.source}
                      </span>
                      {event.agent_id && (
                        <span className="text-sm text-gray-500">
                          Agent: {event.agent_id}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-gray-500">
                      <Calendar className="h-4 w-4" />
                      <span>{formatTimestamp(event.timestamp)}</span>
                    </div>
                  </div>
                  
                  <div className="mt-2">
                    <p className="text-sm font-medium text-gray-900">
                      {event.message}
                    </p>
                    {event.details && (
                      <div className="mt-2 text-sm text-gray-600">
                        <details className="group">
                          <summary className="cursor-pointer hover:text-gray-800 select-none">
                            View details
                          </summary>
                          <div className="mt-2 p-3 bg-gray-50 rounded-md">
                            <pre className="text-xs overflow-x-auto whitespace-pre-wrap">
                              {typeof event.details === 'string' 
                                ? event.details 
                                : JSON.stringify(event.details, null, 2)
                              }
                            </pre>
                          </div>
                        </details>
                      </div>
                    )}
                  </div>

                  {/* Metadata */}
                  {(event.user_id || event.command_id || event.scan_id) && (
                    <div className="mt-3 flex items-center space-x-4 text-xs text-gray-500">
                      {event.user_id && (
                        <div className="flex items-center space-x-1">
                          <User className="h-3 w-3" />
                          <span>User: {event.user_id}</span>
                        </div>
                      )}
                      {event.command_id && (
                        <div className="flex items-center space-x-1">
                          <Tag className="h-3 w-3" />
                          <span>Command: {event.command_id}</span>
                        </div>
                      )}
                      {event.scan_id && (
                        <div className="flex items-center space-x-1">
                          <Activity className="h-3 w-3" />
                          <span>Scan: {event.scan_id}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>

        {/* Empty State */}
        {events.length === 0 && (
          <div className="text-center py-12">
            <Activity className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No events found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {filters.search || filters.level || filters.source
                ? 'Try adjusting your search or filter criteria'
                : 'Events will appear here as they occur in the system'}
            </p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-6 flex items-center justify-between">
          <div className="flex-1 flex justify-between sm:hidden">
            <button
              onClick={() => handleFilterChange('page', Math.max(1, filters.page - 1).toString())}
              disabled={filters.page === 1}
              className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              onClick={() => handleFilterChange('page', Math.min(totalPages, filters.page + 1).toString())}
              disabled={filters.page === totalPages}
              className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
          <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
              <p className="text-sm text-gray-700">
                Showing page <span className="font-medium">{filters.page}</span> of{' '}
                <span className="font-medium">{totalPages}</span>
              </p>
            </div>
            <div>
              <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                <button
                  onClick={() => handleFilterChange('page', Math.max(1, filters.page - 1).toString())}
                  disabled={filters.page === 1}
                  className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <button
                  onClick={() => handleFilterChange('page', Math.min(totalPages, filters.page + 1).toString())}
                  disabled={filters.page === totalPages}
                  className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </nav>
            </div>
          </div>
        </div>
      )}

      {/* Live Update Indicator */}
      <div className="fixed bottom-4 right-4">
        <div className="bg-green-500 text-white px-3 py-2 rounded-full shadow-lg flex items-center space-x-2">
          <div className="w-2 h-2 bg-white rounded-full animate-pulse"></div>
          <span className="text-sm font-medium">Live Updates</span>
        </div>
      </div>
    </div>
  );
};

export default EventsPage;