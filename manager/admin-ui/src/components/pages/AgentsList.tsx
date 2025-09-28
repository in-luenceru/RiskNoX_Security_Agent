import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Search, Filter, Shield, Clock, Tag } from 'lucide-react';
import { agentApi } from '../../services/api';
import { Agent } from '../../types';
import webSocketService from '../../services/websocket';

const AgentsList: React.FC = () => {
  const [search, setSearch] = React.useState('');
  const [statusFilter, setStatusFilter] = React.useState<string>('');
  const [tagFilter, setTagFilter] = React.useState<string>('');
  const [page, setPage] = React.useState(1);

  // Query for agents
  const { data: agentsData, refetch } = useQuery({
    queryKey: ['agents', { page, search, status: statusFilter, tags: tagFilter ? [tagFilter] : undefined }],
    queryFn: () => agentApi.getAgents({
      page,
      per_page: 20,
      search: search || undefined,
      status: statusFilter || undefined,
      tags: tagFilter ? [tagFilter] : undefined,
    }),
  });

  // Subscribe to real-time updates
  React.useEffect(() => {
    const unsubscribe = webSocketService.subscribe('agent_status', (data) => {
      console.log('Agent status update:', data);
      refetch();
    });

    return unsubscribe;
  }, [refetch]);

  const agents = agentsData?.items || [];
  const totalPages = agentsData?.pages || 1;

  const getStatusBadge = (status: Agent['status']) => {
    const styles = {
      online: 'bg-success-100 text-success-800',
      offline: 'bg-gray-100 text-gray-800', 
      error: 'bg-danger-100 text-danger-800',
    };
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[status]}`}>
        {status}
      </span>
    );
  };

  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return `${Math.floor(diffMins / 1440)}d ago`;
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Agents</h1>
        <p className="mt-2 text-gray-600">Manage and monitor your security agents</p>
      </div>

      {/* Filters and Search */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-gray-400" />
            </div>
            <input
              type="text"
              placeholder="Search agents..."
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-primary-500 focus:border-primary-500"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          {/* Status Filter */}
          <div>
            <select
              className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Status</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="error">Error</option>
            </select>
          </div>

          {/* Tag Filter */}
          <div>
            <input
              type="text"
              placeholder="Filter by tag..."
              className="block w-full px-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-primary-500 focus:border-primary-500"
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
            />
          </div>

          {/* Clear Filters */}
          <div>
            <button
              onClick={() => {
                setSearch('');
                setStatusFilter('');
                setTagFilter('');
                setPage(1);
              }}
              className="w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Filter className="h-4 w-4 mr-2" />
              Clear
            </button>
          </div>
        </div>
      </div>

      {/* Agents Table */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {agents.map((agent) => (
            <li key={agent.id}>
              <Link
                to={`/agents/${agent.id}`}
                className="block hover:bg-gray-50 px-4 py-4 sm:px-6"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <Shield className="h-10 w-10 text-gray-400" />
                    </div>
                    <div className="ml-4">
                      <div className="flex items-center">
                        <p className="text-sm font-medium text-primary-600 truncate">
                          {agent.hostname}
                        </p>
                        <div className="ml-2">
                          {getStatusBadge(agent.status)}
                        </div>
                      </div>
                      <div className="mt-1 flex items-center text-sm text-gray-500">
                        <p>{agent.ip_address}</p>
                        <span className="mx-2">•</span>
                        <p>{agent.os_info}</p>
                        <span className="mx-2">•</span>
                        <p>v{agent.agent_version}</p>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    {/* Tags */}
                    {agent.tags.length > 0 && (
                      <div className="flex items-center space-x-1">
                        <Tag className="h-4 w-4 text-gray-400" />
                        <div className="flex space-x-1">
                          {agent.tags.slice(0, 3).map((tag) => (
                            <span
                              key={tag}
                              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-100 text-primary-800"
                            >
                              {tag}
                            </span>
                          ))}
                          {agent.tags.length > 3 && (
                            <span className="text-xs text-gray-500">
                              +{agent.tags.length - 3} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {/* Last Seen */}
                    <div className="flex items-center text-sm text-gray-500">
                      <Clock className="h-4 w-4 mr-1" />
                      {formatLastSeen(agent.last_seen)}
                    </div>
                  </div>
                </div>
              </Link>
            </li>
          ))}
        </ul>

        {/* Empty State */}
        {agents.length === 0 && (
          <div className="text-center py-12">
            <Shield className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No agents found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {search || statusFilter || tagFilter
                ? 'Try adjusting your search or filter criteria'
                : 'Agents will appear here once they enroll with the manager'}
            </p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-6 flex items-center justify-between">
          <div className="flex-1 flex justify-between sm:hidden">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
          <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
              <p className="text-sm text-gray-700">
                Showing page <span className="font-medium">{page}</span> of{' '}
                <span className="font-medium">{totalPages}</span>
              </p>
            </div>
            <div>
              <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px">
                <button
                  onClick={() => setPage(Math.max(1, page - 1))}
                  disabled={page === 1}
                  className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(Math.min(totalPages, page + 1))}
                  disabled={page === totalPages}
                  className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </nav>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentsList;