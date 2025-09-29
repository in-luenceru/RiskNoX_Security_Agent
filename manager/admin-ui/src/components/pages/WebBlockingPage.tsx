import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Globe, Plus, Trash2, Shield, AlertTriangle } from 'lucide-react';
import { agentApi, commandApi, webBlockingApi } from '../../services/api';

interface BlockedUrl {
  id: string;
  url: string;
  category: string;
  added_at: string;
  blocked_count: number;
}

const WebBlockingPage: React.FC = () => {
  const [newUrl, setNewUrl] = React.useState('');
  const [newCategory, setNewCategory] = React.useState('malicious');
  const [selectedAgents, setSelectedAgents] = React.useState<string[]>([]);
  const queryClient = useQueryClient();

  // Get agents
  const { data: agentsData } = useQuery({
    queryKey: ['agents', { per_page: 1000 }],
    queryFn: () => agentApi.getAgents({ per_page: 1000 }),
  });

  // Get real blocked URLs data from API
  const { data: blockedUrls, refetch: refetchBlockedUrls } = useQuery<BlockedUrl[]>({
    queryKey: ['blocked-urls'],
    queryFn: async () => {
      try {
        console.log('Fetching blocked URLs from API...');
        const response = await webBlockingApi.getBlockedUrls({ per_page: 100 });
        console.log('Blocked URLs API response:', response);
        return response.items || [];
      } catch (error) {
        console.error('Failed to fetch blocked URLs:', error);
        // Return empty array instead of mock data to show real state
        return [];
      }
    },
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Block URL mutation
  const blockUrlMutation = useMutation({
    mutationFn: async ({ url, category, agentIds }: { url: string; category: string; agentIds: string[] }) => {
      // First add to blocked URLs list
      await webBlockingApi.addBlockedUrl({ url, category, agent_ids: agentIds });
      // Then send command to agents
      return commandApi.runWebBlockCommand(agentIds, 'block', [url]);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocked-urls'] });
      refetchBlockedUrls();
      setNewUrl('');
      setSelectedAgents([]);
    },
  });

  // Unblock URL mutation
  const unblockUrlMutation = useMutation({
    mutationFn: async ({ urlId, url, agentIds }: { urlId: string; url: string; agentIds: string[] }) => {
      // Send unblock command to agents
      await commandApi.runWebBlockCommand(agentIds, 'unblock', [url]);
      // Then remove from blocked URLs list
      return webBlockingApi.removeBlockedUrl(urlId, agentIds);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocked-urls'] });
      refetchBlockedUrls();
    },
  });

  const agents = agentsData?.items || [];

  const handleBlockUrl = () => {
    if (!newUrl.trim() || selectedAgents.length === 0) return;
    blockUrlMutation.mutate({ 
      url: newUrl.trim(), 
      category: newCategory,
      agentIds: selectedAgents 
    });
  };

  const handleUnblockUrl = (blockedUrl: BlockedUrl) => {
    if (selectedAgents.length === 0) {
      alert('Please select agents first');
      return;
    }
    unblockUrlMutation.mutate({ 
      urlId: blockedUrl.id,
      url: blockedUrl.url, 
      agentIds: selectedAgents 
    });
  };

  const getCategoryBadge = (category: string) => {
    const styles = {
      malicious: 'bg-red-100 text-red-800',
      phishing: 'bg-orange-100 text-orange-800',
      gambling: 'bg-yellow-100 text-yellow-800',
      adult: 'bg-purple-100 text-purple-800',
      social: 'bg-blue-100 text-blue-800',
      other: 'bg-gray-100 text-gray-800',
    };
    
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[category as keyof typeof styles] || styles.other}`}>
        {category}
      </span>
    );
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Web Blocking</h1>
        <p className="mt-2 text-gray-600">Manage web content filtering and URL blocking</p>
      </div>

      {/* Add New Block */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          <Plus className="inline-block w-5 h-5 mr-2" />
          Block New URL
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                URL to Block
              </label>
              <input
                type="text"
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                placeholder="e.g., malicious-site.com"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Category
              </label>
              <select
                className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
              >
                <option value="malicious">Malicious</option>
                <option value="phishing">Phishing</option>
                <option value="gambling">Gambling</option>
                <option value="adult">Adult Content</option>
                <option value="social">Social Media</option>
                <option value="other">Other</option>
              </select>
            </div>
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

        <div className="mt-4">
          <button
            onClick={handleBlockUrl}
            disabled={!newUrl.trim() || selectedAgents.length === 0 || blockUrlMutation.isPending}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 disabled:bg-gray-400"
          >
            <Shield className="inline-block w-4 h-4 mr-2" />
            {blockUrlMutation.isPending ? 'Blocking...' : 'Block URL'}
          </button>
        </div>
      </div>

      {/* Blocked URLs List */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            <Globe className="inline-block w-5 h-5 mr-2" />
            Blocked URLs
          </h2>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  URL
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Category
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Blocked Count
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Added
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {blockedUrls?.map((blockedUrl) => (
                <tr key={blockedUrl.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <AlertTriangle className="w-4 h-4 text-red-500 mr-2" />
                      <span className="text-sm font-medium text-gray-900">
                        {blockedUrl.url}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getCategoryBadge(blockedUrl.category)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {blockedUrl.blocked_count}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(blockedUrl.added_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleUnblockUrl(blockedUrl)}
                      disabled={selectedAgents.length === 0 || unblockUrlMutation.isPending}
                      className="text-red-600 hover:text-red-900 disabled:text-gray-400 mr-2"
                      title="Unblock URL"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {(!blockedUrls || blockedUrls.length === 0) && (
          <div className="text-center py-8">
            <Globe className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No blocked URLs</h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by blocking your first URL.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default WebBlockingPage;