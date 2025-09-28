import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Package, 
  Play, 
  Pause, 
  RotateCcw, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Users,
  TrendingUp,
  Plus
} from 'lucide-react';
import { patchApi } from '../../services/api';
import { PatchRollout } from '../../types';
import webSocketService from '../../services/websocket';

const PatchRolloutPage: React.FC = () => {
  const [modalOpen, setModalOpen] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const queryClient = useQueryClient();

  // Query for rollouts
  const { data: rolloutsData, refetch } = useQuery({
    queryKey: ['patch-rollouts', { page }],
    queryFn: () => patchApi.getRollouts({ page, per_page: 20 }),
  });

  // Subscribe to real-time updates
  React.useEffect(() => {
    const unsubscribe = webSocketService.subscribe('rollout_progress', (data) => {
      console.log('Rollout progress update:', data);
      refetch();
    });

    return unsubscribe;
  }, [refetch]);

  // Mutations
  const pauseMutation = useMutation({
    mutationFn: patchApi.pauseRollout,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['patch-rollouts'] });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: patchApi.resumeRollout,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['patch-rollouts'] });
    },
  });

  const rollbackMutation = useMutation({
    mutationFn: patchApi.rollbackRollout,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['patch-rollouts'] });
    },
  });

  const rollouts = rolloutsData?.items || [];
  const totalPages = rolloutsData?.pages || 1;

  const getStatusIcon = (status: PatchRollout['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-success-500" />;
      case 'failed':
        return <AlertTriangle className="h-5 w-5 text-danger-500" />;
      case 'paused':
        return <Pause className="h-5 w-5 text-warning-500" />;
      case 'rolling_back':
        return <RotateCcw className="h-5 w-5 text-warning-500 animate-spin" />;
      case 'rolled_back':
        return <RotateCcw className="h-5 w-5 text-gray-500" />;
      case 'running':
        return <Play className="h-5 w-5 text-primary-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: PatchRollout['status']) => {
    switch (status) {
      case 'completed':
        return 'bg-success-100 text-success-800';
      case 'failed':
        return 'bg-danger-100 text-danger-800';
      case 'paused':
        return 'bg-warning-100 text-warning-800';
      case 'rolling_back':
      case 'rolled_back':
        return 'bg-gray-100 text-gray-800';
      case 'running':
        return 'bg-primary-100 text-primary-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const handlePause = async (id: string) => {
    await pauseMutation.mutateAsync(id);
  };

  const handleResume = async (id: string) => {
    await resumeMutation.mutateAsync(id);
  };

  const handleRollback = async (id: string) => {
    if (window.confirm('Are you sure you want to rollback this deployment? This action cannot be undone.')) {
      await rollbackMutation.mutateAsync(id);
    }
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Patch Rollouts</h1>
            <p className="mt-2 text-gray-600">Monitor and control patch deployments with canary releases</p>
          </div>
          <button
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <Plus className="h-4 w-4 mr-2" />
            New Rollout
          </button>
        </div>
      </div>

      {/* Rollouts List */}
      <div className="space-y-6">
        {rollouts.map((rollout) => (
          <div key={rollout.id} className="bg-white rounded-lg shadow-sm border border-gray-200">
            <div className="p-6">
              {/* Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {getStatusIcon(rollout.status)}
                  <div>
                    <h3 className="text-lg font-medium text-gray-900">
                      {rollout.name}
                    </h3>
                    <p className="text-sm text-gray-500">
                      {rollout.patches.length} patches • Started {new Date(rollout.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(rollout.status)}`}>
                    {rollout.status.replace('_', ' ')}
                  </span>
                  
                  {/* Action Buttons */}
                  <div className="flex space-x-2">
                    {rollout.status === 'running' && (
                      <button
                        onClick={() => handlePause(rollout.id)}
                        disabled={pauseMutation.isPending}
                        className="inline-flex items-center p-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                      >
                        <Pause className="h-4 w-4" />
                      </button>
                    )}
                    
                    {rollout.status === 'paused' && (
                      <button
                        onClick={() => handleResume(rollout.id)}
                        disabled={resumeMutation.isPending}
                        className="inline-flex items-center p-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                      >
                        <Play className="h-4 w-4" />
                      </button>
                    )}
                    
                    {(rollout.status === 'running' || rollout.status === 'paused') && (
                      <button
                        onClick={() => handleRollback(rollout.id)}
                        disabled={rollbackMutation.isPending}
                        className="inline-flex items-center p-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger-500"
                      >
                        <RotateCcw className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mb-4">
                <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                  <span>Overall Progress</span>
                  <span>{Math.round(rollout.progress)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full transition-all duration-300 ${
                      rollout.status === 'failed' ? 'bg-danger-500' :
                      rollout.status === 'completed' ? 'bg-success-500' :
                      'bg-primary-500'
                    }`}
                    style={{ width: `${rollout.progress}%` }}
                  />
                </div>
              </div>

              {/* Canary Phases */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Users className="h-4 w-4 text-gray-500" />
                    <span className="text-sm font-medium text-gray-700">Canary Phase</span>
                  </div>
                  <div className="text-lg font-semibold text-gray-900">
                    {rollout.canary_completed || 0} / {rollout.canary_size}
                  </div>
                  <div className="text-sm text-gray-500">
                    {rollout.canary_percentage}% of total agents
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <TrendingUp className="h-4 w-4 text-gray-500" />
                    <span className="text-sm font-medium text-gray-700">Success Rate</span>
                  </div>
                  <div className="text-lg font-semibold text-gray-900">
                    {rollout.success_rate !== undefined ? `${Math.round(rollout.success_rate)}%` : 'N/A'}
                  </div>
                  <div className="text-sm text-gray-500">
                    Current phase
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center space-x-2 mb-2">
                    <Package className="h-4 w-4 text-gray-500" />
                    <span className="text-sm font-medium text-gray-700">Total Agents</span>
                  </div>
                  <div className="text-lg font-semibold text-gray-900">
                    {rollout.completed_agents} / {rollout.total_agents}
                  </div>
                  <div className="text-sm text-gray-500">
                    Across all phases
                  </div>
                </div>
              </div>

              {/* Patches */}
              <div>
                <h4 className="text-sm font-medium text-gray-700 mb-2">Patches in this rollout:</h4>
                <div className="flex flex-wrap gap-2">
                  {rollout.patches.map((patch) => (
                    <span
                      key={patch.id}
                      className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                    >
                      {patch.patch_id}
                    </span>
                  ))}
                </div>
              </div>

              {/* Strategy Info */}
              <div className="mt-4 text-sm text-gray-500">
                <span className="capitalize">{rollout.strategy}</span> deployment strategy
                {rollout.auto_promote && (
                  <span> • Auto-promote after {rollout.canary_wait_time} minutes</span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Empty State */}
      {rollouts.length === 0 && (
        <div className="text-center py-12">
          <Package className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No patch rollouts</h3>
          <p className="mt-1 text-sm text-gray-500">
            Get started by creating your first canary deployment.
          </p>
          <div className="mt-6">
            <button
              onClick={() => setModalOpen(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Plus className="h-4 w-4 mr-2" />
              New Rollout
            </button>
          </div>
        </div>
      )}

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

      {/* New Rollout Modal */}
      {modalOpen && (
        <RolloutModal
          onClose={() => setModalOpen(false)}
          onSave={() => {
            setModalOpen(false);
            queryClient.invalidateQueries({ queryKey: ['patch-rollouts'] });
          }}
        />
      )}
    </div>
  );
};

// Rollout Modal Component
interface RolloutModalProps {
  onClose: () => void;
  onSave: () => void;
}

const RolloutModal: React.FC<RolloutModalProps> = ({ onClose, onSave }) => {
  const [formData, setFormData] = React.useState({
    name: '',
    patches: [] as string[],
    target_tags: '',
    strategy: 'canary',
    canary_percentage: 10,
    canary_wait_time: 30,
    success_threshold: 95,
    rollback_on_failure: true,
    auto_promote: false,
  });

  const createMutation = useMutation({
    mutationFn: patchApi.createRollout,
    onSuccess: () => {
      onSave();
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate({
      patch_id: formData.patches[0] || '', // Use first patch as patch_id
      name: formData.name,
      target_tags: formData.target_tags.split(',').map(tag => tag.trim()).filter(Boolean),
      rollout_strategy: formData.strategy,
      canary_percentage: formData.canary_percentage,
    });
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-[500px] shadow-lg rounded-md bg-white">
        <div className="mt-3">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Create New Patch Rollout
          </h3>
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Name</label>
              <input
                type="text"
                required
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Target Tags (comma-separated)</label>
              <input
                type="text"
                required
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                placeholder="production, servers, critical"
                value={formData.target_tags}
                onChange={(e) => setFormData({ ...formData, target_tags: e.target.value })}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Canary Percentage</label>
                <input
                  type="number"
                  min="1"
                  max="50"
                  className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                  value={formData.canary_percentage}
                  onChange={(e) => setFormData({ ...formData, canary_percentage: parseInt(e.target.value) })}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Wait Time (minutes)</label>
                <input
                  type="number"
                  min="5"
                  max="1440"
                  className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                  value={formData.canary_wait_time}
                  onChange={(e) => setFormData({ ...formData, canary_wait_time: parseInt(e.target.value) })}
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Success Threshold (%)</label>
              <input
                type="number"
                min="50"
                max="100"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                value={formData.success_threshold}
                onChange={(e) => setFormData({ ...formData, success_threshold: parseInt(e.target.value) })}
              />
            </div>

            <div className="space-y-3">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="rollback_on_failure"
                  className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  checked={formData.rollback_on_failure}
                  onChange={(e) => setFormData({ ...formData, rollback_on_failure: e.target.checked })}
                />
                <label htmlFor="rollback_on_failure" className="ml-2 block text-sm text-gray-900">
                  Auto-rollback on failure
                </label>
              </div>

              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="auto_promote"
                  className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  checked={formData.auto_promote}
                  onChange={(e) => setFormData({ ...formData, auto_promote: e.target.checked })}
                />
                <label htmlFor="auto_promote" className="ml-2 block text-sm text-gray-900">
                  Auto-promote to full deployment
                </label>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createMutation.isPending}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
              >
                {createMutation.isPending ? 'Creating...' : 'Create Rollout'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default PatchRolloutPage;