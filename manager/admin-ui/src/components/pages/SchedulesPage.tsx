import React from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Calendar, Plus, Edit2, Trash2, Clock, Tag } from 'lucide-react';
import { scheduleApi } from '../../services/api';
import { Schedule } from '../../types';

const SchedulesPage: React.FC = () => {
  const [modalOpen, setModalOpen] = React.useState(false);
  const [editingSchedule, setEditingSchedule] = React.useState<Schedule | null>(null);
  const [page, setPage] = React.useState(1);
  const queryClient = useQueryClient();

  // Query for schedules
  const { data: schedulesData } = useQuery({
    queryKey: ['schedules', { page }],
    queryFn: () => scheduleApi.getSchedules({ page, per_page: 20 }),
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: scheduleApi.createSchedule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      setModalOpen(false);
      setEditingSchedule(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Schedule> }) =>
      scheduleApi.updateSchedule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
      setModalOpen(false);
      setEditingSchedule(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: scheduleApi.deleteSchedule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['schedules'] });
    },
  });

  const schedules = schedulesData?.items || [];
  const totalPages = schedulesData?.pages || 1;

  const handleEdit = (schedule: Schedule) => {
    setEditingSchedule(schedule);
    setModalOpen(true);
  };

  const handleDelete = async (id: string) => {
    if (window.confirm('Are you sure you want to delete this schedule?')) {
      await deleteMutation.mutateAsync(id);
    }
  };

  const parseCronExpression = (cron: string) => {
    // Simple cron parser for display
    const parts = cron.split(' ');
    if (parts.length < 5) return 'Invalid cron expression';
    
    const [minute, hour, , , weekday] = parts;
    
    if (minute === '0' && hour !== '*') {
      return `Daily at ${hour}:00`;
    }
    if (minute !== '*' && hour !== '*') {
      return `Daily at ${hour}:${minute.padStart(2, '0')}`;
    }
    if (weekday !== '*') {
      const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      return `Weekly on ${days[parseInt(weekday)] || weekday}`;
    }
    
    return cron;
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Schedules</h1>
            <p className="mt-2 text-gray-600">Manage automated scan and patch schedules</p>
          </div>
          <button
            onClick={() => {
              setEditingSchedule(null);
              setModalOpen(true);
            }}
            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Schedule
          </button>
        </div>
      </div>

      {/* Schedules Table */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {schedules.map((schedule) => (
            <li key={schedule.id} className="px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="flex-shrink-0">
                    <Calendar className="h-8 w-8 text-gray-400" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h3 className="text-lg font-medium text-gray-900">
                        {schedule.name}
                      </h3>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        schedule.is_active ? 'bg-success-100 text-success-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {schedule.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                      <div className="flex items-center space-x-1">
                        <Clock className="h-4 w-4" />
                        <span>{parseCronExpression(schedule.cron_expression)}</span>
                      </div>
                      <span>•</span>
                      <span className="capitalize">{schedule.command_type} scan</span>
                      {schedule.target_tags.length > 0 && (
                        <>
                          <span>•</span>
                          <div className="flex items-center space-x-1">
                            <Tag className="h-4 w-4" />
                            <span>{schedule.target_tags.join(', ')}</span>
                          </div>
                        </>
                      )}
                    </div>
                    {schedule.description && (
                      <p className="mt-1 text-sm text-gray-600">{schedule.description}</p>
                    )}
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleEdit(schedule)}
                    className="inline-flex items-center p-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    <Edit2 className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(schedule.id)}
                    className="inline-flex items-center p-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger-500"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>

        {/* Empty State */}
        {schedules.length === 0 && (
          <div className="text-center py-12">
            <Calendar className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No schedules</h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by creating your first automated schedule.
            </p>
            <div className="mt-6">
              <button
                onClick={() => {
                  setEditingSchedule(null);
                  setModalOpen(true);
                }}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Schedule
              </button>
            </div>
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

      {/* Schedule Modal */}
      {modalOpen && (
        <ScheduleModal
          schedule={editingSchedule}
          onSave={(scheduleData) => {
            if (editingSchedule) {
              updateMutation.mutate({ id: editingSchedule.id, data: scheduleData });
            } else {
              // Ensure required fields are present for creation
              const createData = {
                name: scheduleData.name || '',
                description: scheduleData.description,
                command_template: scheduleData.command_template || {},
                cron_expression: scheduleData.cron_expression || '',
                target_tags: scheduleData.target_tags || [],
                is_active: scheduleData.is_active ?? true,
              };
              createMutation.mutate(createData);
            }
          }}
          onClose={() => {
            setModalOpen(false);
            setEditingSchedule(null);
          }}
          isSubmitting={createMutation.isPending || updateMutation.isPending}
        />
      )}
    </div>
  );
};

// Schedule Modal Component
interface ScheduleModalProps {
  schedule: Schedule | null;
  onSave: (data: Partial<Schedule>) => void;
  onClose: () => void;
  isSubmitting: boolean;
}

const ScheduleModal: React.FC<ScheduleModalProps> = ({ schedule, onSave, onClose, isSubmitting }) => {
  const [formData, setFormData] = React.useState({
    name: schedule?.name || '',
    description: schedule?.description || '',
    cron_expression: schedule?.cron_expression || '0 2 * * *',
    command_type: schedule?.command_type || 'quick_scan',
    enabled: schedule?.is_active ?? true,
    target_tags: schedule?.target_tags?.join(', ') || '',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const { enabled, ...restData } = formData;
    onSave({
      ...restData,
      is_active: enabled,
      target_tags: formData.target_tags.split(',').map(tag => tag.trim()).filter(Boolean),
    });
  };

  const cronPresets = [
    { label: 'Daily at 2 AM', value: '0 2 * * *' },
    { label: 'Weekly on Sunday at 2 AM', value: '0 2 * * 0' },
    { label: 'Monthly on 1st at 2 AM', value: '0 2 1 * *' },
    { label: 'Every 6 hours', value: '0 */6 * * *' },
    { label: 'Weekdays at 9 AM', value: '0 9 * * 1-5' },
  ];

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
        <div className="mt-3">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            {schedule ? 'Edit Schedule' : 'Create Schedule'}
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
              <label className="block text-sm font-medium text-gray-700">Description</label>
              <textarea
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                rows={3}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Schedule</label>
              <select
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                value={formData.cron_expression}
                onChange={(e) => setFormData({ ...formData, cron_expression: e.target.value })}
              >
                {cronPresets.map((preset) => (
                  <option key={preset.value} value={preset.value}>
                    {preset.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Command Type</label>
              <select
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                value={formData.command_type}
                onChange={(e) => setFormData({ ...formData, command_type: e.target.value })}
              >
                <option value="quick_scan">Quick Scan</option>
                <option value="full_scan">Full Scan</option>
                <option value="update_patches">Update Patches</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Target Tags (comma-separated)</label>
              <input
                type="text"
                className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500"
                placeholder="production, servers, critical"
                value={formData.target_tags}
                onChange={(e) => setFormData({ ...formData, target_tags: e.target.value })}
              />
            </div>

            <div className="flex items-center">
              <input
                type="checkbox"
                id="enabled"
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                checked={formData.enabled}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              />
              <label htmlFor="enabled" className="ml-2 block text-sm text-gray-900">
                Enable schedule
              </label>
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
                disabled={isSubmitting}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
              >
                {isSubmitting ? 'Saving...' : 'Save'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default SchedulesPage;