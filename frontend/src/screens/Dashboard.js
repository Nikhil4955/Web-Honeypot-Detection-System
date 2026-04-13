import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser } from '../context/UserContext';
import { useProject } from '../context/ProjectContext';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '../components/ui/dialog';
import { Plus, FolderOpen, SignOut } from '@phosphor-icons/react';
import { formatApiErrorDetail } from '../utils/errorHandler';

const Dashboard = () => {
  const navigate = useNavigate();
  const { user, logout } = useUser();
  const { projects, fetchProjects, createProject } = useProject();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadProjects();
  }, []);

  const loadProjects = async () => {
    try {
      await fetchProjects();
    } catch (err) {
      console.error('Error loading projects:', err);
    }
  };

  const handleCreateProject = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const project = await createProject(projectName);
      setShowCreateModal(false);
      setProjectName('');
      navigate(`/workspace/${project._id}`);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-[#09090b]">
      {/* Header */}
      <div className="border-b border-zinc-800 bg-zinc-950 px-8 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-mono tracking-tight text-white" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              SOIN
            </h1>
            <p className="text-zinc-400 text-sm">Welcome back, {user?.name}</p>
          </div>
          <Button
            onClick={handleLogout}
            data-testid="logout-button"
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-4 py-2 font-mono text-sm transition-colors flex items-center gap-2"
          >
            <SignOut size={16} />
            Logout
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-8">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-xl text-zinc-200 font-mono">Your Projects</h2>
          <Dialog open={showCreateModal} onOpenChange={setShowCreateModal}>
            <DialogTrigger asChild>
              <Button
                data-testid="new-project-button"
                className="bg-orange-500 hover:bg-orange-600 text-white rounded-sm px-4 py-2 font-mono uppercase tracking-wide transition-colors flex items-center gap-2"
              >
                <Plus size={20} weight="bold" />
                New Project
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-zinc-900 border-zinc-800 text-white">
              <DialogHeader>
                <DialogTitle className="text-xl font-mono text-white">Create New Project</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleCreateProject} className="space-y-4 mt-4">
                <div>
                  <Label htmlFor="project-name" className="text-zinc-300 mb-2 block">
                    Project Name
                  </Label>
                  <Input
                    id="project-name"
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    data-testid="project-name-input"
                    className="w-full bg-zinc-800 border-zinc-700 text-white rounded-sm focus:ring-orange-500 focus:border-orange-500"
                    placeholder="My Awesome Project"
                    required
                  />
                </div>

                {error && (
                  <div className="text-red-400 text-sm border border-red-500/30 bg-red-500/10 p-3 rounded-sm">
                    {error}
                  </div>
                )}

                <Button
                  type="submit"
                  disabled={loading}
                  data-testid="create-project-submit"
                  className="w-full bg-orange-500 hover:bg-orange-600 text-white rounded-sm py-2 font-mono uppercase tracking-wide transition-colors"
                >
                  {loading ? 'Creating...' : 'Create Project'}
                </Button>
              </form>
            </DialogContent>
          </Dialog>
        </div>

        {/* Projects Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <div
              key={project._id}
              onClick={() => navigate(`/workspace/${project._id}`)}
              data-testid={`project-card-${project._id}`}
              className="bg-zinc-950 border border-zinc-800 p-6 rounded-sm cursor-pointer hover:-translate-y-1 hover:border-orange-500 transition-all"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-zinc-800 rounded-sm">
                  <FolderOpen size={24} className="text-orange-500" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-lg font-mono text-white truncate">{project.name}</h3>
                  <p className="text-zinc-500 text-xs mt-1 font-mono">
                    {new Date(project.created_at).toLocaleDateString()}
                  </p>
                  <p className="text-zinc-400 text-sm mt-2">
                    {project.users?.length || 0} collaborator{project.users?.length !== 1 ? 's' : ''}
                  </p>
                </div>
              </div>
            </div>
          ))}

          {projects.length === 0 && (
            <div className="col-span-full text-center py-16">
              <FolderOpen size={64} className="text-zinc-700 mx-auto mb-4" />
              <p className="text-zinc-500 font-mono">No projects yet. Create your first one!</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
