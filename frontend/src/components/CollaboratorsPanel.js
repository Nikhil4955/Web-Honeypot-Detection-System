import React, { useState, useEffect } from 'react';
import { X, UserPlus, Users } from '@phosphor-icons/react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { useProject } from '../context/ProjectContext';
import { formatApiErrorDetail } from '../utils/errorHandler';

const CollaboratorsPanel = ({ projectId, isOpen, onClose }) => {
  const { addCollaborator, fetchCollaborators } = useProject();
  const [collaborators, setCollaborators] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (isOpen && projectId) {
      loadCollaborators();
    }
  }, [isOpen, projectId]);

  const loadCollaborators = async () => {
    try {
      const data = await fetchCollaborators(projectId);
      setCollaborators(data);
    } catch (err) {
      console.error('Error loading collaborators:', err);
    }
  };

  const handleAddCollaborator = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await addCollaborator(projectId, email);
      setEmail('');
      setShowAddForm(false);
      loadCollaborators();
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="absolute top-14 right-4 bg-zinc-900 border border-zinc-800 shadow-2xl rounded-md p-4 w-72 mt-2 z-50"
      data-testid="collaborators-panel"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-mono text-zinc-300 uppercase tracking-widest flex items-center gap-2">
          <Users size={16} />
          Collaborators
        </h3>
        <button
          onClick={onClose}
          className="text-zinc-500 hover:text-zinc-300"
          data-testid="close-collaborators-panel"
        >
          <X size={16} />
        </button>
      </div>

      {/* Collaborators List */}
      <div className="space-y-2 mb-4 max-h-64 overflow-y-auto">
        {collaborators.map((collab, idx) => (
          <div
            key={idx}
            className="flex items-center gap-3 py-2 border-b border-zinc-800/50 last:border-0"
            data-testid={`collaborator-item-${idx}`}
          >
            <img
              src={`https://ui-avatars.com/api/?name=${encodeURIComponent(collab.name)}&background=f97316&color=fff`}
              alt={collab.name}
              className="w-8 h-8 rounded-full border border-zinc-700 object-cover"
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm text-zinc-200 truncate">{collab.name}</p>
              <p className="text-xs text-zinc-500 truncate">{collab.email}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Add Collaborator */}
      {!showAddForm ? (
        <Button
          onClick={() => setShowAddForm(true)}
          data-testid="add-collaborator-button"
          className="w-full bg-orange-500 hover:bg-orange-600 text-white rounded-sm py-2 font-mono uppercase tracking-wide text-xs transition-colors flex items-center justify-center gap-2"
        >
          <UserPlus size={16} />
          Add Collaborator
        </Button>
      ) : (
        <form onSubmit={handleAddCollaborator} className="space-y-3">
          <div>
            <Label htmlFor="collab-email" className="text-zinc-400 mb-1 block text-xs">
              Email Address
            </Label>
            <Input
              id="collab-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              data-testid="collaborator-email-input"
              className="w-full bg-zinc-800 border-zinc-700 text-white rounded-sm focus:ring-orange-500 focus:border-orange-500 text-sm"
              placeholder="colleague@example.com"
              required
            />
          </div>

          {error && (
            <div className="text-red-400 text-xs border border-red-500/30 bg-red-500/10 p-2 rounded-sm">
              {error}
            </div>
          )}

          <div className="flex gap-2">
            <Button
              type="submit"
              disabled={loading}
              data-testid="submit-add-collaborator"
              className="flex-1 bg-orange-500 hover:bg-orange-600 text-white rounded-sm py-1.5 font-mono uppercase tracking-wide text-xs transition-colors"
            >
              {loading ? 'Adding...' : 'Add'}
            </Button>
            <Button
              type="button"
              onClick={() => {
                setShowAddForm(false);
                setError('');
                setEmail('');
              }}
              className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm py-1.5 font-mono uppercase tracking-wide text-xs transition-colors"
            >
              Cancel
            </Button>
          </div>
        </form>
      )}
    </div>
  );
};

export default CollaboratorsPanel;
