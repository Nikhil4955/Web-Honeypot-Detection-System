import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useProject } from '../context/ProjectContext';
import { useUser } from '../context/UserContext';
import { ArrowLeft, Users, Play } from '@phosphor-icons/react';
import { Button } from '../components/ui/button';
import Chat from '../components/Chat';
import CodeEditor from '../components/CodeEditor';
import FileTree from '../components/FileTree';
import CollaboratorsPanel from '../components/CollaboratorsPanel';
import PreviewPanel from '../components/PreviewPanel';

const Workspace = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const { user } = useUser();
  const { currentProject, fetchProject, updateFileTree, socket } = useProject();

  const [selectedFile, setSelectedFile] = useState(null);
  const [showCollaborators, setShowCollaborators] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [fileTree, setFileTree] = useState({});
  const [buildCommand, setBuildCommand] = useState('');
  const [startCommand, setStartCommand] = useState('');

  useEffect(() => {
    if (projectId) {
      fetchProject(projectId).catch(() => navigate('/dashboard'));
    }
  }, [projectId]);

  useEffect(() => {
    if (currentProject?.fileTree && Object.keys(currentProject.fileTree).length > 0) {
      setFileTree(currentProject.fileTree);
    }
  }, [currentProject]);

  useEffect(() => {
    if (!socket) return;

    const handleFileTreeUpdate = (data) => {
      setFileTree(data.fileTree);
      setBuildCommand(data.buildCommand || '');
      setStartCommand(data.startCommand || '');
      if (projectId) updateFileTree(projectId, data.fileTree);
    };

    socket.on('file_tree_update', handleFileTreeUpdate);
    return () => socket.off('file_tree_update', handleFileTreeUpdate);
  }, [socket, projectId]);

  // Save a single file change to the full tree
  const handleFileUpdate = useCallback(async (filePath, content) => {
    setFileTree((prev) => {
      const updated = { ...prev, [filePath]: content };
      // Async save — don't block
      updateFileTree(projectId, updated).catch(console.error);
      return updated;
    });
  }, [projectId, updateFileTree]);

  // Create a new file (from either FileTree or CodeEditor)
  const handleCreateFile = useCallback((fileName) => {
    setFileTree((prev) => {
      const updated = { ...prev, [fileName]: '' };
      updateFileTree(projectId, updated).catch(console.error);
      return updated;
    });
    setSelectedFile(fileName);
  }, [projectId, updateFileTree]);

  // Delete a file
  const handleDeleteFile = useCallback((filePath) => {
    setFileTree((prev) => {
      const updated = { ...prev };
      delete updated[filePath];
      updateFileTree(projectId, updated).catch(console.error);
      return updated;
    });
    if (selectedFile === filePath) setSelectedFile(null);
  }, [projectId, updateFileTree, selectedFile]);

  // Ask AI to review/fix the current file
  const handleRequestAIFix = useCallback((filePath, content) => {
    if (!socket || !user) return;
    const message = `@ai Please review and fix this code in ${filePath}:\n\`\`\`\n${content}\n\`\`\``;
    socket.emit('ai_message', {
      projectId,
      message,
      user: { name: user.name, email: user.email },
      timestamp: new Date().toISOString()
    });
  }, [socket, projectId, user]);

  if (!currentProject) {
    return (
      <div className="min-h-screen bg-[#09090b] flex items-center justify-center">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-zinc-500 font-mono text-sm">Loading project...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-[#09090b]" data-testid="workspace">
      {/* Header */}
      <div className="h-12 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between px-4 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <Button
            onClick={() => navigate('/dashboard')}
            data-testid="back-to-dashboard"
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-3 py-1 font-mono text-sm transition-colors flex items-center gap-2 h-auto"
          >
            <ArrowLeft size={14} />
            Back
          </Button>
          <div className="w-px h-5 bg-zinc-800" />
          <h1 className="text-sm font-mono text-white tracking-tight">{currentProject.name}</h1>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setShowPreview(true)}
            data-testid="run-button"
            className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-4 py-1 rounded hover:bg-emerald-500/20 font-mono text-sm transition-colors flex items-center gap-2 h-auto"
          >
            <Play size={14} weight="fill" />
            Run
          </Button>
          <div className="relative">
            <Button
              onClick={() => setShowCollaborators(!showCollaborators)}
              data-testid="collaborators-button"
              className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-3 py-1 font-mono text-sm transition-colors flex items-center gap-2 h-auto"
            >
              <Users size={14} />
              Collaborators
            </Button>
            <CollaboratorsPanel
              projectId={projectId}
              isOpen={showCollaborators}
              onClose={() => setShowCollaborators(false)}
            />
          </div>
        </div>
      </div>

      {/* Main Workspace - Three Column Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Chat Panel */}
        <div className="w-1/4 min-w-[260px] max-w-[380px]">
          <Chat socket={socket} projectId={projectId} />
        </div>

        {/* Center: Code Editor */}
        <div className="flex-1 min-w-0">
          <CodeEditor
            fileTree={fileTree}
            selectedFile={selectedFile}
            onFileUpdate={handleFileUpdate}
            onRequestAIFix={handleRequestAIFix}
          />
        </div>

        {/* Right: File Tree */}
        <div className="w-1/5 min-w-[200px] max-w-[280px]">
          <FileTree
            fileTree={fileTree}
            onFileSelect={setSelectedFile}
            selectedFile={selectedFile}
            onCreateFile={handleCreateFile}
            onDeleteFile={handleDeleteFile}
          />
        </div>
      </div>

      {/* Preview Panel (Modal) */}
      <PreviewPanel
        fileTree={fileTree}
        buildCommand={buildCommand}
        startCommand={startCommand}
        isOpen={showPreview}
        onClose={() => setShowPreview(false)}
      />
    </div>
  );
};

export default Workspace;
