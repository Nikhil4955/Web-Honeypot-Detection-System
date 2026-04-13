import React, { useState, useEffect } from 'react';
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
      loadProject();
    }
  }, [projectId]);

  useEffect(() => {
    if (currentProject?.fileTree) {
      setFileTree(currentProject.fileTree);
    }
  }, [currentProject]);

  useEffect(() => {
    if (!socket) return;

    // Listen for file tree updates from AI
    socket.on('file_tree_update', (data) => {
      setFileTree(data.fileTree);
      setBuildCommand(data.buildCommand || '');
      setStartCommand(data.startCommand || '');
      // Save to backend
      if (projectId) {
        updateFileTree(projectId, data.fileTree);
      }
    });

    return () => {
      socket.off('file_tree_update');
    };
  }, [socket, projectId]);

  const loadProject = async () => {
    try {
      await fetchProject(projectId);
    } catch (err) {
      console.error('Error loading project:', err);
      navigate('/dashboard');
    }
  };

  const handleFileUpdate = async (filePath, content) => {
    const updatedTree = { ...fileTree, [filePath]: content };
    setFileTree(updatedTree);
    await updateFileTree(projectId, updatedTree);
  };

  const handleFileSelect = (filePath) => {
    setSelectedFile(filePath);
  };

  if (!currentProject) {
    return (
      <div className="min-h-screen bg-[#09090b] flex items-center justify-center">
        <p className="text-zinc-500 font-mono">Loading project...</p>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-[#09090b]" data-testid="workspace">
      {/* Header */}
      <div className="h-14 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between px-4 z-10">
        <div className="flex items-center gap-4">
          <Button
            onClick={() => navigate('/dashboard')}
            data-testid="back-to-dashboard"
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-3 py-1.5 font-mono text-sm transition-colors flex items-center gap-2"
          >
            <ArrowLeft size={16} />
            Back
          </Button>
          <h1 className="text-lg font-mono text-white">{currentProject.name}</h1>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => setShowPreview(true)}
            data-testid="run-button"
            className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-4 py-1.5 rounded hover:bg-emerald-500/20 font-mono text-sm transition-colors flex items-center gap-2"
          >
            <Play size={16} weight="fill" />
            Run
          </Button>
          <div className="relative">
            <Button
              onClick={() => setShowCollaborators(!showCollaborators)}
              data-testid="collaborators-button"
              className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-3 py-1.5 font-mono text-sm transition-colors flex items-center gap-2"
            >
              <Users size={16} />
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
      <div className="flex-1 flex overflow-hidden" style={{ height: 'calc(100vh - 56px)' }}>
        {/* Left: Chat Panel */}
        <div className="w-1/4 min-w-[250px]">
          <Chat socket={socket} projectId={projectId} />
        </div>

        {/* Center: Code Editor */}
        <div className="flex-1">
          <CodeEditor
            fileTree={fileTree}
            selectedFile={selectedFile}
            onFileUpdate={handleFileUpdate}
          />
        </div>

        {/* Right: File Tree */}
        <div className="w-1/5 min-w-[200px]">
          <FileTree
            fileTree={fileTree}
            onFileSelect={handleFileSelect}
            selectedFile={selectedFile}
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
