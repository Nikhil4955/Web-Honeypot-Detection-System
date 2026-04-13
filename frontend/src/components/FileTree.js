import React, { useState } from 'react';
import { File, Folder, FolderOpen, FileJs, FileHtml, FileCss, FilePy, Plus, Trash } from '@phosphor-icons/react';
import { Button } from './ui/button';
import { Input } from './ui/input';

const FileTree = ({ fileTree, onFileSelect, selectedFile, onCreateFile, onDeleteFile }) => {
  const [expandedFolders, setExpandedFolders] = useState({});
  const [showNewFile, setShowNewFile] = useState(false);
  const [newFileName, setNewFileName] = useState('');

  const getFileIcon = (fileName) => {
    const lower = fileName.toLowerCase();
    if (lower.endsWith('.js') || lower.endsWith('.jsx') || lower.endsWith('.ts') || lower.endsWith('.tsx'))
      return <FileJs size={15} className="text-yellow-500 shrink-0" />;
    if (lower.endsWith('.html') || lower.endsWith('.htm'))
      return <FileHtml size={15} className="text-orange-500 shrink-0" />;
    if (lower.endsWith('.css') || lower.endsWith('.scss'))
      return <FileCss size={15} className="text-blue-400 shrink-0" />;
    if (lower.endsWith('.json'))
      return <File size={15} className="text-green-500 shrink-0" />;
    if (lower.endsWith('.py'))
      return <FilePy size={15} className="text-sky-400 shrink-0" />;
    if (lower.endsWith('.md'))
      return <File size={15} className="text-zinc-400 shrink-0" />;
    return <File size={15} className="text-zinc-500 shrink-0" />;
  };

  const toggleFolder = (folderName) => {
    setExpandedFolders((prev) => ({ ...prev, [folderName]: !prev[folderName] }));
  };

  // Build a nested structure from flat file paths
  const organizeFiles = (files) => {
    const structure = {};
    if (!files) return structure;
    Object.keys(files).sort().forEach((path) => {
      const parts = path.split('/');
      if (parts.length === 1) {
        structure[path] = { type: 'file' };
      } else {
        const folder = parts[0];
        if (!structure[folder]) {
          structure[folder] = { type: 'folder', files: {} };
        }
        const subPath = parts.slice(1).join('/');
        structure[folder].files[subPath] = { type: 'file' };
      }
    });
    return structure;
  };

  const structure = organizeFiles(fileTree);

  const handleCreateFile = (e) => {
    e.preventDefault();
    if (!newFileName.trim()) return;
    if (onCreateFile) onCreateFile(newFileName.trim());
    setNewFileName('');
    setShowNewFile(false);
  };

  const renderFile = (fileName, fullPath) => (
    <div
      key={fullPath}
      onClick={() => onFileSelect(fullPath)}
      data-testid={`file-tree-item-${fullPath}`}
      className={`group flex items-center gap-2 text-sm font-mono py-1.5 px-2 rounded-sm cursor-pointer transition-colors ${
        selectedFile === fullPath
          ? 'text-orange-500 bg-orange-500/10'
          : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'
      }`}
    >
      {getFileIcon(fileName)}
      <span className="truncate flex-1">{fileName}</span>
      {onDeleteFile && (
        <button
          onClick={(e) => { e.stopPropagation(); onDeleteFile(fullPath); }}
          className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-red-400 transition-opacity"
          data-testid={`delete-file-${fullPath}`}
        >
          <Trash size={13} />
        </button>
      )}
    </div>
  );

  const renderFolder = (folderName, files) => {
    const isExpanded = expandedFolders[folderName] !== false; // default expanded
    return (
      <div key={folderName} className="mb-1">
        <div
          onClick={() => toggleFolder(folderName)}
          className="flex items-center gap-2 text-sm text-zinc-400 font-mono py-1.5 px-2 rounded-sm cursor-pointer hover:bg-zinc-800/50 hover:text-zinc-200 transition-colors"
        >
          {isExpanded
            ? <FolderOpen size={15} className="text-orange-500/70 shrink-0" />
            : <Folder size={15} className="text-zinc-600 shrink-0" />
          }
          <span>{folderName}</span>
        </div>
        {isExpanded && (
          <div className="ml-4 border-l border-zinc-800/50 pl-1">
            {Object.keys(files).map((subPath) => {
              const fullPath = `${folderName}/${subPath}`;
              return renderFile(subPath, fullPath);
            })}
          </div>
        )}
      </div>
    );
  };

  const fileCount = fileTree ? Object.keys(fileTree).length : 0;

  return (
    <div className="h-full border-l border-zinc-800 bg-zinc-950 flex flex-col" data-testid="file-tree">
      {/* Header */}
      <div className="p-4 pb-2 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono text-zinc-300 uppercase tracking-widest">Files</h3>
          {fileCount > 0 && <span className="text-xs text-zinc-600 font-mono">{fileCount} files</span>}
        </div>
        <Button
          onClick={() => setShowNewFile(!showNewFile)}
          data-testid="file-tree-new-file"
          title="Create new file"
          className="bg-transparent hover:bg-zinc-800 text-zinc-400 hover:text-orange-500 rounded-sm p-1.5 transition-colors h-auto"
        >
          <Plus size={16} />
        </Button>
      </div>

      {/* New file form */}
      {showNewFile && (
        <form onSubmit={handleCreateFile} className="px-4 pb-3">
          <div className="flex gap-1">
            <Input
              value={newFileName}
              onChange={(e) => setNewFileName(e.target.value)}
              placeholder="file.js"
              autoFocus
              data-testid="file-tree-new-filename"
              className="flex-1 bg-zinc-800 border-zinc-700 text-white rounded-sm text-xs h-7 font-mono"
            />
            <Button
              type="submit"
              className="bg-orange-500 hover:bg-orange-600 text-white rounded-sm px-2 h-7 text-xs font-mono"
            >
              Add
            </Button>
          </div>
        </form>
      )}

      {/* File list */}
      <div className="flex-1 overflow-y-auto px-2 pb-4">
        {Object.keys(structure).length === 0 ? (
          <div className="text-center py-8 px-2">
            <Folder size={40} className="text-zinc-800 mx-auto mb-2" />
            <p className="text-zinc-600 text-xs font-mono">No files yet</p>
            <p className="text-zinc-700 text-xs mt-1">Create a file or ask @ai</p>
          </div>
        ) : (
          <div>
            {Object.entries(structure).map(([name, item]) => {
              if (item.type === 'folder') {
                return renderFolder(name, item.files);
              }
              return renderFile(name, name);
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default FileTree;
