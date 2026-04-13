import React from 'react';
import { File, Folder, FileJs, FileHtml, FileCss } from '@phosphor-icons/react';

const FileTree = ({ fileTree, onFileSelect, selectedFile }) => {
  const getFileIcon = (fileName) => {
    if (fileName.endsWith('.js') || fileName.endsWith('.jsx')) return <FileJs size={16} className="text-yellow-500" />;
    if (fileName.endsWith('.html')) return <FileHtml size={16} className="text-orange-500" />;
    if (fileName.endsWith('.css')) return <FileCss size={16} className="text-blue-500" />;
    if (fileName.endsWith('.json')) return <File size={16} className="text-green-500" />;
    return <File size={16} className="text-zinc-500" />;
  };

  // Organize files into folder structure
  const organizeFiles = (files) => {
    const structure = {};
    Object.keys(files).forEach((path) => {
      const parts = path.split('/');
      if (parts.length === 1) {
        // Root level file
        structure[path] = { type: 'file', content: files[path] };
      } else {
        // Nested file
        const folder = parts[0];
        if (!structure[folder]) {
          structure[folder] = { type: 'folder', files: {} };
        }
        const subPath = parts.slice(1).join('/');
        structure[folder].files[subPath] = files[path];
      }
    });
    return structure;
  };

  const structure = fileTree ? organizeFiles(fileTree) : {};

  const renderFileItem = (fileName, fullPath) => (
    <div
      key={fullPath}
      onClick={() => onFileSelect(fullPath)}
      data-testid={`file-tree-item-${fullPath}`}
      className={
        selectedFile === fullPath
          ? 'flex items-center gap-2 text-sm font-mono py-1 px-2 rounded-sm cursor-pointer text-orange-500 bg-orange-500/10'
          : 'flex items-center gap-2 text-sm text-zinc-400 font-mono py-1 px-2 rounded-sm cursor-pointer hover:bg-zinc-800/50 hover:text-zinc-200'
      }
    >
      {getFileIcon(fileName)}
      <span>{fileName}</span>
    </div>
  );

  const renderFolder = (folderName, files) => (
    <div key={folderName} className="mb-2">
      <div className="flex items-center gap-2 text-sm text-zinc-400 font-mono py-1 px-2">
        <Folder size={16} className="text-zinc-600" />
        <span>{folderName}</span>
      </div>
      <div className="ml-4">
        {Object.keys(files).map((subPath) => {
          const fullPath = `${folderName}/${subPath}`;
          return renderFileItem(subPath, fullPath);
        })}
      </div>
    </div>
  );

  return (
    <div className="h-full border-l border-zinc-800 bg-zinc-950 p-4 overflow-y-auto" data-testid="file-tree">
      <h3 className="text-sm font-mono text-zinc-300 uppercase tracking-widest mb-4">Files</h3>
      {Object.keys(structure).length === 0 ? (
        <div className="text-center py-8">
          <Folder size={48} className="text-zinc-800 mx-auto mb-2" />
          <p className="text-zinc-600 text-xs font-mono">No files yet</p>
          <p className="text-zinc-700 text-xs mt-1">Ask @ai to create files</p>
        </div>
      ) : (
        <div>
          {Object.entries(structure).map(([name, item]) => {
            if (item.type === 'folder') {
              return renderFolder(name, item.files);
            } else {
              return renderFileItem(name, name);
            }
          })}
        </div>
      )}
    </div>
  );
};

export default FileTree;
