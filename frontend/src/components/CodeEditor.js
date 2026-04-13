import React, { useState, useEffect } from 'react';
import { File, X } from '@phosphor-icons/react';
import { Button } from './ui/button';

const CodeEditor = ({ fileTree, onFileUpdate }) => {
  const [openFiles, setOpenFiles] = useState([]);
  const [activeFile, setActiveFile] = useState(null);
  const [fileContents, setFileContents] = useState({});

  useEffect(() => {
    if (fileTree && Object.keys(fileTree).length > 0) {
      setFileContents(fileTree);
      // Auto-open first file if no files are open
      if (openFiles.length === 0) {
        const firstFile = Object.keys(fileTree)[0];
        if (firstFile) {
          setOpenFiles([firstFile]);
          setActiveFile(firstFile);
        }
      }
    }
  }, [fileTree]);

  const openFile = (filePath) => {
    if (!openFiles.includes(filePath)) {
      setOpenFiles([...openFiles, filePath]);
    }
    setActiveFile(filePath);
  };

  const closeFile = (filePath, e) => {
    e.stopPropagation();
    const newOpenFiles = openFiles.filter((f) => f !== filePath);
    setOpenFiles(newOpenFiles);
    if (activeFile === filePath) {
      setActiveFile(newOpenFiles[0] || null);
    }
  };

  const handleContentChange = (filePath, newContent) => {
    setFileContents({ ...fileContents, [filePath]: newContent });
    if (onFileUpdate) {
      onFileUpdate(filePath, newContent);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#0d0d0f]" data-testid="code-editor">
      {/* Tabs Bar */}
      <div className="flex border-b border-zinc-800 bg-zinc-950 overflow-x-auto">
        {openFiles.map((filePath) => (
          <div
            key={filePath}
            onClick={() => setActiveFile(filePath)}
            data-testid={`editor-tab-${filePath}`}
            className={
              activeFile === filePath
                ? 'px-4 py-2 text-sm font-mono border-r border-zinc-800 flex items-center gap-2 cursor-pointer text-orange-500 bg-[#0d0d0f] border-t-2 border-t-orange-500'
                : 'px-4 py-2 text-sm font-mono border-r border-zinc-800 flex items-center gap-2 cursor-pointer text-zinc-500 hover:text-zinc-300'
            }
          >
            <File size={14} />
            <span>{filePath}</span>
            <button
              onClick={(e) => closeFile(filePath, e)}
              className="ml-2 hover:text-red-400"
              data-testid={`close-tab-${filePath}`}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>

      {/* Editor Content */}
      <div className="flex-1 overflow-auto" data-testid="editor-content">
        {activeFile ? (
          <div className="flex h-full">
            {/* Line numbers */}
            <div className="text-right pr-4 text-zinc-600 font-mono w-12 border-r border-zinc-800/50 pt-4 text-sm select-none">
              {fileContents[activeFile]?.split('\n').map((_, idx) => (
                <div key={idx}>{idx + 1}</div>
              ))}
            </div>
            {/* Code content */}
            <textarea
              value={fileContents[activeFile] || ''}
              onChange={(e) => handleContentChange(activeFile, e.target.value)}
              data-testid="code-textarea"
              className="flex-1 bg-[#0d0d0f] text-zinc-200 p-4 font-mono text-sm outline-none resize-none"
              style={{ fontFamily: 'JetBrains Mono, monospace' }}
              spellCheck={false}
            />
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-zinc-600">
            <div className="text-center">
              <File size={64} className="mx-auto mb-4 text-zinc-800" />
              <p className="font-mono text-sm">No file selected</p>
              <p className="text-xs mt-2">Select a file from the file tree or ask AI to generate code</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CodeEditor;
