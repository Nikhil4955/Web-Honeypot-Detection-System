import React, { useState, useEffect, useRef, useCallback } from 'react';
import { File, X, Plus, MagicWand, FloppyDisk } from '@phosphor-icons/react';
import { Button } from './ui/button';
import { Input } from './ui/input';

const CodeEditor = ({ fileTree, selectedFile, onFileUpdate, onRequestAIFix }) => {
  const [openFiles, setOpenFiles] = useState([]);
  const [activeFile, setActiveFile] = useState(null);
  const [fileContents, setFileContents] = useState({});
  const [showNewFile, setShowNewFile] = useState(false);
  const [newFileName, setNewFileName] = useState('');
  const [unsavedChanges, setUnsavedChanges] = useState({});
  const textareaRef = useRef(null);

  // Sync file contents from fileTree prop
  useEffect(() => {
    if (fileTree && Object.keys(fileTree).length > 0) {
      setFileContents((prev) => {
        const merged = { ...prev };
        Object.keys(fileTree).forEach((key) => {
          // Only update if user hasn't made unsaved changes
          if (!unsavedChanges[key]) {
            merged[key] = fileTree[key];
          }
        });
        return merged;
      });

      // Auto-open first file if nothing is open
      if (openFiles.length === 0) {
        const firstFile = Object.keys(fileTree)[0];
        if (firstFile) {
          setOpenFiles([firstFile]);
          setActiveFile(firstFile);
        }
      }
    }
  }, [fileTree]);

  // React to selectedFile prop from FileTree clicks
  useEffect(() => {
    if (selectedFile && fileContents[selectedFile] !== undefined) {
      if (!openFiles.includes(selectedFile)) {
        setOpenFiles((prev) => [...prev, selectedFile]);
      }
      setActiveFile(selectedFile);
    }
  }, [selectedFile, fileContents]);

  const openFile = useCallback((filePath) => {
    if (!openFiles.includes(filePath)) {
      setOpenFiles((prev) => [...prev, filePath]);
    }
    setActiveFile(filePath);
  }, [openFiles]);

  const closeFile = (filePath, e) => {
    e.stopPropagation();
    const newOpenFiles = openFiles.filter((f) => f !== filePath);
    setOpenFiles(newOpenFiles);
    if (activeFile === filePath) {
      setActiveFile(newOpenFiles[newOpenFiles.length - 1] || null);
    }
    // Clear unsaved marker
    setUnsavedChanges((prev) => {
      const copy = { ...prev };
      delete copy[filePath];
      return copy;
    });
  };

  const handleContentChange = (filePath, newContent) => {
    setFileContents((prev) => ({ ...prev, [filePath]: newContent }));
    setUnsavedChanges((prev) => ({ ...prev, [filePath]: true }));
  };

  const saveFile = (filePath) => {
    if (onFileUpdate && fileContents[filePath] !== undefined) {
      onFileUpdate(filePath, fileContents[filePath]);
      setUnsavedChanges((prev) => {
        const copy = { ...prev };
        delete copy[filePath];
        return copy;
      });
    }
  };

  const saveActiveFile = () => {
    if (activeFile) saveFile(activeFile);
  };

  // Keyboard shortcut: Ctrl+S to save
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        saveActiveFile();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeFile, fileContents]);

  const handleCreateFile = (e) => {
    e.preventDefault();
    if (!newFileName.trim()) return;
    const name = newFileName.trim();
    setFileContents((prev) => ({ ...prev, [name]: '' }));
    setOpenFiles((prev) => [...prev, name]);
    setActiveFile(name);
    setNewFileName('');
    setShowNewFile(false);
    // Save empty file to backend
    if (onFileUpdate) onFileUpdate(name, '');
  };

  const handleDeleteFile = (filePath) => {
    // Remove from open files and contents
    setOpenFiles((prev) => prev.filter((f) => f !== filePath));
    setFileContents((prev) => {
      const copy = { ...prev };
      delete copy[filePath];
      return copy;
    });
    if (activeFile === filePath) {
      const remaining = openFiles.filter((f) => f !== filePath);
      setActiveFile(remaining[remaining.length - 1] || null);
    }
  };

  const handleAIFix = () => {
    if (activeFile && fileContents[activeFile] && onRequestAIFix) {
      onRequestAIFix(activeFile, fileContents[activeFile]);
    }
  };

  const lineCount = activeFile && fileContents[activeFile]
    ? fileContents[activeFile].split('\n').length
    : 0;

  return (
    <div className="h-full flex flex-col bg-[#0d0d0f]" data-testid="code-editor">
      {/* Toolbar */}
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-950 px-2">
        {/* Tabs */}
        <div className="flex overflow-x-auto flex-1">
          {openFiles.map((filePath) => (
            <div
              key={filePath}
              onClick={() => setActiveFile(filePath)}
              data-testid={`editor-tab-${filePath}`}
              className={
                activeFile === filePath
                  ? 'px-3 py-2 text-sm font-mono border-r border-zinc-800 flex items-center gap-1.5 cursor-pointer text-orange-500 bg-[#0d0d0f] border-t-2 border-t-orange-500 shrink-0'
                  : 'px-3 py-2 text-sm font-mono border-r border-zinc-800 flex items-center gap-1.5 cursor-pointer text-zinc-500 hover:text-zinc-300 shrink-0'
              }
            >
              <File size={13} />
              <span>{filePath}</span>
              {unsavedChanges[filePath] && (
                <span className="w-2 h-2 rounded-full bg-orange-500 shrink-0" title="Unsaved changes" />
              )}
              <button
                onClick={(e) => closeFile(filePath, e)}
                className="ml-1 hover:text-red-400 opacity-60 hover:opacity-100"
                data-testid={`close-tab-${filePath}`}
              >
                <X size={12} />
              </button>
            </div>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-1 px-2 shrink-0">
          {activeFile && (
            <>
              <Button
                onClick={saveActiveFile}
                data-testid="save-file-button"
                title="Save (Ctrl+S)"
                className="bg-transparent hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded-sm p-1.5 transition-colors h-auto"
              >
                <FloppyDisk size={16} />
              </Button>
              <Button
                onClick={handleAIFix}
                data-testid="ai-fix-button"
                title="Ask AI to review & fix this file"
                className="bg-transparent hover:bg-yellow-500/10 text-zinc-400 hover:text-yellow-500 rounded-sm p-1.5 transition-colors h-auto"
              >
                <MagicWand size={16} />
              </Button>
            </>
          )}
          <Button
            onClick={() => setShowNewFile(true)}
            data-testid="new-file-button"
            title="Create new file"
            className="bg-transparent hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded-sm p-1.5 transition-colors h-auto"
          >
            <Plus size={16} />
          </Button>
        </div>
      </div>

      {/* New File Input */}
      {showNewFile && (
        <form onSubmit={handleCreateFile} className="flex items-center gap-2 px-4 py-2 bg-zinc-900 border-b border-zinc-800">
          <Input
            value={newFileName}
            onChange={(e) => setNewFileName(e.target.value)}
            placeholder="filename.js"
            autoFocus
            data-testid="new-file-name-input"
            className="flex-1 bg-zinc-800 border-zinc-700 text-white rounded-sm text-sm h-8 font-mono"
          />
          <Button
            type="submit"
            data-testid="create-file-confirm"
            className="bg-orange-500 hover:bg-orange-600 text-white rounded-sm px-3 h-8 text-xs font-mono"
          >
            Create
          </Button>
          <Button
            type="button"
            onClick={() => { setShowNewFile(false); setNewFileName(''); }}
            className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-sm px-3 h-8 text-xs font-mono"
          >
            Cancel
          </Button>
        </form>
      )}

      {/* Editor Content */}
      <div className="flex-1 overflow-hidden" data-testid="editor-content">
        {activeFile ? (
          <div className="flex h-full">
            {/* Line numbers */}
            <div className="text-right pr-3 pl-2 text-zinc-600 font-mono w-14 border-r border-zinc-800/50 pt-4 text-sm select-none overflow-hidden"
                 style={{ fontFamily: 'JetBrains Mono, monospace' }}>
              {Array.from({ length: lineCount }, (_, idx) => (
                <div key={idx} className="leading-6">{idx + 1}</div>
              ))}
            </div>
            {/* Code textarea */}
            <textarea
              ref={textareaRef}
              value={fileContents[activeFile] || ''}
              onChange={(e) => handleContentChange(activeFile, e.target.value)}
              data-testid="code-textarea"
              className="flex-1 bg-[#0d0d0f] text-zinc-200 p-4 outline-none resize-none text-sm leading-6 overflow-auto"
              style={{ fontFamily: 'JetBrains Mono, monospace', tabSize: 2 }}
              spellCheck={false}
              onKeyDown={(e) => {
                // Tab key inserts 2 spaces
                if (e.key === 'Tab') {
                  e.preventDefault();
                  const start = e.target.selectionStart;
                  const end = e.target.selectionEnd;
                  const val = e.target.value;
                  const newVal = val.substring(0, start) + '  ' + val.substring(end);
                  handleContentChange(activeFile, newVal);
                  setTimeout(() => {
                    e.target.selectionStart = e.target.selectionEnd = start + 2;
                  }, 0);
                }
              }}
            />
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-zinc-600">
            <div className="text-center">
              <File size={48} className="mx-auto mb-4 text-zinc-800" />
              <p className="font-mono text-sm">No file open</p>
              <p className="text-xs text-zinc-700 mt-2">Click a file in the tree, create a new file, or ask @ai to generate code</p>
            </div>
          </div>
        )}
      </div>

      {/* Status Bar */}
      {activeFile && (
        <div className="h-6 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between px-4 text-xs font-mono text-zinc-600">
          <span>{activeFile}</span>
          <div className="flex items-center gap-4">
            <span>{lineCount} lines</span>
            {unsavedChanges[activeFile] && <span className="text-orange-500">Unsaved</span>}
          </div>
        </div>
      )}
    </div>
  );
};

export default CodeEditor;
