import React, { useState, useEffect, useRef } from 'react';
import { WebContainer } from '@webcontainer/api';
import { Play, X, Terminal as TerminalIcon } from '@phosphor-icons/react';
import { Button } from './ui/button';

const PreviewPanel = ({ fileTree, buildCommand, startCommand, isOpen, onClose }) => {
  const [webcontainer, setWebcontainer] = useState(null);
  const [url, setUrl] = useState('');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const iframeRef = useRef(null);

  useEffect(() => {
    initWebContainer();
    return () => {
      if (webcontainer) {
        webcontainer.teardown();
      }
    };
  }, []);

  const initWebContainer = async () => {
    try {
      const instance = await WebContainer.boot();
      setWebcontainer(instance);
      addLog('WebContainer initialized');
    } catch (err) {
      addLog(`Error initializing WebContainer: ${err.message}`, 'error');
    }
  };

  const addLog = (message, type = 'info') => {
    setLogs((prev) => [...prev, { message, type, timestamp: new Date().toLocaleTimeString() }]);
  };

  const runProject = async () => {
    if (!webcontainer || !fileTree || Object.keys(fileTree).length === 0) {
      addLog('No files to run', 'error');
      return;
    }

    setLoading(true);
    setLogs([]);
    addLog('Starting project...');

    try {
      // Mount files
      addLog('Mounting files...');
      await webcontainer.mount(convertFileTreeToWebContainer(fileTree));
      addLog('Files mounted successfully');

      // Install dependencies
      if (buildCommand) {
        addLog(`Running: ${buildCommand}`);
        const installProcess = await webcontainer.spawn('sh', ['-c', buildCommand]);
        installProcess.output.pipeTo(
          new WritableStream({
            write(data) {
              addLog(data);
            }
          })
        );
        await installProcess.exit;
        addLog('Dependencies installed');
      }

      // Start server
      if (startCommand) {
        addLog(`Running: ${startCommand}`);
        const startProcess = await webcontainer.spawn('sh', ['-c', startCommand]);
        startProcess.output.pipeTo(
          new WritableStream({
            write(data) {
              addLog(data);
            }
          })
        );

        // Listen for server ready
        webcontainer.on('server-ready', (port, url) => {
          addLog(`Server ready on port ${port}`);
          setUrl(url);
        });
      }
    } catch (err) {
      addLog(`Error: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const convertFileTreeToWebContainer = (tree) => {
    const structure = {};
    Object.entries(tree).forEach(([path, content]) => {
      const parts = path.split('/');
      let current = structure;

      parts.forEach((part, idx) => {
        if (idx === parts.length - 1) {
          // File
          current[part] = {
            file: {
              contents: content
            }
          };
        } else {
          // Directory
          if (!current[part]) {
            current[part] = {
              directory: {}
            };
          }
          current = current[part].directory;
        }
      });
    });
    return structure;
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center" data-testid="preview-panel">
      <div className="w-[90vw] h-[90vh] bg-zinc-950 border border-zinc-800 rounded-sm flex flex-col">
        {/* Header */}
        <div className="h-14 border-b border-zinc-800 bg-zinc-950 flex items-center justify-between px-4">
          <div className="flex items-center gap-4 flex-1">
            <Button
              onClick={runProject}
              disabled={loading}
              data-testid="run-project-button"
              className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-4 py-1.5 rounded hover:bg-emerald-500/20 font-mono text-sm transition-colors flex items-center gap-2"
            >
              <Play size={16} weight="fill" />
              {loading ? 'Running...' : 'Run'}
            </Button>
            {url && (
              <div className="flex-1 max-w-[400px]">
                <input
                  type="text"
                  value={url}
                  readOnly
                  data-testid="preview-address-bar"
                  className="w-full bg-zinc-900 border border-zinc-800 text-sm text-zinc-400 px-4 py-1.5 rounded font-mono focus:outline-none focus:ring-1 focus:ring-orange-500"
                />
              </div>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-300"
            data-testid="close-preview-panel"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Preview */}
          <div className="flex-1 bg-white">
            {url ? (
              <iframe
                ref={iframeRef}
                src={url}
                className="w-full h-full border-0"
                title="preview"
                data-testid="preview-iframe"
              />
            ) : (
              <div className="flex items-center justify-center h-full text-zinc-600">
                <div className="text-center">
                  <Play size={64} className="mx-auto mb-4 text-zinc-800" />
                  <p className="font-mono text-sm">Click Run to preview your project</p>
                </div>
              </div>
            )}
          </div>

          {/* Terminal Logs */}
          <div className="w-96 border-l border-zinc-800 bg-black flex flex-col">
            <div className="p-2 border-b border-zinc-800 flex items-center gap-2">
              <TerminalIcon size={16} className="text-zinc-500" />
              <span className="text-xs font-mono text-zinc-500 uppercase tracking-widest">Terminal</span>
            </div>
            <div className="flex-1 overflow-y-auto p-2 font-mono text-xs" data-testid="terminal-logs">
              {logs.map((log, idx) => (
                <div
                  key={idx}
                  className={log.type === 'error' ? 'text-red-400' : 'text-green-400'}
                >
                  <span className="text-zinc-600">[{log.timestamp}]</span> {log.message}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PreviewPanel;
