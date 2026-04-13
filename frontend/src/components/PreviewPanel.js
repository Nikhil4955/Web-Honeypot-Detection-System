import React, { useState, useRef, useCallback } from 'react';
import { Play, X, Terminal as TerminalIcon, ArrowClockwise, Globe } from '@phosphor-icons/react';
import { Button } from './ui/button';

const PreviewPanel = ({ fileTree, buildCommand, startCommand, isOpen, onClose }) => {
  const [url, setUrl] = useState('');
  const [addressInput, setAddressInput] = useState('');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState('terminal'); // 'terminal' | 'preview'
  const iframeRef = useRef(null);
  const logsEndRef = useRef(null);

  const addLog = useCallback((message, type = 'info') => {
    setLogs((prev) => [...prev, { message, type, timestamp: new Date().toLocaleTimeString() }]);
    setTimeout(() => logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
  }, []);

  const runProject = async () => {
    if (!fileTree || Object.keys(fileTree).length === 0) {
      addLog('No files to run', 'error');
      return;
    }

    setLoading(true);
    setLogs([]);
    setUrl('');
    addLog('Starting project...');

    // Check if it's a simple HTML project (has index.html but no package.json)
    const hasHtml = Object.keys(fileTree).some((f) => f.endsWith('.html'));
    const hasPackageJson = Object.keys(fileTree).some((f) => f === 'package.json' || f.endsWith('/package.json'));

    if (hasHtml && !hasPackageJson) {
      // Simple HTML preview — create a blob URL
      addLog('Detected static HTML project');
      try {
        const htmlFile = Object.keys(fileTree).find((f) => f.endsWith('.html'));
        let htmlContent = fileTree[htmlFile];

        // Inline CSS files
        Object.keys(fileTree).forEach((f) => {
          if (f.endsWith('.css')) {
            const cssContent = fileTree[f];
            const linkTag = `<link rel="stylesheet" href="${f}">`;
            const styleTag = `<style>/* ${f} */\n${cssContent}\n</style>`;
            if (htmlContent.includes(linkTag)) {
              htmlContent = htmlContent.replace(linkTag, styleTag);
            } else {
              // Insert before </head>
              htmlContent = htmlContent.replace('</head>', `${styleTag}\n</head>`);
            }
          }
        });

        // Inline JS files
        Object.keys(fileTree).forEach((f) => {
          if (f.endsWith('.js')) {
            const jsContent = fileTree[f];
            const scriptTag = `<script src="${f}"></script>`;
            const inlineScript = `<script>/* ${f} */\n${jsContent}\n</script>`;
            if (htmlContent.includes(scriptTag)) {
              htmlContent = htmlContent.replace(scriptTag, inlineScript);
            } else {
              // Insert before </body>
              htmlContent = htmlContent.replace('</body>', `${inlineScript}\n</body>`);
            }
          }
        });

        const blob = new Blob([htmlContent], { type: 'text/html' });
        const blobUrl = URL.createObjectURL(blob);
        setUrl(blobUrl);
        setAddressInput('index.html (local preview)');
        setMode('preview');
        addLog('HTML preview ready!', 'success');
      } catch (err) {
        addLog(`Error creating preview: ${err.message}`, 'error');
      }
      setLoading(false);
      return;
    }

    // Node.js project — try WebContainers
    try {
      addLog('Attempting to boot WebContainer...');
      const { WebContainer } = await import('@webcontainer/api');
      const instance = await WebContainer.boot();
      addLog('WebContainer booted');

      // Mount files
      addLog('Mounting files...');
      const wcFiles = convertFileTreeToWebContainer(fileTree);
      await instance.mount(wcFiles);
      addLog('Files mounted');

      // Install dependencies
      const cmd = buildCommand || 'npm install';
      addLog(`Running: ${cmd}`);
      const installProcess = await instance.spawn('sh', ['-c', cmd]);

      const installReader = installProcess.output.getReader();
      (async () => {
        while (true) {
          const { done, value } = await installReader.read();
          if (done) break;
          addLog(value);
        }
      })();

      const installExit = await installProcess.exit;
      if (installExit !== 0) {
        addLog(`Build process exited with code ${installExit}`, 'error');
      } else {
        addLog('Dependencies installed');
      }

      // Start server
      const start = startCommand || 'node index.js';
      addLog(`Running: ${start}`);
      const startProcess = await instance.spawn('sh', ['-c', start]);

      const startReader = startProcess.output.getReader();
      (async () => {
        while (true) {
          const { done, value } = await startReader.read();
          if (done) break;
          addLog(value);
        }
      })();

      instance.on('server-ready', (port, serverUrl) => {
        addLog(`Server ready on port ${port}`, 'success');
        setUrl(serverUrl);
        setAddressInput(serverUrl);
        setMode('preview');
      });
    } catch (err) {
      addLog(`WebContainer error: ${err.message}`, 'error');
      addLog('WebContainers require cross-origin isolation headers (COOP/COEP).', 'warn');
      addLog('Falling back to terminal-only mode. Output shown below.', 'warn');

      // Fallback: just show the file contents as terminal output
      if (Object.keys(fileTree).some((f) => f.endsWith('.html'))) {
        addLog('Tip: HTML files detected — creating local preview...', 'info');
        const htmlFile = Object.keys(fileTree).find((f) => f.endsWith('.html'));
        if (htmlFile) {
          let htmlContent = fileTree[htmlFile];
          Object.keys(fileTree).forEach((f) => {
            if (f.endsWith('.css')) {
              htmlContent = htmlContent.replace('</head>', `<style>${fileTree[f]}</style>\n</head>`);
            }
            if (f.endsWith('.js')) {
              htmlContent = htmlContent.replace('</body>', `<script>${fileTree[f]}</script>\n</body>`);
            }
          });
          const blob = new Blob([htmlContent], { type: 'text/html' });
          const blobUrl = URL.createObjectURL(blob);
          setUrl(blobUrl);
          setAddressInput('index.html (local preview)');
          setMode('preview');
          addLog('Fallback HTML preview created!', 'success');
        }
      }
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
          current[part] = { file: { contents: content } };
        } else {
          if (!current[part]) current[part] = { directory: {} };
          current = current[part].directory;
        }
      });
    });
    return structure;
  };

  const handleNavigate = (e) => {
    e.preventDefault();
    if (addressInput && iframeRef.current) {
      setUrl(addressInput);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center" data-testid="preview-panel">
      <div className="w-[90vw] h-[90vh] bg-zinc-950 border border-zinc-800 rounded-sm flex flex-col">
        {/* Header */}
        <div className="h-12 border-b border-zinc-800 bg-zinc-950 flex items-center gap-3 px-4">
          <Button
            onClick={runProject}
            disabled={loading}
            data-testid="run-project-button"
            className="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-4 py-1.5 rounded hover:bg-emerald-500/20 font-mono text-sm transition-colors flex items-center gap-2 shrink-0"
          >
            <Play size={14} weight="fill" />
            {loading ? 'Running...' : 'Run'}
          </Button>

          {/* Address bar */}
          <form onSubmit={handleNavigate} className="flex-1 max-w-[500px]">
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded overflow-hidden focus-within:ring-1 focus-within:ring-orange-500">
              <Globe size={14} className="text-zinc-500 ml-3 shrink-0" />
              <input
                type="text"
                value={addressInput}
                onChange={(e) => setAddressInput(e.target.value)}
                data-testid="preview-address-bar"
                placeholder="Preview URL will appear here..."
                className="w-full bg-transparent text-sm text-zinc-400 px-2 py-1.5 font-mono focus:outline-none"
              />
            </div>
          </form>

          {/* Mode toggle */}
          <div className="flex items-center gap-1 shrink-0">
            <Button
              onClick={() => setMode('preview')}
              className={`px-3 py-1 text-xs font-mono rounded-sm transition-colors h-auto ${
                mode === 'preview'
                  ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20'
                  : 'bg-zinc-800 text-zinc-500 border border-zinc-800'
              }`}
            >
              Preview
            </Button>
            <Button
              onClick={() => setMode('terminal')}
              className={`px-3 py-1 text-xs font-mono rounded-sm transition-colors h-auto ${
                mode === 'terminal'
                  ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20'
                  : 'bg-zinc-800 text-zinc-500 border border-zinc-800'
              }`}
            >
              Terminal
            </Button>
          </div>

          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-300 shrink-0"
            data-testid="close-preview-panel"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden">
          {mode === 'preview' ? (
            <div className="h-full bg-white">
              {url ? (
                <iframe
                  ref={iframeRef}
                  src={url}
                  className="w-full h-full border-0"
                  title="preview"
                  sandbox="allow-scripts allow-same-origin allow-forms allow-modals allow-popups"
                  data-testid="preview-iframe"
                />
              ) : (
                <div className="flex items-center justify-center h-full bg-[#0d0d0f]">
                  <div className="text-center text-zinc-600">
                    <Play size={48} className="mx-auto mb-3 text-zinc-800" />
                    <p className="font-mono text-sm">Click Run to preview your project</p>
                    <p className="text-xs text-zinc-700 mt-2">HTML files get instant preview, Node.js uses WebContainers</p>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full bg-black flex flex-col">
              <div className="p-2 border-b border-zinc-800 flex items-center gap-2 shrink-0">
                <TerminalIcon size={14} className="text-zinc-500" />
                <span className="text-xs font-mono text-zinc-500 uppercase tracking-widest">Terminal Output</span>
                <div className="flex-1" />
                <Button
                  onClick={() => setLogs([])}
                  className="bg-transparent hover:bg-zinc-800 text-zinc-600 hover:text-zinc-400 rounded-sm p-1 h-auto"
                >
                  <ArrowClockwise size={12} />
                </Button>
              </div>
              <div className="flex-1 overflow-y-auto p-3 font-mono text-xs" data-testid="terminal-logs">
                {logs.length === 0 && (
                  <div className="text-zinc-700">$ Click "Run" to execute your project...</div>
                )}
                {logs.map((log, idx) => (
                  <div
                    key={idx}
                    className={
                      log.type === 'error'
                        ? 'text-red-400'
                        : log.type === 'success'
                        ? 'text-emerald-400'
                        : log.type === 'warn'
                        ? 'text-yellow-500'
                        : 'text-green-400/80'
                    }
                  >
                    <span className="text-zinc-700 mr-2">[{log.timestamp}]</span>
                    {log.message}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PreviewPanel;
