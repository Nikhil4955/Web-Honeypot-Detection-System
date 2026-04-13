import React, { useState, useEffect, useRef } from 'react';
import { useUser } from '../context/UserContext';
import { PaperPlaneRight, CircleNotch, WifiHigh, WifiSlash } from '@phosphor-icons/react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import axios from 'axios';

const API_URL = process.env.REACT_APP_BACKEND_URL;

const api = axios.create({
  baseURL: `${API_URL}/api`,
  withCredentials: true
});
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soin_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

const Chat = ({ socket, projectId }) => {
  const { user } = useUser();
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [connected, setConnected] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const messagesEndRef = useRef(null);

  // Load chat history from MongoDB
  useEffect(() => {
    if (!projectId) return;
    const loadHistory = async () => {
      try {
        const { data } = await api.get(`/projects/${projectId}/messages`);
        if (data && data.length > 0) {
          setMessages(data);
        }
        setHistoryLoaded(true);
      } catch (err) {
        console.error('Error loading chat history:', err);
        setHistoryLoaded(true);
      }
    };
    loadHistory();
  }, [projectId]);

  // Socket.IO connection & events
  useEffect(() => {
    if (!socket || !projectId) return;

    const onConnect = () => {
      setConnected(true);
      socket.emit('join_project', { projectId });
    };

    const onDisconnect = () => {
      setConnected(false);
    };

    const onNewMessage = (data) => {
      setMessages((prev) => [...prev, data]);
      if (data.type === 'ai') {
        setAiLoading(false);
      }
    };

    if (socket.connected) {
      setConnected(true);
      socket.emit('join_project', { projectId });
    }

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('new_message', onNewMessage);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('new_message', onNewMessage);
      socket.emit('leave_project', { projectId });
    };
  }, [socket, projectId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || !socket || !connected) return;

    const timestamp = new Date().toISOString();
    const messageData = {
      projectId,
      message: inputMessage,
      user: { name: user.name, email: user.email },
      timestamp
    };

    if (inputMessage.includes('@ai')) {
      setAiLoading(true);
      socket.emit('ai_message', messageData);
    } else {
      socket.emit('chat_message', messageData);
    }

    setInputMessage('');
  };

  const renderMessageContent = (msg) => {
    const parts = msg.message.split(/(@ai)/g);
    return parts.map((part, i) =>
      part === '@ai' ? (
        <span key={i} className="text-yellow-500 bg-yellow-500/10 px-1.5 py-0.5 rounded-sm font-mono text-xs">
          @ai
        </span>
      ) : (
        <span key={i}>{part}</span>
      )
    );
  };

  return (
    <div className="h-full border-r border-zinc-800 bg-zinc-950 flex flex-col" data-testid="chat-panel">
      {/* Chat Header */}
      <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono text-zinc-300 uppercase tracking-widest">Project Chat</h3>
          <p className="text-xs text-zinc-500 mt-1">Use @ai to ask AI for help</p>
        </div>
        <div className="flex items-center gap-1.5" data-testid="chat-connection-status">
          {connected ? (
            <WifiHigh size={14} className="text-emerald-500" />
          ) : (
            <WifiSlash size={14} className="text-red-400" />
          )}
          <span className={`text-xs font-mono ${connected ? 'text-emerald-500' : 'text-red-400'}`}>
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4" data-testid="chat-messages">
        {!historyLoaded && (
          <div className="flex items-center justify-center py-4">
            <CircleNotch size={20} className="text-zinc-500 animate-spin" />
            <span className="text-zinc-500 text-xs ml-2">Loading messages...</span>
          </div>
        )}
        {historyLoaded && messages.length === 0 && (
          <div className="text-center py-8">
            <p className="text-zinc-600 text-sm font-mono">No messages yet</p>
            <p className="text-zinc-700 text-xs mt-1">Send a message or type @ai for AI help</p>
          </div>
        )}
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={msg.type === 'ai' ? 'mr-8' : 'ml-8'}
            data-testid={`chat-message-${idx}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs font-mono ${msg.type === 'ai' ? 'text-orange-500' : 'text-zinc-500'}`}>
                {msg.user?.name || 'User'}
              </span>
              <span className="text-xs text-zinc-600">
                {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ''}
              </span>
            </div>
            <div
              className={
                msg.type === 'ai'
                  ? 'border border-zinc-800 bg-zinc-900/50 p-3 rounded-md text-sm text-zinc-200'
                  : 'bg-zinc-800 text-zinc-100 p-3 rounded-md text-sm'
              }
            >
              {renderMessageContent(msg)}
            </div>
          </div>
        ))}
        {aiLoading && (
          <div className="mr-8" data-testid="ai-loading-indicator">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono text-orange-500">SOIN AI</span>
            </div>
            <div className="border border-zinc-800 bg-zinc-900/50 p-3 rounded-md text-sm text-zinc-400 flex items-center gap-2">
              <CircleNotch size={14} className="animate-spin" />
              Thinking...
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <form onSubmit={handleSendMessage} className="p-4 border-t border-zinc-800 bg-zinc-950">
        <div className="flex gap-2">
          <Input
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder={connected ? "Type a message... (use @ai for AI help)" : "Connecting..."}
            disabled={!connected}
            data-testid="chat-input"
            className="flex-1 bg-zinc-900 border-zinc-800 text-zinc-200 rounded-sm focus:ring-orange-500 focus:border-orange-500 text-sm"
          />
          <Button
            type="submit"
            disabled={!inputMessage.trim() || !connected}
            data-testid="chat-send-button"
            className="bg-orange-500 hover:bg-orange-600 text-white rounded-sm px-4 transition-colors"
          >
            <PaperPlaneRight size={16} weight="fill" />
          </Button>
        </div>
      </form>
    </div>
  );
};

export default Chat;
