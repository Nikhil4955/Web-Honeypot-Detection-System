import React, { useState, useEffect, useRef } from 'react';
import { useUser } from '../context/UserContext';
import { PaperPlaneRight } from '@phosphor-icons/react';
import { Button } from './ui/button';
import { Input } from './ui/input';

const Chat = ({ socket, projectId }) => {
  const { user } = useUser();
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (!socket || !projectId) return;

    // Join project room
    socket.emit('join_project', { projectId });

    // Listen for new messages
    socket.on('new_message', (data) => {
      setMessages((prev) => [...prev, data]);
    });

    return () => {
      socket.off('new_message');
      socket.emit('leave_project', { projectId });
    };
  }, [socket, projectId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || !socket) return;

    const timestamp = new Date().toISOString();
    const messageData = {
      projectId,
      message: inputMessage,
      user: { name: user.name, email: user.email },
      timestamp
    };

    // Check if message contains @ai
    if (inputMessage.includes('@ai')) {
      socket.emit('ai_message', messageData);
    } else {
      socket.emit('chat_message', messageData);
    }

    setInputMessage('');
  };

  const renderMessage = (msg) => {
    // Highlight @ai mentions
    const parts = msg.message.split(/(@ai)/g);
    return parts.map((part, i) =>
      part === '@ai' ? (
        <span key={i} className="text-yellow-500 bg-yellow-500/10 px-1.5 py-0.5 rounded-sm font-mono text-xs">
          @ai
        </span>
      ) : (
        part
      )
    );
  };

  return (
    <div className="h-full border-r border-zinc-800 bg-zinc-950 flex flex-col" data-testid="chat-panel">
      {/* Chat Header */}
      <div className="p-4 border-b border-zinc-800">
        <h3 className="text-sm font-mono text-zinc-300 uppercase tracking-widest">Project Chat</h3>
        <p className="text-xs text-zinc-500 mt-1">Use @ai to ask AI for help</p>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4" data-testid="chat-messages">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={msg.type === 'ai' ? 'mr-8' : 'ml-8'}
            data-testid={`chat-message-${idx}`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-zinc-500 font-mono">{msg.user?.name || 'User'}</span>
              <span className="text-xs text-zinc-600">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div
              className={
                msg.type === 'ai'
                  ? 'border border-zinc-800 bg-zinc-900/50 p-3 rounded-md text-sm text-zinc-200'
                  : 'bg-zinc-800 text-zinc-100 p-3 rounded-md text-sm'
              }
            >
              {renderMessage(msg)}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <form onSubmit={handleSendMessage} className="p-4 border-t border-zinc-800 bg-zinc-950">
        <div className="flex gap-2">
          <Input
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Type a message... (use @ai for AI help)"
            data-testid="chat-input"
            className="flex-1 bg-zinc-900 border-zinc-800 text-zinc-200 rounded-sm focus:ring-orange-500 focus:border-orange-500 text-sm"
          />
          <Button
            type="submit"
            disabled={!inputMessage.trim()}
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
