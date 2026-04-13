# SOIN - Software Engineer AI Platform

## Original Problem Statement
Build SOIN, a real-time collaborative AI development platform with auth, project management, chat with @ai trigger, code editor, file tree, collaborators, and WebContainers.

## Architecture
- Backend: FastAPI + python-socketio, MongoDB via Motor
- Frontend: React 19 + Socket.io-client + WebContainers API + Shadcn UI
- AI: Gemini 3 Flash via Emergent LLM key
- Auth: JWT (httpOnly cookies + Bearer token localStorage fallback)
- Real-time: Socket.IO (path: /api/socket.io)

## What's Been Implemented (April 13, 2026)
- [x] JWT auth (register, login, logout, me, refresh) with dual token strategy
- [x] Project CRUD + collaborator management
- [x] Socket.IO real-time messaging with persistent chat (MongoDB)
- [x] @ai trigger -> Gemini 3 Flash -> JSON fileTree generation
- [x] Robust AI response parser (handles prefixed/wrapped JSON)
- [x] **File tree clicking opens files in editor** (fixed)
- [x] **Manual file creation** (+ button in file tree and editor toolbar)
- [x] **Manual code writing** with tab support, line numbers, Ctrl+S save
- [x] **AI code review/fix** (magic wand button sends current code to AI)
- [x] **Run button** with HTML preview (blob URL with inline CSS/JS) + WebContainers for Node.js
- [x] Tab management with unsaved change indicators
- [x] File deletion from tree
- [x] Status bar (filename, line count, save state)
- [x] Connection status indicator in chat
- [x] AI loading spinner ("Thinking...")
- [x] Preview/Terminal toggle in run panel

## Prioritized Backlog
### P1
- Monaco Editor for syntax highlighting
- Real-time cursor presence for collaborators
- File rename support

### P2  
- Project deletion
- Password reset flow
- User profile editing
- Keyboard shortcuts guide
