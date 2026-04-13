# SOIN - Software Engineer AI Platform

## Original Problem Statement
Build SOIN, a real-time MERN-based collaborative AI agent platform with authentication, project management, real-time chat with AI (@ai trigger), code editor, file tree, collaborator management, and WebContainers for browser-based code execution.

## Architecture
- **Backend**: FastAPI + python-socketio (ASGI), MongoDB via Motor
- **Frontend**: React 19 + Socket.io-client + WebContainers API + Shadcn UI
- **AI**: Gemini 3 Flash via Emergent LLM key (emergentintegrations library)
- **Auth**: JWT (httpOnly cookies + Bearer token fallback) + Bcrypt
- **Real-time**: Socket.IO (path: /api/socket.io for Kubernetes routing)

## User Personas
- **Solo Developer**: Creates projects, uses @ai to generate code, previews in WebContainers
- **Team Lead**: Creates projects, adds collaborators, monitors real-time progress
- **Collaborator**: Joins shared projects, contributes via chat and code editing

## Core Requirements (Static)
1. Email/Password JWT authentication
2. Project CRUD with fileTree persistence in MongoDB
3. Three-column workspace: Chat, Code Editor, File Tree
4. @ai trigger for Gemini AI code generation
5. Real-time collaboration via Socket.IO
6. Collaborator management (add by email)
7. WebContainers for browser-based code execution
8. Dark theme IDE aesthetic

## What's Been Implemented (April 13, 2026)
- [x] JWT authentication (register, login, logout, me, refresh)
- [x] Admin seeding with configurable credentials
- [x] Project CRUD (create, list, get by ID)
- [x] Collaborator management (add, list)
- [x] File tree storage/update in MongoDB
- [x] Socket.IO real-time messaging
- [x] @ai trigger -> Gemini 3 Flash AI code generation
- [x] AI returns JSON fileTree -> auto-populates file tree and editor
- [x] Chat panel with @ai highlighting (yellow badge)
- [x] Tabbed code editor with line numbers
- [x] File tree explorer with folder structure
- [x] Collaborators panel (slide-out with avatar + email)
- [x] Preview panel with WebContainers boot, terminal logs
- [x] Dark theme (zinc/obsidian + orange accents)
- [x] JetBrains Mono + IBM Plex Sans typography

## Prioritized Backlog
### P0 (Critical)
- None remaining for MVP

### P1 (Important)
- Chat message persistence to MongoDB
- File tree persistence on page reload
- WebContainers cross-browser compatibility testing
- Brute force protection for login

### P2 (Nice to Have)
- Syntax highlighting in code editor (Monaco/CodeMirror)
- Multiple file tab management improvements
- Real-time cursor presence for collaborators
- Project deletion
- Password reset flow
- User profile editing

## Next Tasks
1. Integrate Monaco Editor for proper syntax highlighting
2. Add chat message history persistence in MongoDB
3. Implement proper WebContainers error handling
4. Add file upload/download capability
5. Implement user online presence indicators
