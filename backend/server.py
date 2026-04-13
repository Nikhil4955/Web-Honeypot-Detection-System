from fastapi import FastAPI
from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import socketio
import logging
from routes.auth_routes import create_auth_router
from routes.project_routes import create_project_router
from services.auth_service import seed_admin
from services.ai_service import get_ai_response, parse_ai_response

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',
    logger=True,
    engineio_logger=True
)

# Create FastAPI app
app = FastAPI()

# Create Socket.IO ASGI app - use /api/socket.io path for Kubernetes routing
socket_app = socketio.ASGIApp(sio, app, socketio_path='/api/socket.io')

# CORS middleware
frontend_url = os.environ.get('FRONTEND_URL', 'https://ai-dev-workspace-7.preview.emergentagent.com')
cors_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
if frontend_url not in cors_origins:
    cors_origins.append(frontend_url)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
auth_router = create_auth_router(db)
project_router = create_project_router(db)

app.include_router(auth_router, prefix="/api")
app.include_router(project_router, prefix="/api")

# Health check
@app.get("/api/health")
async def health():
    return {"status": "ok"}

# Socket.IO event handlers
@sio.event
async def connect(sid, environ):
    logging.info(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    logging.info(f"Client disconnected: {sid}")

@sio.event
async def join_project(sid, data):
    project_id = data.get('projectId')
    if project_id:
        await sio.enter_room(sid, project_id)
        logging.info(f"Client {sid} joined project {project_id}")

@sio.event
async def leave_project(sid, data):
    project_id = data.get('projectId')
    if project_id:
        await sio.leave_room(sid, project_id)
        logging.info(f"Client {sid} left project {project_id}")

@sio.event
async def chat_message(sid, data):
    """Handle regular chat messages"""
    project_id = data.get('projectId')
    message = data.get('message')
    user = data.get('user')
    
    if project_id and message and user:
        # Broadcast to all users in the project room
        await sio.emit('new_message', {
            'message': message,
            'user': user,
            'timestamp': data.get('timestamp'),
            'type': 'user'
        }, room=project_id)

@sio.event
async def ai_message(sid, data):
    """Handle @ai messages"""
    project_id = data.get('projectId')
    message = data.get('message')
    user = data.get('user')
    
    if project_id and message and user:
        # Echo user message
        await sio.emit('new_message', {
            'message': message,
            'user': user,
            'timestamp': data.get('timestamp'),
            'type': 'user'
        }, room=project_id)
        
        # Get AI response
        ai_response = await get_ai_response(message, project_id)
        
        # Try to parse as JSON for file generation
        try:
            parsed = parse_ai_response(ai_response)
            if 'fileTree' in parsed:
                # Send file tree update
                await sio.emit('file_tree_update', {
                    'fileTree': parsed['fileTree'],
                    'buildCommand': parsed.get('buildCommand', ''),
                    'startCommand': parsed.get('startCommand', ''),
                    'timestamp': data.get('timestamp')
                }, room=project_id)
                
                # Send confirmation message
                file_count = len(parsed['fileTree'])
                await sio.emit('new_message', {
                    'message': f"I've created {file_count} file(s) for you. Check the file tree on the right!",
                    'user': {'name': 'SOIN AI', 'email': 'ai@soin.dev'},
                    'timestamp': data.get('timestamp'),
                    'type': 'ai'
                }, room=project_id)
            else:
                # Regular AI response
                await sio.emit('new_message', {
                    'message': parsed.get('message', ai_response),
                    'user': {'name': 'SOIN AI', 'email': 'ai@soin.dev'},
                    'timestamp': data.get('timestamp'),
                    'type': 'ai'
                }, room=project_id)
        except Exception as e:
            # Send error message
            await sio.emit('new_message', {
                'message': f"Error processing AI request: {str(e)}",
                'user': {'name': 'SOIN AI', 'email': 'ai@soin.dev'},
                'timestamp': data.get('timestamp'),
                'type': 'ai'
            }, room=project_id)

@sio.event
async def file_update(sid, data):
    """Handle file content updates"""
    project_id = data.get('projectId')
    file_path = data.get('filePath')
    content = data.get('content')
    
    if project_id and file_path is not None:
        # Broadcast file update to all users in the project
        await sio.emit('file_updated', {
            'filePath': file_path,
            'content': content
        }, room=project_id, skip_sid=sid)

# Startup event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    
    # Seed admin
    await seed_admin(db)
    
    logging.info("Application started successfully")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
