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
from datetime import datetime, timezone
from bson import ObjectId
from routes.auth_routes import create_auth_router
from routes.project_routes import create_project_router
from services.auth_service import seed_admin
from services.ai_service import get_ai_response, parse_ai_response
from utils.auth_utils import get_current_user
from fastapi import Request

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',
    logger=False,
    engineio_logger=False
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

# Chat history endpoint
@app.get("/api/projects/{project_id}/messages")
async def get_project_messages(project_id: str, request: Request):
    user = await get_current_user(request, db)
    # Verify user is in project
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        if not project or user["_id"] not in project.get("users", []):
            return []
    except Exception:
        return []
    
    messages = await db.messages.find(
        {"project_id": project_id},
        {"_id": 0}
    ).sort("created_at", 1).to_list(500)
    return messages


# Helper: save message to MongoDB
async def save_message(project_id, message, user_info, msg_type, timestamp=None):
    msg_doc = {
        "project_id": project_id,
        "message": message,
        "user": user_info,
        "type": msg_type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.messages.insert_one(msg_doc)


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
    timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())
    
    if project_id and message and user:
        msg_payload = {
            'message': message,
            'user': user,
            'timestamp': timestamp,
            'type': 'user'
        }
        # Save to MongoDB
        await save_message(project_id, message, user, 'user', timestamp)
        # Broadcast to all users in the project room
        await sio.emit('new_message', msg_payload, room=project_id)

@sio.event
async def ai_message(sid, data):
    """Handle @ai messages"""
    project_id = data.get('projectId')
    message = data.get('message')
    user = data.get('user')
    timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())
    
    if project_id and message and user:
        # Save & broadcast user message
        user_msg = {
            'message': message,
            'user': user,
            'timestamp': timestamp,
            'type': 'user'
        }
        await save_message(project_id, message, user, 'user', timestamp)
        await sio.emit('new_message', user_msg, room=project_id)
        
        # Get AI response
        ai_response = await get_ai_response(message, project_id)
        ai_user = {'name': 'SOIN AI', 'email': 'ai@soin.dev'}
        ai_timestamp = datetime.now(timezone.utc).isoformat()
        
        # Try to parse as JSON for file generation
        try:
            parsed = parse_ai_response(ai_response)
            if 'fileTree' in parsed:
                # Send file tree update
                await sio.emit('file_tree_update', {
                    'fileTree': parsed['fileTree'],
                    'buildCommand': parsed.get('buildCommand', ''),
                    'startCommand': parsed.get('startCommand', ''),
                    'timestamp': ai_timestamp
                }, room=project_id)
                
                # Save file tree to project
                try:
                    await db.projects.update_one(
                        {"_id": ObjectId(project_id)},
                        {"$set": {"fileTree": parsed['fileTree'], "updated_at": ai_timestamp}}
                    )
                except Exception:
                    pass
                
                # Send and save confirmation message
                file_count = len(parsed['fileTree'])
                confirm_msg = f"I've created {file_count} file(s) for you. Check the file tree on the right!"
                await save_message(project_id, confirm_msg, ai_user, 'ai', ai_timestamp)
                await sio.emit('new_message', {
                    'message': confirm_msg,
                    'user': ai_user,
                    'timestamp': ai_timestamp,
                    'type': 'ai'
                }, room=project_id)
            else:
                # Regular AI response
                ai_text = parsed.get('message', ai_response)
                await save_message(project_id, ai_text, ai_user, 'ai', ai_timestamp)
                await sio.emit('new_message', {
                    'message': ai_text,
                    'user': ai_user,
                    'timestamp': ai_timestamp,
                    'type': 'ai'
                }, room=project_id)
        except Exception as e:
            err_msg = f"Error processing AI request: {str(e)}"
            await save_message(project_id, err_msg, ai_user, 'ai', ai_timestamp)
            await sio.emit('new_message', {
                'message': err_msg,
                'user': ai_user,
                'timestamp': ai_timestamp,
                'type': 'ai'
            }, room=project_id)

@sio.event
async def file_update(sid, data):
    """Handle file content updates"""
    project_id = data.get('projectId')
    file_path = data.get('filePath')
    content = data.get('content')
    
    if project_id and file_path is not None:
        await sio.emit('file_updated', {
            'filePath': file_path,
            'content': content
        }, room=project_id, skip_sid=sid)

# Startup event
@app.on_event("startup")
async def startup_event():
    await db.users.create_index("email", unique=True)
    await db.login_attempts.create_index("identifier")
    await db.messages.create_index([("project_id", 1), ("created_at", 1)])
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
