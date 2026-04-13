from datetime import datetime, timezone
from fastapi import HTTPException
from bson import ObjectId

async def create_project(db, name: str, owner_id: str):
    now = datetime.now(timezone.utc).isoformat()
    project_doc = {
        "name": name,
        "owner": owner_id,
        "users": [owner_id],
        "fileTree": {},
        "created_at": now,
        "updated_at": now
    }
    result = await db.projects.insert_one(project_doc)
    return {
        "_id": str(result.inserted_id),
        "name": name,
        "owner": owner_id,
        "users": [owner_id],
        "fileTree": {},
        "created_at": now,
        "updated_at": now
    }

async def get_user_projects(db, user_id: str):
    projects = await db.projects.find({"users": user_id}).to_list(1000)
    for project in projects:
        project["_id"] = str(project["_id"])
    return projects

async def get_project_by_id(db, project_id: str, user_id: str):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if user_id not in project["users"]:
            raise HTTPException(status_code=403, detail="Access denied")
        project["_id"] = str(project["_id"])
        return project
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Invalid project ID")

async def add_collaborator(db, project_id: str, owner_id: str, collaborator_email: str):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if project["owner"] != owner_id:
            raise HTTPException(status_code=403, detail="Only owner can add collaborators")
        
        collaborator = await db.users.find_one({"email": collaborator_email.lower()})
        if not collaborator:
            raise HTTPException(status_code=404, detail="User not found")
        
        collaborator_id = str(collaborator["_id"])
        if collaborator_id in project["users"]:
            raise HTTPException(status_code=400, detail="User already a collaborator")
        
        await db.projects.update_one(
            {"_id": ObjectId(project_id)},
            {"$push": {"users": collaborator_id}, "$set": {"updated_at": datetime.now(timezone.utc)}}
        )
        return {"message": "Collaborator added successfully"}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=str(e))

async def update_file_tree(db, project_id: str, user_id: str, file_tree: dict):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if user_id not in project["users"]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        await db.projects.update_one(
            {"_id": ObjectId(project_id)},
            {"$set": {"fileTree": file_tree, "updated_at": datetime.now(timezone.utc)}}
        )
        return {"message": "File tree updated successfully"}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=str(e))

async def get_project_collaborators(db, project_id: str, user_id: str):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if user_id not in project["users"]:
            raise HTTPException(status_code=403, detail="Access denied")
        
        collaborators = []
        for uid in project["users"]:
            user = await db.users.find_one({"_id": ObjectId(uid)}, {"_id": 0, "email": 1, "name": 1})
            if user:
                collaborators.append(user)
        return collaborators
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail=str(e))
