from fastapi import APIRouter, Request
from models.project import ProjectCreate, AddCollaborator, UpdateFileTree
from services.project_service import (
    create_project,
    get_user_projects,
    get_project_by_id,
    add_collaborator,
    update_file_tree,
    get_project_collaborators
)
from utils.auth_utils import get_current_user

def create_project_router(db):
    router = APIRouter(prefix="/projects", tags=["projects"])

    @router.post("")
    async def create(project_data: ProjectCreate, request: Request):
        user = await get_current_user(request, db)
        project = await create_project(db, project_data.name, user["_id"])
        return project

    @router.get("")
    async def get_projects(request: Request):
        user = await get_current_user(request, db)
        projects = await get_user_projects(db, user["_id"])
        return projects

    @router.get("/{project_id}")
    async def get_project(project_id: str, request: Request):
        user = await get_current_user(request, db)
        project = await get_project_by_id(db, project_id, user["_id"])
        return project

    @router.post("/{project_id}/collaborators")
    async def add_collaborator_route(project_id: str, data: AddCollaborator, request: Request):
        user = await get_current_user(request, db)
        result = await add_collaborator(db, project_id, user["_id"], data.email)
        return result

    @router.get("/{project_id}/collaborators")
    async def get_collaborators(project_id: str, request: Request):
        user = await get_current_user(request, db)
        collaborators = await get_project_collaborators(db, project_id, user["_id"])
        return collaborators

    @router.put("/{project_id}/filetree")
    async def update_filetree(project_id: str, data: UpdateFileTree, request: Request):
        user = await get_current_user(request, db)
        result = await update_file_tree(db, project_id, user["_id"], data.fileTree)
        return result

    return router
