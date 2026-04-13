from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime

class ProjectCreate(BaseModel):
    name: str

class ProjectResponse(BaseModel):
    id: str = Field(alias="_id")
    name: str
    owner: str
    users: List[str] = []
    fileTree: Dict[str, str] = {}
    created_at: datetime
    updated_at: datetime

    class Config:
        populate_by_name = True

class AddCollaborator(BaseModel):
    email: str

class UpdateFileTree(BaseModel):
    fileTree: Dict[str, str]
