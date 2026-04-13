import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';
import { io } from 'socket.io-client';

const API_URL = process.env.REACT_APP_BACKEND_URL;

const ProjectContext = createContext();

export const useProject = () => {
  const context = useContext(ProjectContext);
  if (!context) {
    throw new Error('useProject must be used within ProjectProvider');
  }
  return context;
};

// Shared API instance with credentials
const api = axios.create({
  baseURL: `${API_URL}/api`,
  withCredentials: true
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soin_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const ProjectProvider = ({ children }) => {
  const [projects, setProjects] = useState([]);
  const [currentProject, setCurrentProject] = useState(null);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    const newSocket = io(API_URL, {
      path: '/api/socket.io',
      transports: ['websocket', 'polling']
    });
    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const fetchProjects = async () => {
    const { data } = await api.get('/projects');
    setProjects(data);
    return data;
  };

  const createProject = async (name) => {
    const { data } = await api.post('/projects', { name });
    setProjects((prev) => [...prev, data]);
    return data;
  };

  const fetchProject = async (projectId) => {
    const { data } = await api.get(`/projects/${projectId}`);
    setCurrentProject(data);
    return data;
  };

  const updateFileTree = async (projectId, fileTree) => {
    await api.put(`/projects/${projectId}/filetree`, { fileTree });
  };

  const addCollaborator = async (projectId, email) => {
    const { data } = await api.post(`/projects/${projectId}/collaborators`, { email });
    return data;
  };

  const fetchCollaborators = async (projectId) => {
    const { data } = await api.get(`/projects/${projectId}/collaborators`);
    return data;
  };

  return (
    <ProjectContext.Provider
      value={{
        projects,
        currentProject,
        setCurrentProject,
        socket,
        fetchProjects,
        createProject,
        fetchProject,
        updateFileTree,
        addCollaborator,
        fetchCollaborators
      }}
    >
      {children}
    </ProjectContext.Provider>
  );
};
