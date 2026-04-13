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

export const ProjectProvider = ({ children }) => {
  const [projects, setProjects] = useState([]);
  const [currentProject, setCurrentProject] = useState(null);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io(API_URL, {
      transports: ['websocket', 'polling']
    });
    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const fetchProjects = async () => {
    try {
      const { data } = await axios.get(`${API_URL}/api/projects`, {
        withCredentials: true
      });
      setProjects(data);
      return data;
    } catch (error) {
      console.error('Error fetching projects:', error);
      throw error;
    }
  };

  const createProject = async (name) => {
    try {
      const { data } = await axios.post(
        `${API_URL}/api/projects`,
        { name },
        { withCredentials: true }
      );
      setProjects([...projects, data]);
      return data;
    } catch (error) {
      console.error('Error creating project:', error);
      throw error;
    }
  };

  const fetchProject = async (projectId) => {
    try {
      const { data } = await axios.get(`${API_URL}/api/projects/${projectId}`, {
        withCredentials: true
      });
      setCurrentProject(data);
      return data;
    } catch (error) {
      console.error('Error fetching project:', error);
      throw error;
    }
  };

  const updateFileTree = async (projectId, fileTree) => {
    try {
      await axios.put(
        `${API_URL}/api/projects/${projectId}/filetree`,
        { fileTree },
        { withCredentials: true }
      );
    } catch (error) {
      console.error('Error updating file tree:', error);
      throw error;
    }
  };

  const addCollaborator = async (projectId, email) => {
    try {
      const { data } = await axios.post(
        `${API_URL}/api/projects/${projectId}/collaborators`,
        { email },
        { withCredentials: true }
      );
      return data;
    } catch (error) {
      console.error('Error adding collaborator:', error);
      throw error;
    }
  };

  const fetchCollaborators = async (projectId) => {
    try {
      const { data } = await axios.get(
        `${API_URL}/api/projects/${projectId}/collaborators`,
        { withCredentials: true }
      );
      return data;
    } catch (error) {
      console.error('Error fetching collaborators:', error);
      throw error;
    }
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
