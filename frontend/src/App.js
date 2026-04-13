import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { UserProvider } from './context/UserContext';
import { ProjectProvider } from './context/ProjectContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './screens/Login';
import Register from './screens/Register';
import Dashboard from './screens/Dashboard';
import Workspace from './screens/Workspace';
import { Toaster } from './components/ui/sonner';
import './App.css';

function App() {
  return (
    <UserProvider>
      <ProjectProvider>
        <BrowserRouter>
          <div className="App">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/workspace/:projectId"
                element={
                  <ProtectedRoute>
                    <Workspace />
                  </ProtectedRoute>
                }
              />
            </Routes>
            <Toaster />
          </div>
        </BrowserRouter>
      </ProjectProvider>
    </UserProvider>
  );
}

export default App;
