/**
 * Global Configuration and State Management
 * Shared state variables used across the admin panel
 */

// API Configuration
const API_BASE = window.location.origin;

// Authentication state
let authToken = localStorage.getItem('jwt_token');
let refreshToken = localStorage.getItem('refresh_token');
let tempMFAToken = null;
let currentUser = null;

// Script management state
let currentScript = null;
let currentScriptDetails = null;
let isEditMode = false;

// Delete confirmation state
let currentDeleteScriptId = null;

// Export configuration for use in other modules
window.AdminConfig = {
    API_BASE,
    getAuthToken: () => authToken,
    setAuthToken: (token) => { authToken = token; },
    getRefreshToken: () => refreshToken,
    setRefreshToken: (token) => { refreshToken = token; },
    getTempMFAToken: () => tempMFAToken,
    setTempMFAToken: (token) => { tempMFAToken = token; },
    getCurrentUser: () => currentUser,
    setCurrentUser: (user) => { currentUser = user; },
    getCurrentScript: () => currentScript,
    setCurrentScript: (script) => { currentScript = script; },
    getCurrentScriptDetails: () => currentScriptDetails,
    setCurrentScriptDetails: (details) => { currentScriptDetails = details; },
    getIsEditMode: () => isEditMode,
    setIsEditMode: (mode) => { isEditMode = mode; },
    getCurrentDeleteScriptId: () => currentDeleteScriptId,
    setCurrentDeleteScriptId: (id) => { currentDeleteScriptId = id; }
};
