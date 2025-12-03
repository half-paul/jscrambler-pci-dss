/**
 * API Module
 * Handles all API calls with automatic token refresh
 */

// API Calls with automatic token refresh
async function apiCall(endpoint, options = {}, retryCount = 0) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${AdminConfig.getAuthToken()}`,
            ...options.headers
        }
    });

    if (response.status === 401) {
        const error = await response.json();

        // Try to refresh token if expired
        if (error.code === 'TOKEN_EXPIRED' && AdminConfig.getRefreshToken() && retryCount === 0) {
            console.log('Token expired, attempting refresh...');
            const refreshed = await refreshAccessToken();
            if (refreshed) {
                // Retry the original request with new token
                return apiCall(endpoint, options, retryCount + 1);
            }
        }

        // Refresh failed or no refresh token - logout
        logout();
        throw new Error('Authentication required');
    }

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Request failed');
    }

    return response.json();
}
