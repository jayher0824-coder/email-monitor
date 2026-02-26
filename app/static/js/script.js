// Email Monitor - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    console.log('Email Monitor initialized');
    setupEventListeners();
}

function setupEventListeners() {
    // Add any dynamic event listeners here
    const syncButton = document.querySelector('[onclick="syncEmails()"]');
    if (syncButton) {
        syncButton.addEventListener('click', function(e) {
            e.preventDefault();
        });
    }
}

// Utility functions
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function truncateText(text, maxLength) {
    if (text.length > maxLength) {
        return text.substring(0, maxLength) + '...';
    }
    return text;
}

// For future enhancements
function notifyUser(message, type = 'info') {
    console.log(`[${type}] ${message}`);
    // Could be expanded to show toast notifications
}

function showError(message) {
    notifyUser(message, 'error');
    alert(`Error: ${message}`);
}

function showSuccess(message) {
    notifyUser(message, 'success');
}
