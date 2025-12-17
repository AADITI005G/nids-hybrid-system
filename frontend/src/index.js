import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Find the root element where the React app will be mounted
const container = document.getElementById('root');

// Check if the container element exists before creating the root
if (container) {
  const root = ReactDOM.createRoot(container);
  
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
} else {
  console.error("Failed to find the root element with ID 'root' in index.html.");
}
