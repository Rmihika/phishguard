import React, { useState, useCallback } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './index.css';
import App from './App';
import SandboxPage from './SandboxPage';
import SplashScreen from './SplashScreen';
import reportWebVitals from './reportWebVitals';

function Root() {
  const [showSplash, setShowSplash] = useState(true);
  const handleSplashComplete = useCallback(() => setShowSplash(false), []);

  return (
    <>
      {showSplash && <SplashScreen onComplete={handleSplashComplete} />}
      {!showSplash && (
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<App />} />
            <Route path="/sandbox" element={<SandboxPage />} />
          </Routes>
        </BrowserRouter>
      )}
    </>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
