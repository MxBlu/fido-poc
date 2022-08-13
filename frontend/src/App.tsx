import axios from 'axios';
import React, { useState } from 'react';
import './App.css';
import { LoginStartRequest, LoginStartResponse, RegistrationFinishRequest, RegistrationStartRequest, RegistrationStartResponse } from './request_interfaces.js';

const client = axios.create({
  baseURL: "http://localhost:8080"
});

function App() {
  const [displayName, setDisplayName] = useState("");
  const [userName, setUserName] = useState("");
  const [result, setResult] = useState<Record<string, any> | null>(null);

  const handleDisplayNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newDisplayName = event.target.value;
    setDisplayName(newDisplayName);
  }

  const handleUserNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newUserName = event.target.value;
    setUserName(newUserName);
  }

  const handleLogin = async (event: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
    event.preventDefault();
    setResult({'status': 'loggingIn'});
  }

  const handleRegistration = async (event: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
    event.preventDefault();
    setResult({'status': 'registering'});
  }

  let resultText = "";
  if (result != null) {
    resultText = JSON.stringify(result, null, 4);
  }

  return (
    <div className='App'>
      <h1>FIDO2 PoC</h1>
      <form className='userForm'>
        <label htmlFor='displayName' >Display Name:</label>
        <input
          id='displayName'
          type='text'
          value={displayName}
          onChange={handleDisplayNameChange}
        />
        <label htmlFor='userName' >Username:</label>
        <input
          id='userName'
          type='text'
          value={userName}
          onChange={handleUserNameChange}
        />
        <div className='interactions'>
          <button onClick={handleRegistration}>Register</button>
          <button onClick={handleLogin}>Login</button>
        </div>
      </form>
      <div className='result'>
        {resultText}
      </div>
    </div>
  );
}

export default App;
