import axios, { AxiosError } from 'axios';
import React, { useState } from 'react';
import './App.css';
import { AttestationResultWireFormat, LoginStartRequest, LoginStartResponse, RegistrationFinishRequest, RegistrationFinishResponse, RegistrationStartRequest, RegistrationStartResponse } from './request_interfaces.js';

const client = axios.create({
  baseURL: "https://fido.mxblue.net.au/api"
});

function App() {
  const [displayName, setDisplayName] = useState("");
  const [userName, setUserName] = useState("");
  const [result, setResult] = useState("");

  const appendResult = (newResult: any): void => {
    const jsonString = JSON.stringify(newResult);
    setResult(result => result + '\n' + jsonString);
  }

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
    appendResult({'status': 'loggingIn'});

    // const loginData: LoginStartRequest = {
    //   userName: userName
    // };

    // try {
    //   let resp = await client.post('/login/start', loginData);
    //   let respData = resp.data as LoginStartResponse;

    //   const jwt = respData.token;
    //   const opts = respData.options;

    //   setResult({'status': resp.data });
    // } catch (e) {
    //   setResult({'error': e });
    // }
  }

  const handleRegistration = async (event: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
    event.preventDefault();
    appendResult({'status': 'registering'});

    try {
      const initialRegistrationData: RegistrationStartRequest = {
        displayName: displayName,
        userName: userName
      };

      const startResp = await client.post('/register/start', initialRegistrationData);
      const startRespData = startResp.data as RegistrationStartResponse;

      const jwt = startRespData.token;
      const opts: CredentialCreationOptions = {
        publicKey: {
          ...startRespData.options,
          challenge: Uint8Array.from(atob(startRespData.options.challenge), c => c.charCodeAt(0)),
          user: {
            ...startRespData.options.user,
            id: Uint8Array.from(atob(startRespData.options.user.id), c => c.charCodeAt(0)),
          }
        }
      };
      appendResult({'status': 'gotchallenge', 'data': opts });

      const credential = await navigator.credentials.create(opts) as PublicKeyCredential;

      const transferrableCredentials: AttestationResultWireFormat = {
        ...credential,
        rawId: btoa(String.fromCharCode(...Array.from(new Uint8Array(credential.rawId)))),
        response: {
          clientDataJSON: btoa(String.fromCharCode(...Array.from(new Uint8Array(credential.response.clientDataJSON)))),
          attestationObject: btoa(String.fromCharCode(...Array.from(new Uint8Array((credential.response as AuthenticatorAttestationResponse).attestationObject)))),
        }
      };

      appendResult({'status': 'sendingcredentials', 'credentials': transferrableCredentials });
      const registrationFinishData: RegistrationFinishRequest = {
        result: transferrableCredentials,
        token: jwt
      }
      const finishResp = await client.post('/register/finish', registrationFinishData);
      const finishRespData = finishResp.data as RegistrationFinishResponse;

      appendResult(finishRespData);
    } catch (e) {
      if (e instanceof AxiosError) {
        const axiosError = e as AxiosError;
        appendResult(axiosError.response?.data ?? {'error': e});
      }
    }
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
        {result}
      </div>
    </div>
  );
}

export default App;
