import axios, { AxiosError } from 'axios';
import React, { useState } from 'react';
import * as base64buffer from 'base64-arraybuffer';
import './App.css';
import { AssertionResultWireFormat, AttestationResultWireFormat, LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, RegistrationFinishRequest, RegistrationFinishResponse, RegistrationStartRequest, RegistrationStartResponse } from './request_interfaces.js';

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

    try {
      const loginData: LoginStartRequest = {
        userName: userName
      };

      let startResp = await client.post('/login/start', loginData);
      let startRespData = startResp.data as LoginStartResponse;

      appendResult({'status': 'gotchallenge', 'data': startRespData.options.challenge });
      const jwt = startRespData.token;
      const opts: CredentialRequestOptions = {
        publicKey: {
          ...startRespData.options,
          challenge: base64buffer.decode(startRespData.options.challenge),
          allowCredentials: startRespData.options.allowCredentials?.map(
            c => ({ id: base64buffer.decode(c.id), type: c.type }))
        }
      };

      const credential = await navigator.credentials.get(opts) as PublicKeyCredential;
      const assertionResponse = credential.response as AuthenticatorAssertionResponse;
      const transferrableCredentials: AssertionResultWireFormat = {
        id: credential.id,
        rawId: base64buffer.encode(credential.rawId),
        response: {
          clientDataJSON: base64buffer.encode(credential.response.clientDataJSON),
          authenticatorData: base64buffer.encode(assertionResponse.authenticatorData),
          signature: base64buffer.encode(assertionResponse.signature),
          userHandle: assertionResponse.userHandle ? base64buffer.encode(assertionResponse.userHandle) : undefined
        }
      };

      appendResult({'status': 'sendingcredential', 'credential': credential.id });
      const loginFinishData: LoginFinishRequest = {
        result: transferrableCredentials,
        token: jwt
      }
      const finishResp = await client.post('/login/finish', loginFinishData);
      const finishRespData = finishResp.data as LoginFinishResponse;

      appendResult(finishRespData);
    } catch (e) {
      appendResult({'error': e });
    }
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
      
      appendResult({'status': 'gotchallenge', 'data': startRespData.options.challenge });
      const jwt = startRespData.token;
      const opts: CredentialCreationOptions = {
        publicKey: {
          ...startRespData.options,
          challenge: base64buffer.decode(startRespData.options.challenge),
          user: {
            ...startRespData.options.user,
            id: base64buffer.decode(startRespData.options.user.id),
          }
        }
      };

      const credential = await navigator.credentials.create(opts) as PublicKeyCredential;
      const transferrableCredentials: AttestationResultWireFormat = {
        id: credential.id,
        rawId: base64buffer.encode(credential.rawId),
        response: {
          clientDataJSON: base64buffer.encode(credential.response.clientDataJSON),
          attestationObject: base64buffer.encode((credential.response as AuthenticatorAttestationResponse).attestationObject),
        },
        type: credential.type
      };

      appendResult({'status': 'sendingcredential', 'credential': credential.id });
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
