import axios, { AxiosError } from 'axios';
import React, { useState } from 'react';
import * as base64buffer from 'base64-arraybuffer';
import './App.css';
import { AssertionResultWireFormat, AttestationResultWireFormat, LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, RegistrationFinishRequest, RegistrationFinishResponse, RegistrationStartRequest, RegistrationStartResponse } from './request_interfaces.js';
import { FIDO2_BACKEND_URL } from './constants';

// Axios client pointing at backend server
const client = axios.create({
  baseURL: FIDO2_BACKEND_URL
});

function App() {
  const [displayName, setDisplayName] = useState("");
  const [userName, setUserName] = useState("");
  const [result, setResult] = useState("");

  /**
   * Add `newResult` object to the result field
   * @param newResult New result object to log
   */
  const appendResult = (newResult: any): void => {
    const jsonString = JSON.stringify(newResult);
    setResult(result => result + '\n' + jsonString);
  }

  /**
   * Update display name to new value
   * @param event 
   */
  const handleDisplayNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newDisplayName = event.target.value;
    setDisplayName(newDisplayName);
  }

  /**
   * Update username to new value
   * @param event
   */
  const handleUserNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const newUserName = event.target.value;
    setUserName(newUserName);
  }

  /**
   * Perform a WebAuthn login
   * @param event 
   */
  const handleLogin = async (event: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
    event.preventDefault();
    appendResult({ 'status': 'loggingIn' });

    try {
      // Prepare the request data
      const loginData: LoginStartRequest = {
        userName: userName
      };

      // Send a request to the server to get the login challenge and options
      let startResp = await client.post('/login/start', loginData);
      let startRespData = startResp.data as LoginStartResponse;

      appendResult({ 'status': 'gotchallenge', 'data': startRespData.options.challenge });
      // Hold on to the JWT to send back later with the login completion request
      const jwt = startRespData.token;
      // Translate the wire format login options from the server to what the browser protocol expects
      // Basically just decoding base64 strings to array buffers
      const opts: CredentialRequestOptions = {
        publicKey: {
          ...startRespData.options,
          challenge: base64buffer.decode(startRespData.options.challenge),
          allowCredentials: startRespData.options.allowCredentials?.map(
            c => ({ id: base64buffer.decode(c.id), type: c.type }))
        }
      };

      // Request credentials from the browser
      // This should prompt you to log in with a security key
      const credential = await navigator.credentials.get(opts) as PublicKeyCredential;
      // Extract the response object and type it to the right type
      const assertionResponse = credential.response as AuthenticatorAssertionResponse;
      // Convert the credential to the wire format for sending to the server
      // Basically encoding all array buffers to base64 strings 
      const transferrableCredential: AssertionResultWireFormat = {
        id: credential.id,
        rawId: base64buffer.encode(credential.rawId),
        response: {
          clientDataJSON: base64buffer.encode(credential.response.clientDataJSON),
          authenticatorData: base64buffer.encode(assertionResponse.authenticatorData),
          signature: base64buffer.encode(assertionResponse.signature),
          userHandle: assertionResponse.userHandle ? base64buffer.encode(assertionResponse.userHandle) : undefined
        }
      };

      appendResult({ 'status': 'sendingcredential', 'credential': credential.id });
      // Prepare a response data with the credential and the original JWT token
      const loginFinishData: LoginFinishRequest = {
        result: transferrableCredential,
        token: jwt
      }
      // Send the data to the server 
      // The client will throw an error if we get a non 2xx response (indicating failure)
      const finishResp = await client.post('/login/finish', loginFinishData);
      const finishRespData = finishResp.data as LoginFinishResponse;

      // Log the response object which should have the User object
      appendResult(finishRespData);
    } catch (e) {
      appendResult({ 'error': e });
    }
  }

  /**
   * Perform a Webauthn registration
   * @param event 
   */
  const handleRegistration = async (event: React.MouseEvent<HTMLButtonElement>): Promise<void> => {
    event.preventDefault();
    appendResult({ 'status': 'registering' });

    try {
      // Prepare the request data
      const initialRegistrationData: RegistrationStartRequest = {
        displayName: displayName,
        userName: userName
      };

      // Send a request to the server to get the registration challenge and options
      const startResp = await client.post('/register/start', initialRegistrationData);
      const startRespData = startResp.data as RegistrationStartResponse;

      appendResult({ 'status': 'gotchallenge', 'data': startRespData.options.challenge });
      // Hold on to the JWT to send back later with the login completion request
      const jwt = startRespData.token;
      // Translate the wire format registration options from the server to what the browser protocol expects
      // Basically just decoding base64 strings to array buffers
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

      // Request credentials from the browser
      // This should prompt you to log in with a security key
      const credential = await navigator.credentials.create(opts) as PublicKeyCredential;
      // Extract the response object and type it to the right type
      const attestationResponse = credential.response as AuthenticatorAttestationResponse;
      // Convert the credential to the wire format for sending to the server
      // Basically encoding all array buffers to base64 strings 
      const transferrableCredentials: AttestationResultWireFormat = {
        id: credential.id,
        rawId: base64buffer.encode(credential.rawId),
        response: {
          clientDataJSON: base64buffer.encode(credential.response.clientDataJSON),
          attestationObject: base64buffer.encode(attestationResponse.attestationObject),
        },
        type: credential.type
      };

      appendResult({ 'status': 'sendingcredential', 'credential': credential.id });
      // Prepare a response data with the credential and the original JWT token
      const registrationFinishData: RegistrationFinishRequest = {
        result: transferrableCredentials,
        token: jwt
      }
      // Send the data to the server 
      // The client will throw an error if we get a non 2xx response (indicating failure)
      const finishResp = await client.post('/register/finish', registrationFinishData);
      const finishRespData = finishResp.data as RegistrationFinishResponse;

      appendResult(finishRespData);
    } catch (e) {
      if (e instanceof AxiosError) {
        const axiosError = e as AxiosError;
        appendResult(axiosError.response?.data ?? { 'error': e });
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
