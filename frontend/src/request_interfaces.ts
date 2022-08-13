
/** Request body for /login/start */
export interface LoginStartRequest {
  userName?: string;
}

/** Response body for /login/start */
export interface LoginStartResponse {
  error?: string;
  token: string;
  challenge_64: string;
  options: PublicKeyCredentialRequestOptions;
}

/** Request body for /login/finish */
export interface LoginFinishRequest {
  token: string;
  result: PublicKeyCredential;
}

/** Response body for /login/finish */
export interface LoginFinishResponse {
  error?: string;
  status: string;
  user: {
    userName: string;
    displayName: string;
  }
}

/** Request body for /register/start */
export interface RegistrationStartRequest {
  displayName: string;
  userName: string;
}

/** Response body for /register/start */
export interface RegistrationStartResponse {
  error?: string;
  token: string;
  options: AttestationOptionsWireFormat;
}

/** Request body for /register/finish */
export interface RegistrationFinishRequest {
  token: string;
  result: PublicKeyCredential;
}

/** Response body for /register/finish */
export interface RegistrationFinishResponse {
  error?: string;
  status: string;
}

/** Slight variation of the attestation request interface to facilitate transport over JSON */
export interface AttestationOptionsWireFormat {
  rp: { name: string; id: string; icon?: string };
  user: { id: string, name: string, displayName: string };
  challenge: string;
  pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelectionCriteria?: AuthenticatorSelectionCriteria;
  rawChallenge?: ArrayBuffer;
  extensions?: AuthenticationExtensionsClientInputs;
}