
/** Request body for /login/start */
export interface LoginStartRequest {
  userName?: string;
}

/** Response body for /login/start */
export interface LoginStartResponse {
  error?: string;
  token?: string;
  options?: PublicKeyCredentialRequestOptions;
}

/** Request body for /login/finish */
export interface LoginFinishRequest {
  token: string;
  result: PublicKeyCredential;
}

/** Response body for /login/finish */
export interface LoginFinishResponse {
  error?: string;
  status?: string;
  user?: {
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
  token?: string;
  options?: CredentialCreationOptions;
}

/** Request body for /register/finish */
export interface RegistrationFinishRequest {
  token: string;
  result: PublicKeyCredential;
}

/** Response body for /register/finish */
export interface RegistrationFinishResponse {
  error?: string;
  status?: string;
}