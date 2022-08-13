import { JWTPayload } from "jose";

/** Basic user data to persist something resembling a user */
export interface UserData {
  userName: string;
  displayName: string;
  credentials?: FIDO2Credential[];
  userHandle?: string;
}

/** Data to represent a FIDO2 credential */
export interface FIDO2Credential {
  counter: number;
  credentialId_b64: string;
  publicKey: string;
}

/** JWT interface data passed around during registration */
export type ChallengeJWT = JWTPayload & {
  userName?: string;
  challenge_b64: string;
};

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

/** Slight variation of the attestation result interface to facilitate transport over JSON */
export interface AttestationResultWireFormat {
  id?: string;
  rawId?: string;
  type?: string;
  response: { clientDataJSON: string; attestationObject: string };
}

export interface AssertionOptionsWireFormat {
  challenge: string;
  timeout?: number;
  rpId?: string;
  attestation?: AttestationConveyancePreference;
  userVerification?: "required" | "preferred" | "discouraged";
  rawChallenge?: string;
  extensions?: AuthenticationExtensionsClientInputs;
  allowCredentials?: {
    id: string;
    transports?: AuthenticatorTransport[];
    type: PublicKeyCredentialType;
  }[];
}

export interface AssertionResultWireFormat {
  id?: string;
  rawId?: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}