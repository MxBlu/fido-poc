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
  credentialId: ArrayBuffer;
  publicKey: string;
}

/** JWT interface data passed around during registration */
export type ChallengeJWT = JWTPayload & { 
  userName?: string;
  challenge: string; 
};
