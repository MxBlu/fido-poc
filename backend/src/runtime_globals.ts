import { Fido2Lib } from "fido2-lib";
import { generateKeyPair, GenerateKeyPairResult } from "jose";
import { HOSTNAME } from "./constants.js";
import { UserData } from "./models.js";
import { Logger } from "./utils/logger.js";

export const Fido2 = new Fido2Lib({
  timeout: 120,
  rpId: HOSTNAME,
  rpName: "MxBlue Server",
  attestation: "none",
  authenticatorAttachment: "cross-platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "preferred"
});

export let ServerKP: GenerateKeyPairResult = null;
generateKeyPair('ES256').then(kp => { 
  ServerKP = kp;
  new Logger("KeyPairGen").info('Keypair ready');
});

/** Global map of usernames to user data */
export const Users = new Map<string, UserData>();