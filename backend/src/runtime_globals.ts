import { Fido2Lib } from "fido2-lib";
import { generateKeyPair, GenerateKeyPairResult } from "jose";
import { FIDO2_ATTACHMENT_REQUIREMENT, FIDO2_REQUIRE_RESIDENT_KEY, FIDO2_USER_VERIFICATION_REQUIREMENT, HOSTNAME, RP_NAME } from "./constants.js";
import { UserData } from "./models.js";
import { Logger } from "./utils/logger.js";

/** Global Fido2Lib instance */
export const Fido2 = new Fido2Lib({
  timeout: 120000,
  rpId: HOSTNAME,
  rpName: RP_NAME,
  attestation: "none",
  authenticatorAttachment: FIDO2_ATTACHMENT_REQUIREMENT,
  authenticatorRequireResidentKey: FIDO2_REQUIRE_RESIDENT_KEY,
  authenticatorUserVerification: FIDO2_USER_VERIFICATION_REQUIREMENT
});

/** Key pair for JWT signing */
export let ServerKP: GenerateKeyPairResult = null;
generateKeyPair('ES256').then(kp => { 
  ServerKP = kp;
  new Logger("KeyPairGen").info('Keypair ready');
});

/** Global map of usernames to user data */
export const Users = new Map<string, UserData>();