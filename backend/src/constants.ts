import { Attachment, UserVerification } from "fido2-lib";

/** Server runtime port */
export const PORT = 8080;
/** Hostname that the server runs on - used by FIDO2 */
export const HOSTNAME = "fido.mxblue.net.au"
/** Origin URL (with protocol and port) that responses should originate from */
export const ORIGIN = "https://fido.mxblue.net.au"
/** Display name for this server, shown to client on WebAuthn requests */
export const RP_NAME = "MxBlue Server";
/** 
 * Setting this requires the client to use a certain kind of authenticator:
 *
 * * Platform authenticators ('platform') - Uses a security feature built on top of a platform, i.e. Windows Hello, Face ID
 * * Roaming authenticators ('cross-platform') - Uses a physical security key, i.e. anything FIDO2 compliant like a Yubikey
*/
export const FIDO2_ATTACHMENT_REQUIREMENT: Attachment = null;
/** 
 * Setting this will instruct the platform whether or not to allow resident key login.
 * 
 * A resident key is a reference to a credential that is tied to the RP ID and stored by the authenticator.
 * 
 * * Setting this to null means its up to the platform to decide if it wants to store a resident key
 * * Setting this to false will discourage storing a resident key, and prevent resident key login
 * * Setting this to true will require the platform to store a resident key
 */
export const FIDO2_REQUIRE_RESIDENT_KEY: boolean | null = null;
/**
 * Setting this will determine whether to require user verification
 * 
 * User verification is a validation that the platform has verified the users identity with the authenticator
 * 
 * * Setting this to null will let the platform decide whether to verify the user or not
 * * Setting this to preferred will request the platform to verify if possible
 * * Setting this to discouraged will request the platform to not verify if possible
 * * Setting this to required will require the platform to verify
 */
export const FIDO2_USER_VERIFICATION_REQUIREMENT: UserVerification = null;