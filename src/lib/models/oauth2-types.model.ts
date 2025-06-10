/**
 * PKCE Challenge Interface
 */
export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: string;
}

/**
 * OAuth2 Authorization Request Interface
 */
export interface AuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  nonce: string;
  audience?: string;
  scope: string;
  code_challenge_method: string;
  code_challenge: string;
  state?: string;
}

/**
 * OAuth2 Token Request Interface
 */
export interface TokenRequest {
  grant_type: string;
  redirect_uri: string;
  client_id: string;
  code: string;
  code_verifier: string;
}

/**
 * OAuth2 Token Response Interface
 */
export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  id_token?: string;
}

/**
 * Token Information Interface
 */
export interface TokenInfo {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresAt: number;
  scope?: string;
  idToken?: string;
}

/**
 * Authentication State Interface
 */
export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  error?: string;
  tokenInfo?: TokenInfo;
}

/**
 * OAuth2 Error Interface
 */
export interface OAuth2Error {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * User Information Response Interface
 */
export interface UserInfoResponse {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  updated_at?: number;
  [key: string]: any;
}

/**
 * OAuth2 Storage Keys Constants
 */
export const OAUTH2_STORAGE_KEYS = {
  CODE_VERIFIER: 'oauth2_code_verifier',
  STATE: 'oauth2_state',
  ACCESS_TOKEN: 'oauth2_access_token',
  REFRESH_TOKEN: 'oauth2_refresh_token',
  TOKEN_EXPIRES_AT: 'oauth2_token_expires_at',
  TOKEN_TYPE: 'oauth2_token_type',
  SCOPE: 'oauth2_scope',
  ID_TOKEN: 'oauth2_id_token',
  NONCE: 'oauth2_nonce'
} as const;

/**
 * OAuth2 Log Levels
 */
export type OAuth2LogLevel = 'none' | 'error' | 'warn' | 'info' | 'debug';

/**
 * OAuth2 Events
 */
export interface OAuth2Events {
  tokenRefreshed: TokenInfo;
  tokenExpired: void;
  authenticationFailed: OAuth2Error;
  userLoggedOut: void;
}