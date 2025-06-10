/**
 * OAuth2 Configuration Interface
 */
export interface OAuth2Config {
  /** OAuth2 Client ID */
  clientId: string;
  
  /** Redirect URI for OAuth2 callback */
  redirectUri: string;
  
  /** Authorization endpoint URL */
  authorizationEndpoint: string;
  
  /** Token endpoint URL */
  tokenEndpoint: string;
  
  /** Token revocation endpoint URL (optional) */
  revokeEndpoint?: string;
  
  /** OIDC UserInfo endpoint URL (optional) */
  userInfoEndpoint?: string;
  
  /** OAuth2 audience parameter (optional) */
  audience?: string;
  
  /** OAuth2 scope parameter */
  scope: string;
  
  /** OAuth2 response type (default: 'code') */
  responseType?: 'code';
  
  /** PKCE code challenge method (default: 'S256') */
  codeChallengeMethod?: 'S256';
  
  /** Storage strategy for tokens */
  storage?: 'localStorage' | 'sessionStorage' | 'custom';
  
  /** Custom storage implementation (required if storage is 'custom') */
  customStorage?: OAuth2Storage;
  
  /** Enable automatic token refresh (default: true) */
  autoRefresh?: boolean;
  
  /** Seconds before expiry to refresh token (default: 300) */
  refreshThreshold?: number;
  
  /** Logging level (default: 'warn') */
  logLevel?: 'none' | 'error' | 'warn' | 'info' | 'debug';
  
  /** Custom nonce value (optional, will be generated if not provided) */
  nonce?: string;
}

/**
 * Custom Storage Interface
 */
export interface OAuth2Storage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  clear?(): void;
}
