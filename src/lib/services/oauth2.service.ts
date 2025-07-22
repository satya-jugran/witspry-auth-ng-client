import { Injectable, Inject, PLATFORM_ID, signal, OnDestroy } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, BehaviorSubject, throwError, of } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';

import { OAuth2Config } from '../models/oauth2-config.model';
import {
  PKCEChallenge,
  AuthorizationRequest,
  TokenRequest,
  TokenResponse,
  TokenInfo,
  AuthState,
  OAuth2Error,
  OAUTH2_STORAGE_KEYS,
  UserInfoResponse,
  OAuth2LogLevel
} from '../models/oauth2-types.model';
import { OAUTH2_CONFIG_TOKEN } from '../tokens/oauth2-config.token';
import { OAuth2StorageService } from './oauth2-storage.service';
import { AppResponseType } from '../models';

/**
 * OAuth2 Service with PKCE Support
 * Handles OAuth2 authorization flow, token management, and user authentication
 */
@Injectable({
  providedIn: 'root'
})
export class OAuth2Service implements OnDestroy {
  private _authState = signal<AuthState>({
    isAuthenticated: false,
    isLoading: false
  });

  private _authStateSubject = new BehaviorSubject<AuthState>({
    isAuthenticated: false,
    isLoading: false
  });

  public authState$ = this._authStateSubject.asObservable();
  public readonly authState = this._authState.asReadonly();

  private logLevel: OAuth2LogLevel;
  private autoRefreshTimer?: number;

  constructor(
    @Inject(OAUTH2_CONFIG_TOKEN) private config: OAuth2Config,
    @Inject(PLATFORM_ID) private platformId: Object,
    private http: HttpClient,
    private router: Router,
    private storageService: OAuth2StorageService
  ) {
    this.logLevel = config.logLevel || 'warn';
    this.initializeAuthState();
  }

  /**
   * Initialize authentication state from stored tokens
   */
  private initializeAuthState(): void {
    if (!isPlatformBrowser(this.platformId)) {
      return;
    }

    try {
      const tokenInfo = this.getStoredTokenInfo();
      if (tokenInfo && this.isTokenValid(tokenInfo)) {
        this.updateAuthState({
          isAuthenticated: true,
          isLoading: false,
          tokenInfo
        });
        this.logInfo('Authentication state initialized from stored tokens');
      } else if (tokenInfo && tokenInfo.refreshToken) {
        // Access token is expired but refresh token exists
        this.logInfo('Access token expired but refresh token available - preserving for refresh flow');
        this.updateAuthState({
          isAuthenticated: false,
          isLoading: false,
          tokenInfo: undefined
        });
      } else {
        // No tokens or no refresh token available - clear everything
        this.storageService.clearTokens();
        this.logInfo('No valid stored tokens found');
      }
    } catch (error) {
      this.logError('Error initializing auth state:', error);
      this.storageService.clearTokens();
    }
  }

  /**
   * Generate cryptographically secure PKCE challenge
   */
  private async generatePKCEChallenge(): Promise<PKCEChallenge> {
    const codeVerifier = this.generateSecureCodeVerifier();
    const codeChallenge = await this.createCodeChallenge(codeVerifier);
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: this.config.codeChallengeMethod || 'S256'
    };
  }

  /**
   * Generate cryptographically secure 6-digit code verifier
   */
  private generateSecureCodeVerifier(): string {
    if (!isPlatformBrowser(this.platformId)) {
      throw new Error('Code verifier generation requires browser environment');
    }

    // Generate 6 cryptographically secure random digits
    const array = new Uint8Array(6);
    crypto.getRandomValues(array);
    
    // Convert to 6-digit string (000000-999999)
    const codeVerifier = Array.from(array)
      .map(byte => (byte % 10).toString())
      .join('');
    
    this.logDebug('Generated secure 6-digit code verifier');
    return codeVerifier;
  }

  /**
   * Create SHA-256 hash and base64 encode for code challenge
   */
  private async createCodeChallenge(codeVerifier: string): Promise<string> {
    if (!isPlatformBrowser(this.platformId)) {
      throw new Error('Code challenge creation requires browser environment');
    }

    try {
      // Encode the code verifier as UTF-8
      const encoder = new TextEncoder();
      const data = encoder.encode(codeVerifier);
      
      // Create SHA-256 hash
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      
      // Convert to base64url encoding
      const hashArray = new Uint8Array(hashBuffer);
      const base64String = btoa(String.fromCharCode(...hashArray))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      this.logDebug('Generated code challenge from verifier');
      return base64String;
    } catch (error) {
      this.logError('Error creating code challenge:', error);
      throw new Error('Failed to create code challenge');
    }
  }

  /**
   * Generate cryptographically secure state parameter for CSRF protection
   */
  private generateState(): string {
    if (!isPlatformBrowser(this.platformId)) {
      return 'fallback-state';
    }

    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate nonce if not provided in config
   */
  private generateNonce(): string {
    if (this.config.nonce) {
      return this.config.nonce;
    }

    if (!isPlatformBrowser(this.platformId)) {
      return 'fallback-nonce';
    }

    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Start OAuth2 PKCE authorization flow
   */
  async startAuthorization(): Promise<void> {
    if (!isPlatformBrowser(this.platformId)) {
      this.logError('Authorization attempted in non-browser environment', 'SSR or server context detected');
      this.updateAuthState({
        isLoading: false,
        error: 'Authentication not available in server environment'
      });
      return;
    }

    try {
      this.updateAuthState({ isLoading: true, error: undefined });
      
      // Generate PKCE challenge
      const pkceChallenge = await this.generatePKCEChallenge();
      
      // Generate state for CSRF protection
      const state = this.generateState();
      
      // Generate nonce
      const nonce = this.generateNonce();
      
      // Store code verifier, state, and nonce securely
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.CODE_VERIFIER, pkceChallenge.codeVerifier);
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.STATE, state);
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.NONCE, nonce);
      
      // Build authorization request
      const authRequest: AuthorizationRequest = {
        client_id: this.config.clientId,
        redirect_uri: this.config.redirectUri,
        response_type: this.config.responseType || 'code',
        nonce,
        audience: this.config.audience,
        scope: this.config.scope,
        code_challenge_method: pkceChallenge.codeChallengeMethod,
        code_challenge: pkceChallenge.codeChallenge,
        state
      };
      
      // Build authorization URL
      const authUrl = this.buildAuthorizationUrl(authRequest);
      
      this.logInfo('Starting OAuth2 PKCE authorization flow');
      this.logDebug('Authorization URL:', authUrl);
      
      // Redirect to authorization server
      window.location.href = authUrl;
      
    } catch (error) {
      this.logError('Error starting authorization:', error);
      this.updateAuthState({ 
        isLoading: false, 
        error: 'Failed to start authorization flow' 
      });
      throw error;
    }
  }

  /**
   * Build authorization URL with parameters
   */
  private buildAuthorizationUrl(request: AuthorizationRequest): string {
    const params = new URLSearchParams();
    
    Object.entries(request).forEach(([key, value]) => {
      if (value !== undefined) {
        params.append(key, value.toString());
      }
    });
    
    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * Handle OAuth2 callback and extract tokens
   */
  async handleCallback(): Promise<void> {
    if (!isPlatformBrowser(this.platformId)) {
      throw new Error('Callback handling requires browser environment');
    }

    try {
      this.updateAuthState({ isLoading: true, error: undefined });
      
      const currentUrl = window.location.href;
      this.logInfo('Handling OAuth2 callback:', currentUrl);
      
      // Check for error in callback
      const error = this.extractErrorFromCallback();
      if (error) {
        throw new Error(`OAuth2 Error: ${error.error} - ${error.error_description || 'Unknown error'}`);
      }
      
      // Extract authorization code from query parameters or hash fragment
      const authCode = this.extractAuthorizationCode();
      this.logDebug('Extracted authorization code:', authCode ? 'Found' : 'Not found');
      
      if (authCode) {
        await this.exchangeCodeForTokens(authCode);
        return;
      }
      
      // Extract tokens from URL fragment (implicit flow)
      const tokens = this.extractTokensFromFragment();
      this.logDebug('Extracted tokens from fragment:', tokens ? 'Found' : 'Not found');
      
      if (tokens) {
        await this.handleTokenResponse(tokens);
        return;
      }

      if(this.config.oAuthProvider === 'witsauth') {
        // Handle WitsAuth specific logic
        const witsAuthAppResponse = this.getWitsAuthMessageFromCallback();
        this.logInfo('WitsAuth message from callback:', witsAuthAppResponse);
        switch (witsAuthAppResponse.appResponseType) {
          case '2':
            this.logInfo('WitsAuth app response type 2:', witsAuthAppResponse.message);
            break;
          case '3':
            this.logInfo('WitsAuth app response type 3:', witsAuthAppResponse.message);
            throw new Error(`Error: ${witsAuthAppResponse.message}`);
            break;
          case '4':
            this.logInfo('WitsAuth app response type 4:', witsAuthAppResponse.message);
            break;
          default:
            this.logWarn('Unknown WitsAuth app response type:', witsAuthAppResponse.appResponseType);
        }
        return;
      }
      
      throw new Error('No authorization code or tokens found in callback');
      
    } catch (error) {
      this.logError('Error handling callback:', error);
      this.updateAuthState({ 
        isLoading: false, 
        error: error instanceof Error ? error.message : 'Callback handling failed' 
      });
      this.storageService.clearAll();
      throw error;
    }
  }

  getWitsAuthResponse(): {isApplicable: boolean, message: string} {
    const witsAuthAppResponse = this.getWitsAuthMessageFromCallback();
    const applicableCodes = [
      "409778fc-6ced-4de0-935a-fc1afdd20b7b", //RegistrationSuccess
      "2bbcc634-96f9-4e99-832d-fb84c9139a14", //PasswordResetEmailSent
      "6ae5ba7f-f6ae-44ec-9130-685b8810fae8" //UnlockEmailSent
    ];
    if (witsAuthAppResponse.appResponseType === AppResponseType.Success.toString()
      && witsAuthAppResponse.code
      && applicableCodes.includes(witsAuthAppResponse.code)
    ) {
      return {
        isApplicable: true,
        message: witsAuthAppResponse.message
      };
    }
    return {
      isApplicable: false,
      message: ''
    };
  }

  /**
   * Extract error from callback URL
   */
  private extractErrorFromCallback(): OAuth2Error | null {
    const urlParams = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    
    const error = urlParams.get('error') || hashParams.get('error');
    if (error) {
      return {
        error,
        error_description: urlParams.get('error_description') || hashParams.get('error_description') || undefined,
        error_uri: urlParams.get('error_uri') || hashParams.get('error_uri') || undefined,
        state: urlParams.get('state') || hashParams.get('state') || undefined
      };
    }
    
    return null;
  }

  private getWitsAuthMessageFromCallback(): {appResponseType: string, code: string, message: string } {
    const urlParams = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const appResponseType = urlParams.get('appResponseType') || hashParams.get('appResponseType');
    if (appResponseType === AppResponseType.Success.toString()) {
      const message = urlParams.get('appMessage') || hashParams.get('appMessage');
      const code = urlParams.get('appMessageCode') || hashParams.get('appMessageCode');
      return {
        appResponseType,
        code: decodeURIComponent(code || ''),
        message: decodeURIComponent(message || '')
      };
    }
    return {
      appResponseType: '',
      code: '',
      message: ''
    };
  }

  /**
   * Extract authorization code from query parameters
   */
  private extractAuthorizationCode(): string | null {
    // First check query parameters
    const urlParams = new URLSearchParams(window.location.search);
    let code = urlParams.get('code');
    
    // If not found in query params, check hash fragment
    if (!code && window.location.hash) {
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      code = hashParams.get('code');
    }
    
    if (code) {
      this.logDebug('Authorization code extracted from callback');
      return code;
    }
    
    return null;
  }

  /**
   * Extract tokens from URL fragment
   */
  private extractTokensFromFragment(): TokenResponse | null {
    const fragment = window.location.hash.substring(1);
    if (!fragment) {
      return null;
    }
    
    const params = new URLSearchParams(fragment);
    const accessToken = params.get('access_token');
    
    if (accessToken) {
      this.logDebug('Tokens extracted from URL fragment');
      return {
        access_token: accessToken,
        refresh_token: params.get('refresh_token') || undefined,
        token_type: params.get('token_type') || 'Bearer',
        expires_in: parseInt(params.get('expires_in') || '3600', 10),
        scope: params.get('scope') || undefined,
        id_token: params.get('id_token') || undefined
      };
    }
    
    return null;
  }

  /**
   * Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(authCode: string): Promise<void> {
    const codeVerifier = this.storageService.getItem(OAUTH2_STORAGE_KEYS.CODE_VERIFIER);
    
    if (!codeVerifier) {
      this.logError('Code verifier not found in storage');
      throw new Error('Code verifier not found in storage');
    }
    
    const tokenRequest: TokenRequest = {
      grant_type: 'authorization_code',
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code: authCode,
      code_verifier: codeVerifier
    };
    
    this.logInfo('Exchanging authorization code for tokens');
    
    // Convert to URL-encoded form data as per OAuth 2.0 standard
    const formData = new URLSearchParams();
    Object.entries(tokenRequest).forEach(([key, value]) => {
      if (value !== undefined) {
        formData.append(key, value.toString());
      }
    });
    
    try {
      const tokenResponse = await this.http.post<TokenResponse>(
        this.config.tokenEndpoint,
        formData.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      ).toPromise();
      
      if (tokenResponse) {
        await this.handleTokenResponse(tokenResponse);
      } else {
        throw new Error('No token response received');
      }
      
    } catch (error) {
      this.logError('Token exchange failed:', error);
      throw new Error('Failed to exchange authorization code for tokens');
    }
  }

  /**
   * Handle token response and store tokens securely
   */
  private async handleTokenResponse(tokenResponse: TokenResponse): Promise<void> {
    try {
      // Validate state parameter for CSRF protection
      await this.validateState();
      
      // Create token info
      const tokenInfo: TokenInfo = {
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        tokenType: tokenResponse.token_type || 'Bearer',
        expiresAt: Date.now() + (tokenResponse.expires_in * 1000),
        scope: tokenResponse.scope,
        idToken: tokenResponse.id_token
      };
      
      // Store tokens securely
      this.storeTokenInfo(tokenInfo);
      
      // Update authentication state
      this.updateAuthState({
        isAuthenticated: true,
        isLoading: false,
        tokenInfo,
        error: undefined
      });
      
      // Clean up temporary storage
      this.storageService.clearTemporary();
      
      // Set up auto-refresh if enabled
      this.setupAutoRefresh(tokenInfo);
      
      this.logInfo('Tokens stored successfully, user authenticated');
      
    } catch (error) {
      this.logError('Error handling token response:', error);
      throw error;
    }
  }

  /**
   * Validate state parameter for CSRF protection
   */
  private async validateState(): Promise<void> {
    const urlParams = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    
    const receivedState = urlParams.get('state') || hashParams.get('state');
    const storedState = this.storageService.getItem(OAUTH2_STORAGE_KEYS.STATE);
    
    if (!receivedState || !storedState || receivedState !== storedState) {
      throw new Error('Invalid state parameter - possible CSRF attack');
    }
    
    this.logDebug('State parameter validated successfully');
  }

  /**
   * Get current access token (only if valid/not expired)
   */
  getAccessToken(): string | null {
    const tokenInfo = this.getStoredTokenInfo();
    if (tokenInfo && this.isTokenValid(tokenInfo)) {
      return tokenInfo.accessToken;
    }
    return null;
  }

  /**
   * Get raw access token (even if expired) - used for refresh flow
   */
  getRawAccessToken(): string | null {
    const tokenInfo = this.getStoredTokenInfo();
    return tokenInfo?.accessToken || null;
  }

  /**
   * Get current refresh token
   */
  getRefreshToken(): string | null {
    const tokenInfo = this.getStoredTokenInfo();
    return tokenInfo?.refreshToken || null;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    const tokenInfo = this.getStoredTokenInfo();
    return tokenInfo ? this.isTokenValid(tokenInfo) : false;
  }

  /**
   * Check if authentication is available in current environment
   */
  isAuthenticationAvailable(): boolean {
    return isPlatformBrowser(this.platformId);
  }

  /**
   * Fetch user information from OIDC userinfo endpoint
   */
  async getUserInfo(): Promise<UserInfoResponse> {
    if (!this.config.userInfoEndpoint) {
      throw new Error('UserInfo endpoint not configured');
    }

    let accessToken = this.getAccessToken();
    if (!accessToken) {
      this.logInfo('No access token available');
      if (this.config.autoRefresh) {
        this.logInfo('autoRefresh is true. Attempting to refresh access token');
        accessToken = await this.refreshAccessToken();
      } else {
        throw new Error('No access token available');
      }
    }

    this.logInfo('Fetching user info from OIDC userinfo endpoint');

    try {
      const userInfo = await this.http.get<UserInfoResponse>(
        this.config.userInfoEndpoint,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        }
      ).toPromise();

      if (userInfo) {
        this.logDebug('User info retrieved successfully:', userInfo);
        return userInfo;
      } else {
        throw new Error('No user info response received');
      }
    } catch (error) {
      this.logError('Failed to fetch user info:', error);
      throw new Error('Failed to fetch user information');
    }
  }

  /**
   * Check if token is valid (not expired)
   */
  private isTokenValid(tokenInfo: TokenInfo): boolean {
    const threshold = (this.config.refreshThreshold || 300) * 1000; // Convert to milliseconds
    return Date.now() < (tokenInfo.expiresAt - threshold);
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(): Promise<string> {
    const refreshToken = this.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    
    this.logInfo('Refreshing access token');
    
    const tokenRequest = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId
    };
    
    // Convert to URL-encoded form data as per OAuth 2.0 standard
    const formData = new URLSearchParams();
    Object.entries(tokenRequest).forEach(([key, value]) => {
      if (value !== undefined) {
        formData.append(key, value.toString());
      }
    });
    
    try {
      const tokenResponse = await this.http.post<TokenResponse>(
        this.config.tokenEndpoint,
        formData.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      ).toPromise();
      
      if (tokenResponse) {
        const tokenInfo: TokenInfo = {
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token || refreshToken,
          tokenType: tokenResponse.token_type || 'Bearer',
          expiresAt: Date.now() + (tokenResponse.expires_in * 1000),
          scope: tokenResponse.scope,
          idToken: tokenResponse.id_token
        };
        
        this.storeTokenInfo(tokenInfo);
        this.updateAuthState({
          isAuthenticated: true,
          isLoading: false,
          tokenInfo
        });
        
        // Set up auto-refresh for the new token
        this.setupAutoRefresh(tokenInfo);
        
        this.logInfo('Access token refreshed successfully');
        return tokenResponse.access_token;
      } else {
        throw new Error('No token response received');
      }
      
    } catch (error) {
      this.logError('Token refresh failed:', error);
      
      // Clear auto-refresh timer on error
      this.clearAutoRefreshTimer();
      
      // Only logout if it's a 400/401 error indicating invalid refresh token
      if (error instanceof Error && 'status' in error) {
        const httpError = error as any;
        if (httpError.status === 400 || httpError.status === 401) {
          this.logInfo('Refresh token is invalid, logging out');
          this.logout();
        }
      } else {
        this.logInfo('Network or server error during token refresh, will retry later');
      }
      
      throw new Error('Failed to refresh access token');
    }
  }

  /**
   * Set up automatic token refresh if enabled
   */
  private setupAutoRefresh(tokenInfo: TokenInfo): void {
    // Clear any existing timer
    this.clearAutoRefreshTimer();
    
    // Check if auto-refresh is enabled
    if (!this.config.autoRefresh) {
      return;
    }
    
    // Calculate timeout: time until refresh should happen
    const refreshThreshold = (this.config.refreshThreshold || 300) * 1000; // Convert to milliseconds
    const timeout = tokenInfo.expiresAt - Date.now() - refreshThreshold;
    
    // Only set timer if there's time left before refresh is needed
    if (timeout > 0) {
      this.logDebug(`Setting up auto-refresh timer for ${timeout}ms`);
      this.autoRefreshTimer = window.setTimeout(() => {
        this.logInfo('Auto-refreshing access token');
        this.refreshAccessToken().catch(error => {
          this.logError('Auto-refresh failed:', error);
        });
      }, timeout);
    } else {
      this.logDebug('Token expires soon, not setting up auto-refresh timer');
    }
  }

  /**
   * Clear the auto-refresh timer
   */
  private clearAutoRefreshTimer(): void {
    if (this.autoRefreshTimer) {
      clearTimeout(this.autoRefreshTimer);
      this.autoRefreshTimer = undefined;
      this.logDebug('Auto-refresh timer cleared');
    }
  }

  /**
   * Logout user and clean up all stored data
   */
  async logout(): Promise<void> {
    try {
      this.updateAuthState({ isLoading: true });
      
      // Clear auto-refresh timer
      this.clearAutoRefreshTimer();
      
      // Revoke tokens if supported
      await this.revokeTokens();
      
      // Clear all stored authentication data
      this.storageService.clearAll();
      
      // Update authentication state
      this.updateAuthState({
        isAuthenticated: false,
        isLoading: false,
        tokenInfo: undefined,
        error: undefined
      });
      
      this.logInfo('User logged out successfully');

      // Redirect to logout route if configured
      if (this.config.logoutRedirectRoute) {
        this.logInfo('Redirecting to logout route: ', this.config.logoutRedirectRoute);
        this.router.navigate([this.config.logoutRedirectRoute]);
      }
      
    } catch (error) {
      this.logError('Error during logout:', error);
      // Still clear local data even if revocation fails
      this.storageService.clearAll();
      this.updateAuthState({
        isAuthenticated: false,
        isLoading: false,
        tokenInfo: undefined
      });
      // Redirect to logout route if configured
      if (this.config.logoutRedirectRoute) {
        this.logInfo('Redirecting to logout route: ', this.config.logoutRedirectRoute);
        this.router.navigate([this.config.logoutRedirectRoute]);
      }
    }
  }

  /**
   * Revoke tokens at authorization server
   */
  private async revokeTokens(): Promise<void> {
    if (!this.config.revokeEndpoint) {
      this.logInfo('Token revocation endpoint not configured');
      return;
    }
    
    const accessToken = this.getAccessToken();
    const refreshToken = this.getRefreshToken();
    
    const revokePromises: Promise<any>[] = [];
    
    if (accessToken) {
      const revokeRequest = {
        token: accessToken,
        token_type_hint: 'access_token',
        client_id: this.config.clientId
      };
      
      const formData = new URLSearchParams();
      Object.entries(revokeRequest).forEach(([key, value]) => {
        if (value !== undefined) {
          formData.append(key, value.toString());
        }
      });
      
      revokePromises.push(
        this.http.post(this.config.revokeEndpoint, formData.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }).toPromise()
      );
    }
    
    if (refreshToken) {
      const revokeRequest = {
        token: refreshToken,
        token_type_hint: 'refresh_token',
        client_id: this.config.clientId
      };
      
      const formData = new URLSearchParams();
      Object.entries(revokeRequest).forEach(([key, value]) => {
        if (value !== undefined) {
          formData.append(key, value.toString());
        }
      });
      
      revokePromises.push(
        this.http.post(this.config.revokeEndpoint, formData.toString(), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }).toPromise()
      );
    }
    
    if (revokePromises.length > 0) {
      try {
        await Promise.all(revokePromises);
        this.logInfo('Tokens revoked successfully');
      } catch (error) {
        this.logError('Token revocation failed:', error);
        // Don't throw error, continue with logout
      }
    }
  }

  /**
   * Store token information securely
   */
  private storeTokenInfo(tokenInfo: TokenInfo): void {
    try {
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.ACCESS_TOKEN, tokenInfo.accessToken);
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.TOKEN_EXPIRES_AT, tokenInfo.expiresAt.toString());
      this.storageService.setItem(OAUTH2_STORAGE_KEYS.TOKEN_TYPE, tokenInfo.tokenType);
      
      if (tokenInfo.refreshToken) {
        this.storageService.setItem(OAUTH2_STORAGE_KEYS.REFRESH_TOKEN, tokenInfo.refreshToken);
      }
      
      if (tokenInfo.scope) {
        this.storageService.setItem(OAUTH2_STORAGE_KEYS.SCOPE, tokenInfo.scope);
      }
      
      if (tokenInfo.idToken) {
        this.storageService.setItem(OAUTH2_STORAGE_KEYS.ID_TOKEN, tokenInfo.idToken);
      }
      
      this.logDebug('Token information stored securely');
    } catch (error) {
      this.logError('Error storing token information:', error);
      throw new Error('Failed to store token information');
    }
  }

  /**
   * Retrieve stored token information
   */
  private getStoredTokenInfo(): TokenInfo | null {
    if (!this.storageService.isAvailable()) {
      return null;
    }
    
    try {
      const accessToken = this.storageService.getItem(OAUTH2_STORAGE_KEYS.ACCESS_TOKEN);
      const expiresAtStr = this.storageService.getItem(OAUTH2_STORAGE_KEYS.TOKEN_EXPIRES_AT);
      
      if (!accessToken || !expiresAtStr) {
        return null;
      }
      
      return {
        accessToken,
        refreshToken: this.storageService.getItem(OAUTH2_STORAGE_KEYS.REFRESH_TOKEN) || undefined,
        tokenType: this.storageService.getItem(OAUTH2_STORAGE_KEYS.TOKEN_TYPE) || 'Bearer',
        expiresAt: parseInt(expiresAtStr, 10),
        scope: this.storageService.getItem(OAUTH2_STORAGE_KEYS.SCOPE) || undefined,
        idToken: this.storageService.getItem(OAUTH2_STORAGE_KEYS.ID_TOKEN) || undefined
      };
    } catch (error) {
      this.logError('Error retrieving stored token information:', error);
      return null;
    }
  }

  /**
   * Update authentication state
   */
  private updateAuthState(newState: Partial<AuthState>): void {
    const currentState = this._authState();
    const updatedState = { ...currentState, ...newState };
    
    this._authState.set(updatedState);
    this._authStateSubject.next(updatedState);
  }

  /**
   * Debug logging
   */
  private logDebug(message: string, ...args: any[]): void {
    if (this.logLevel === 'debug') {
      console.log(`[OAuth2Service] ${message}`, ...args);
    }
  }

  /**
   * Info logging
   */
  private logInfo(message: string, ...args: any[]): void {
    if (['debug', 'info'].includes(this.logLevel)) {
      console.info(`[OAuth2Service] ${message}`, ...args);
    }
  }

  /**
   * Warning logging
   */
  private logWarn(message: string, ...args: any[]): void {
    if (['debug', 'info', 'warn'].includes(this.logLevel)) {
      console.warn(`[OAuth2Service] ${message}`, ...args);
    }
  }

  /**
   * Error logging
   */
  private logError(message: string, error?: any): void {
    if (this.logLevel !== 'none') {
      console.error(`[OAuth2Service] ${message}`, error);
    }
  }

  /**
   * Angular OnDestroy lifecycle hook
   */
  ngOnDestroy(): void {
    this.clearAutoRefreshTimer();
  }
}