import { inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import {
  HttpInterceptorFn,
  HttpRequest,
  HttpHandlerFn,
  HttpEvent,
  HttpErrorResponse,
  HttpResponse,
  HttpHeaders
} from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, switchMap, filter, take } from 'rxjs/operators';

import { OAuth2Config } from '../models/oauth2-config.model';
import { OAUTH2_STORAGE_KEYS, OAuth2LogLevel } from '../models/oauth2-types.model';
import { OAUTH2_CONFIG_TOKEN } from '../tokens/oauth2-config.token';
import { OAuth2StorageService } from '../services/oauth2-storage.service';

// Global state for token refresh
let isRefreshing = false;
let refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);

/**
 * OAuth2 HTTP Interceptor Function
 * Automatically adds Bearer tokens to requests and handles token refresh
 */
export const oauth2InterceptorFn: HttpInterceptorFn = (
  request: HttpRequest<any>,
  next: HttpHandlerFn
): Observable<HttpEvent<any>> => {
  const platformId = inject(PLATFORM_ID);
  const config = inject(OAUTH2_CONFIG_TOKEN);
  const storageService = inject(OAuth2StorageService);
  const router = inject(Router);
  
  const logLevel = config.logLevel || 'warn';

  // Only intercept requests that should have OAuth2 tokens
  if (!shouldInterceptRequest(request, config)) {
    return next(request);
  }

  // Get access token directly from storage to avoid circular dependency
  let accessToken = storageService.getItem(OAUTH2_STORAGE_KEYS.ACCESS_TOKEN);
  const hasValidToken = accessToken && isTokenValid(storageService);
  
  logDebug(logLevel, 'Access token retrieved:', accessToken ? (hasValidToken ? 'Valid' : 'Expired') : 'Not found');
  logDebug(logLevel, 'Request URL:', request.url);
  
  // Always add token if available, even if expired (server will reject and we'll refresh)
  if (accessToken) {
    request = addTokenToRequest(request, accessToken);
    logDebug(logLevel, 'Authorization header added to request');
  } else {
    logDebug(logLevel, 'No access token available, proceeding without Authorization header');
  }

  return next(request).pipe(
    catchError((error: HttpErrorResponse) => {
      // Handle 401 Unauthorized errors - attempt refresh if we have access token OR refresh token
      if (error.status === 401) {
        const refreshToken = storageService.getItem(OAUTH2_STORAGE_KEYS.REFRESH_TOKEN);
        if (accessToken || refreshToken) {
          logInfo(logLevel, '401 error detected, attempting token refresh');
          logDebug(logLevel, 'Has access token:', !!accessToken, 'Has refresh token:', !!refreshToken);
          return handle401Error(request, next, config, storageService, router, logLevel);
        } else {
          logInfo(logLevel, '401 error but no tokens available for refresh');
        }
      }
      
      return throwError(() => error);
    })
  );
};

/**
 * Check if token is valid (not expired)
 */
function isTokenValid(storageService: OAuth2StorageService): boolean {
  const expiresAtStr = storageService.getItem(OAUTH2_STORAGE_KEYS.TOKEN_EXPIRES_AT);
  if (!expiresAtStr) {
    return false;
  }
  
  const expiresAt = parseInt(expiresAtStr, 10);
  return Date.now() < expiresAt;
}

/**
 * Check if request should be intercepted
 */
function shouldInterceptRequest(request: HttpRequest<any>, config: OAuth2Config): boolean {
  // Exclude token refresh requests to avoid circular dependency
  if (request.url === config.tokenEndpoint) {
    return false;
  }
  
  // Exclude revoke requests
  if (config.revokeEndpoint && request.url === config.revokeEndpoint) {
    return false;
  }
  
  // You can customize this logic based on your needs
  // For example, only intercept requests to specific domains or paths
  return true;
}

/**
 * Add Bearer token to request headers
 */
function addTokenToRequest(request: HttpRequest<any>, token: string): HttpRequest<any> {
  return request.clone({
    setHeaders: {
      Authorization: `Bearer ${token}`
    }
  });
}

/**
 * Handle 401 Unauthorized errors by attempting token refresh
 */
function handle401Error(
  request: HttpRequest<any>,
  next: HttpHandlerFn,
  config: OAuth2Config,
  storageService: OAuth2StorageService,
  router: Router,
  logLevel: OAuth2LogLevel
): Observable<HttpEvent<any>> {
  if (!isRefreshing) {
    isRefreshing = true;
    refreshTokenSubject.next(null);

    const refreshToken = storageService.getItem(OAUTH2_STORAGE_KEYS.REFRESH_TOKEN);
    if (!refreshToken) {
      isRefreshing = false;
      logInfo(logLevel, 'No refresh token available');
      return throwError(() => new Error('No refresh token available'));
    }

    // Create token refresh request directly using HttpRequest
    const tokenRequestData = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: config.clientId
    };
    
    // Convert to URL-encoded form data as per OAuth 2.0 standard
    const formData = new URLSearchParams();
    Object.entries(tokenRequestData).forEach(([key, value]) => {
      if (value !== undefined) {
        formData.append(key, value.toString());
      }
    });
    
    const headers = new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded'
    });
    
    const refreshRequest = new HttpRequest('POST', config.tokenEndpoint, formData.toString(), {
      headers: headers
    });

    return next(refreshRequest).pipe(
      filter((event: HttpEvent<any>) => event instanceof HttpResponse),
      switchMap((event: HttpResponse<any>) => {
        const tokenResponse = event.body;
        isRefreshing = false;
        
        if (tokenResponse?.access_token) {
          // Store new tokens
          storageService.setItem(OAUTH2_STORAGE_KEYS.ACCESS_TOKEN, tokenResponse.access_token);
          storageService.setItem(OAUTH2_STORAGE_KEYS.TOKEN_EXPIRES_AT, (Date.now() + (tokenResponse.expires_in * 1000)).toString());
          if (tokenResponse.refresh_token) {
            storageService.setItem(OAUTH2_STORAGE_KEYS.REFRESH_TOKEN, tokenResponse.refresh_token);
          }
          
          refreshTokenSubject.next(tokenResponse.access_token);
          logInfo(logLevel, 'Token refreshed successfully, retrying original request');
          
          // Retry the original request with new token
          return next(addTokenToRequest(request, tokenResponse.access_token));
        } else {
          throw new Error('No access token in refresh response');
        }
      }),
      catchError(error => {
        isRefreshing = false;
        refreshTokenSubject.next(null);
        
        logError(logLevel, 'Token refresh failed:', error);
        
        // Check if it's an authentication error (invalid refresh token)
        if (error?.status === 400 || error?.status === 401) {
          logInfo(logLevel, 'Refresh token is invalid, clearing tokens');
          
          // Clear all OAuth2 tokens from storage
          storageService.clearAll();
          
          // Redirect to logout route if configured
          if (config.logoutRedirectRoute) {
            logInfo(logLevel, `Redirecting to logout route: ${config.logoutRedirectRoute}`);
            router.navigate([config.logoutRedirectRoute]);
          }
        } else {
          logInfo(logLevel, 'Network/server error, not clearing tokens');
        }
        
        return throwError(() => error);
      })
    );
  } else {
    // Wait for refresh to complete, then retry request
    return refreshTokenSubject.pipe(
      filter(token => token != null),
      take(1),
      switchMap(token => next(addTokenToRequest(request, token)))
    );
  }
}

/**
 * Debug logging
 */
function logDebug(logLevel: OAuth2LogLevel, message: string, ...args: any[]): void {
  if (logLevel === 'debug') {
    console.log(`[OAuth2Interceptor] ${message}`, ...args);
  }
}

/**
 * Info logging
 */
function logInfo(logLevel: OAuth2LogLevel, message: string, ...args: any[]): void {
  if (['debug', 'info'].includes(logLevel)) {
    console.info(`[OAuth2Interceptor] ${message}`, ...args);
  }
}

/**
 * Error logging
 */
function logError(logLevel: OAuth2LogLevel, message: string, error?: any): void {
  if (logLevel !== 'none') {
    console.error(`[OAuth2Interceptor] ${message}`, error);
  }
}