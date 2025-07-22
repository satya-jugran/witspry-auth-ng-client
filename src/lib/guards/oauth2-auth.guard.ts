import { inject } from '@angular/core';
import { Router, CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable, of } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { OAuth2Service } from '../services/oauth2.service';
import { OAUTH2_CONFIG_TOKEN } from '../tokens';

/**
 * OAuth2 Authentication Guard Function
 * Protects routes by checking if user is authenticated
 */
export const oauth2AuthGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
): Observable<boolean> | Promise<boolean> | boolean => {
  const oauth2Service = inject(OAuth2Service);
  const router = inject(Router);
  const config = inject(OAUTH2_CONFIG_TOKEN);

  // Check if authentication is available in current environment
  if (!oauth2Service.isAuthenticationAvailable()) {
    console.warn('[OAuth2AuthGuard] Authentication not available in current environment');
    return false;
  }

  // Check current authentication state
  return oauth2Service.authState$.pipe(
    take(1),
    map(authState => {
      if (authState.isAuthenticated) {
        return true;
      }

      // Check if we have stored tokens that might be valid
      if (oauth2Service.isAuthenticated()) {
        return true;
      }

      // User is not authenticated, check for refresh token and attempt to refresh
      if (config.autoRefresh) {
        oauth2Service.refreshAccessToken().catch(error => {
          console.error('[OAuth2AuthGuard] Failed to refresh access token:', error);
          oauth2Service.startAuthorization().catch(error => {
            console.error('[OAuth2AuthGuard] Failed to start OAuth2 flow:', error);
          });
        });
      } else {
        // You can customize this behavior:
        // Option 1: Start OAuth2 flow immediately
        oauth2Service.startAuthorization().catch(error => {
          console.error('[OAuth2AuthGuard] Failed to start OAuth2 flow:', error);
        });
        // Option 2: Redirect to a login page
        // router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
      }
      
      
      return false;
    })
  );
};

/**
 * OAuth2 Authentication Guard Class (for backward compatibility)
 * @deprecated Use oauth2AuthGuard function instead
 */
export class OAuth2AuthGuard {
  constructor(
    private oauth2Service: OAuth2Service,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {
    // Check if authentication is available in current environment
    if (!this.oauth2Service.isAuthenticationAvailable()) {
      console.warn('[OAuth2AuthGuard] Authentication not available in current environment');
      return false;
    }

    // Check current authentication state
    return this.oauth2Service.authState$.pipe(
      take(1),
      map(authState => {
        if (authState.isAuthenticated) {
          return true;
        }

        // Check if we have stored tokens that might be valid
        if (this.oauth2Service.isAuthenticated()) {
          return true;
        }

        // User is not authenticated, redirect to login or start OAuth flow
        console.log('[OAuth2AuthGuard] User not authenticated, starting OAuth2 flow');
        
        this.oauth2Service.startAuthorization().catch(error => {
          console.error('[OAuth2AuthGuard] Failed to start OAuth2 flow:', error);
        });
        
        return false;
      })
    );
  }
}

/**
 * OAuth2 Unauthenticated Guard Function
 * Protects routes that should only be accessible to unauthenticated users
 * (e.g., login page, registration page)
 */
export const oauth2UnauthGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
): Observable<boolean> | Promise<boolean> | boolean => {
  const oauth2Service = inject(OAuth2Service);
  const router = inject(Router);

  // Check if authentication is available in current environment
  if (!oauth2Service.isAuthenticationAvailable()) {
    return true; // Allow access if auth is not available
  }

  // Check current authentication state
  return oauth2Service.authState$.pipe(
    take(1),
    map(authState => {
      if (!authState.isAuthenticated && !oauth2Service.isAuthenticated()) {
        return true; // User is not authenticated, allow access
      }

      // User is authenticated, redirect to protected area
      console.log('[OAuth2UnauthGuard] User already authenticated, redirecting');
      router.navigate(['/']); // Redirect to home or dashboard
      return false;
    })
  );
};

/**
 * OAuth2 Role Guard Function
 * Protects routes based on user roles or permissions
 */
export interface OAuth2RoleGuardConfig {
  roles?: string[];
  permissions?: string[];
  requireAll?: boolean; // If true, user must have ALL roles/permissions. If false, user needs ANY.
}

export function oauth2RoleGuard(config: OAuth2RoleGuardConfig): CanActivateFn {
  return (route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean => {
    const oauth2Service = inject(OAuth2Service);
    const router = inject(Router);

    // First check if user is authenticated
    if (!oauth2Service.isAuthenticated()) {
      console.log('[OAuth2RoleGuard] User not authenticated');
      oauth2Service.startAuthorization().catch(error => {
        console.error('[OAuth2RoleGuard] Failed to start OAuth2 flow:', error);
      });
      return false;
    }

    // If no roles or permissions specified, just check authentication
    if (!config.roles?.length && !config.permissions?.length) {
      return true;
    }

    // Get user info to check roles/permissions
    return oauth2Service.getUserInfo().then(userInfo => {
      const userRoles = (userInfo as any).roles || [];
      const userPermissions = (userInfo as any).permissions || [];

      let hasRequiredRoles = true;
      let hasRequiredPermissions = true;

      // Check roles
      if (config.roles?.length) {
        if (config.requireAll) {
          hasRequiredRoles = config.roles.every(role => userRoles.includes(role));
        } else {
          hasRequiredRoles = config.roles.some(role => userRoles.includes(role));
        }
      }

      // Check permissions
      if (config.permissions?.length) {
        if (config.requireAll) {
          hasRequiredPermissions = config.permissions.every(permission => userPermissions.includes(permission));
        } else {
          hasRequiredPermissions = config.permissions.some(permission => userPermissions.includes(permission));
        }
      }

      const hasAccess = hasRequiredRoles && hasRequiredPermissions;

      if (!hasAccess) {
        console.warn('[OAuth2RoleGuard] User does not have required roles/permissions');
        router.navigate(['/unauthorized']); // Redirect to unauthorized page
      }

      return hasAccess;
    }).catch(error => {
      console.error('[OAuth2RoleGuard] Failed to get user info:', error);
      return false;
    });
  };
}