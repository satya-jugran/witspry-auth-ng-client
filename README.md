# witspry-auth-ng-client

A comprehensive Angular library for OAuth2 authentication with PKCE (Proof Key for Code Exchange) support. This library provides secure, configurable, and easy-to-use OAuth2 authentication for Angular applications.

## Features

- ✅ **PKCE Support**: Implements OAuth2 PKCE flow with SHA-256 for enhanced security
- ✅ **Automatic Token Refresh**: Handles token refresh automatically with configurable thresholds
- ✅ **SSR Compatible**: Works with Angular Universal and server-side rendering
- ✅ **Configurable Storage**: Support for localStorage, sessionStorage, or custom storage
- ✅ **HTTP Interceptor**: Automatically adds Bearer tokens to HTTP requests
- ✅ **Route Guards**: Protect routes with authentication and role-based guards
- ✅ **TypeScript**: Full TypeScript support with comprehensive type definitions
- ✅ **Standalone Components**: Support for Angular 14+ standalone components
- ✅ **Customizable**: Highly configurable to work with different OAuth2 providers

## Installation

```bash
npm install witspry-auth-ng-client
```

## Quick Start

### 1. Configure OAuth2 in your app

```typescript
// app.config.ts
import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideOAuth2 } from 'witspry-auth-ng-client';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideOAuth2({
      clientId: 'your-client-id',
      redirectUri: 'http://localhost:4200/auth/callback',
      authorizationEndpoint: 'https://your-auth-server.com/auth/authorize',
      tokenEndpoint: 'https://your-auth-server.com/auth/oauth/token',
      revokeEndpoint: 'https://your-auth-server.com/auth/oauth/revoke',
      userInfoEndpoint: 'https://your-auth-server.com/userinfo',
      scope: 'openid profile email',
      audience: 'https://your-api.com'
    })
  ]
};
```

### 2. Add callback route

```typescript
// app.routes.ts
import { Routes } from '@angular/router';
import { OAuth2CallbackComponent } from 'witspry-auth-ng-client';

export const routes: Routes = [
  {
    path: 'auth/callback',
    component: OAuth2CallbackComponent
  },
  // ... other routes
];
```

### 3. Use in your components

```typescript
// login.component.ts
import { Component } from '@angular/core';
import { OAuth2Service } from 'witspry-auth-ng-client';

@Component({
  selector: 'app-login',
  template: `
    <button (click)="login()" [disabled]="!oauth2Service.isAuthenticationAvailable()">
      Login with OAuth2
    </button>
  `
})
export class LoginComponent {
  constructor(public oauth2Service: OAuth2Service) {}

  login() {
    this.oauth2Service.startAuthorization();
  }
}
```

### 4. Protect routes with guards

```typescript
// app.routes.ts
import { Routes } from '@angular/router';
import { oauth2AuthGuard } from 'witspry-auth-ng-client';

export const routes: Routes = [
  {
    path: 'protected',
    component: ProtectedComponent,
    canActivate: [oauth2AuthGuard]
  }
];
```

## Configuration Options

```typescript
interface OAuth2Config {
  clientId: string;                    // OAuth2 Client ID
  redirectUri: string;                 // Redirect URI for callback
  authorizationEndpoint: string;       // Authorization endpoint URL
  tokenEndpoint: string;               // Token endpoint URL
  revokeEndpoint?: string;             // Token revocation endpoint (optional)
  userInfoEndpoint?: string;           // OIDC UserInfo endpoint (optional)
  audience?: string;                   // OAuth2 audience parameter (optional)
  scope: string;                       // OAuth2 scope parameter
  responseType?: 'code';               // Response type (default: 'code')
  codeChallengeMethod?: 'S256';        // PKCE method (default: 'S256')
  storage?: 'localStorage' | 'sessionStorage' | 'custom'; // Storage strategy
  customStorage?: OAuth2Storage;       // Custom storage implementation
  autoRefresh?: boolean;               // Enable auto token refresh (default: true)
  refreshThreshold?: number;           // Seconds before expiry to refresh (default: 300)
  logLevel?: 'none' | 'error' | 'warn' | 'info' | 'debug'; // Logging level
  nonce?: string;                      // Custom nonce (optional)
}
```

## Advanced Usage

### Custom Storage

```typescript
import { OAuth2Storage } from 'witspry-auth-ng-client';

class CustomStorage implements OAuth2Storage {
  getItem(key: string): string | null {
    // Your custom storage logic
    return null;
  }
  
  setItem(key: string, value: string): void {
    // Your custom storage logic
  }
  
  removeItem(key: string): void {
    // Your custom storage logic
  }
}

// Use in configuration
provideOAuth2({
  // ... other config
  storage: 'custom',
  customStorage: new CustomStorage()
})
```

### Custom Redirect Routes For Login And Logout

```typescript
import { OAuth2Config } from 'witspry-auth-ng-client';

const oauth2Config: OAuth2Config = {
  clientId: 'your-client-id',
  redirectUri: 'http://localhost:4200/oauth2/callback',
  authorizationEndpoint: 'https://auth.example.com/oauth2/authorize',
  tokenEndpoint: 'https://auth.example.com/oauth2/token',
  scope: 'openid profile email',
  redirectRoute: '/dashboard'
  logoutRedirectRoute: '/home'
};
```

### Role-based Guards

```typescript
import { oauth2RoleGuard } from 'witspry-auth-ng-client';

const routes: Routes = [
  {
    path: 'admin',
    component: AdminComponent,
    canActivate: [oauth2RoleGuard({
      roles: ['admin', 'super-admin'],
      requireAll: false // User needs ANY of the roles
    })]
  }
];
```

### Manual HTTP Interceptor Setup

```typescript
// If you want to configure the HTTP interceptor manually
import { provideOAuth2WithoutInterceptor, oauth2InterceptorFn } from 'witspry-auth-ng-client';
import { provideHttpClient, withInterceptors } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
  providers: [
    provideOAuth2WithoutInterceptor(config),
    provideHttpClient(
      withInterceptors([oauth2InterceptorFn])
    )
  ]
};
```

### Using with NgModule (Legacy)

```typescript
// app.module.ts
import { NgOAuth2PkceModule } from 'witspry-auth-ng-client';

@NgModule({
  imports: [
    NgOAuth2PkceModule.forRoot({
      clientId: 'your-client-id',
      // ... other config
    })
  ]
})
export class AppModule {}
```

## API Reference

### OAuth2Service

#### Methods

- `startAuthorization(): Promise<void>` - Start OAuth2 authorization flow
- `handleCallback(): Promise<void>` - Handle OAuth2 callback
- `getAccessToken(): string | null` - Get current valid access token
- `getRefreshToken(): string | null` - Get current refresh token
- `isAuthenticated(): boolean` - Check if user is authenticated
- `getUserInfo(): Promise<UserInfoResponse>` - Get user information
- `refreshAccessToken(): Promise<string>` - Manually refresh access token
- `logout(): Promise<void>` - Logout user and clear tokens

#### Properties

- `authState$: Observable<AuthState>` - Observable of authentication state
- `authState: Signal<AuthState>` - Signal of authentication state

### Guards

- `oauth2AuthGuard` - Protect routes requiring authentication
- `oauth2UnauthGuard` - Protect routes for unauthenticated users only
- `oauth2RoleGuard(config)` - Protect routes based on user roles/permissions

### Components

- `OAuth2CallbackComponent` - Handle OAuth2 callback with UI feedback

## Browser Support

This library supports all modern browsers that support:
- Web Crypto API (for PKCE)
- ES2017+ features
- Angular 19+

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

### Npm Publish
Update the version in package.json. Make sure the test cases are passing. Then run the following commands:

```
npm run build
cd .\dist\witspry-auth-ng-client\
npm publish
```

## License

MIT License - see LICENSE file for details.

## Changelog

### 1.0.0
- Initial release
- OAuth2 PKCE implementation
- Automatic token refresh
- SSR support
- Configurable storage
- HTTP interceptor
- Route guards
- TypeScript support

### 1.1.0
- Added config parameter logoutRedirectRoute

### 1.1.3
- Fix: error section was visible even on successful login.