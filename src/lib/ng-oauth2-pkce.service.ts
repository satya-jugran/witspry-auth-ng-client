import { EnvironmentProviders, makeEnvironmentProviders } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { OAuth2Config } from './models/oauth2-config.model';
import { OAUTH2_CONFIG_TOKEN } from './tokens/oauth2-config.token';
import { OAuth2Service } from './services/oauth2.service';
import { OAuth2StorageService } from './services/oauth2-storage.service';
import { oauth2InterceptorFn } from './interceptors/oauth2.interceptor';

/**
 * Provide OAuth2 configuration and services
 * Use this function in your app.config.ts or main.ts
 */
export function provideOAuth2(config: OAuth2Config): EnvironmentProviders {
  return makeEnvironmentProviders([
    // Provide the OAuth2 configuration
    { provide: OAUTH2_CONFIG_TOKEN, useValue: config },
    
    // Provide the OAuth2 services
    OAuth2Service,
    OAuth2StorageService,
    
    // Provide HTTP client with OAuth2 interceptor
    provideHttpClient(
      withInterceptors([oauth2InterceptorFn])
    )
  ]);
}

/**
 * Provide OAuth2 configuration and services without HTTP interceptor
 * Use this if you want to manually configure the HTTP interceptor
 */
export function provideOAuth2WithoutInterceptor(config: OAuth2Config): EnvironmentProviders {
  return makeEnvironmentProviders([
    // Provide the OAuth2 configuration
    { provide: OAUTH2_CONFIG_TOKEN, useValue: config },
    
    // Provide the OAuth2 services
    OAuth2Service,
    OAuth2StorageService
  ]);
}

/**
 * Legacy NgModule for backward compatibility
 * @deprecated Use provideOAuth2() function instead
 */
import { NgModule, ModuleWithProviders } from '@angular/core';
import { CommonModule } from '@angular/common';

@NgModule({
  imports: [CommonModule],
  exports: []
})
export class NgOAuth2PkceModule {
  static forRoot(config: OAuth2Config): ModuleWithProviders<NgOAuth2PkceModule> {
    return {
      ngModule: NgOAuth2PkceModule,
      providers: [
        { provide: OAUTH2_CONFIG_TOKEN, useValue: config },
        OAuth2Service,
        OAuth2StorageService
      ]
    };
  }
}