import { InjectionToken } from '@angular/core';
import { OAuth2Config } from '../models/oauth2-config.model';

/**
 * Injection token for OAuth2 configuration
 */
export const OAUTH2_CONFIG_TOKEN = new InjectionToken<OAuth2Config>('OAUTH2_CONFIG');