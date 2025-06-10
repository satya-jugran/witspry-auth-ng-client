import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { OAuth2Config, OAuth2Storage } from '../models/oauth2-config.model';
import { OAUTH2_STORAGE_KEYS, OAuth2LogLevel } from '../models/oauth2-types.model';
import { OAUTH2_CONFIG_TOKEN } from '../tokens/oauth2-config.token';

/**
 * OAuth2 Storage Service
 * Handles secure storage and retrieval of OAuth2 tokens and data
 */
@Injectable({
  providedIn: 'root'
})
export class OAuth2StorageService {
  private storage: OAuth2Storage;
  private logLevel: OAuth2LogLevel;

  constructor(
    @Inject(OAUTH2_CONFIG_TOKEN) private config: OAuth2Config,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    this.logLevel = config.logLevel || 'warn';
    this.storage = this.initializeStorage();
  }

  /**
   * Initialize storage based on configuration
   */
  private initializeStorage(): OAuth2Storage {
    if (!isPlatformBrowser(this.platformId)) {
      // Return a no-op storage for SSR
      return {
        getItem: () => null,
        setItem: () => {},
        removeItem: () => {},
        clear: () => {}
      };
    }

    switch (this.config.storage) {
      case 'sessionStorage':
        return sessionStorage;
      case 'custom':
        if (!this.config.customStorage) {
          this.logError('Custom storage specified but not provided');
          return localStorage;
        }
        return this.config.customStorage;
      case 'localStorage':
      default:
        return localStorage;
    }
  }

  /**
   * Store a value securely
   */
  setItem(key: string, value: string): void {
    try {
      // In production, consider encrypting sensitive values
      this.storage.setItem(key, value);
      this.logDebug(`Stored item with key: ${key}`);
    } catch (error) {
      this.logError('Error storing item:', error);
      throw new Error('Failed to store item');
    }
  }

  /**
   * Retrieve a value securely
   */
  getItem(key: string): string | null {
    try {
      const value = this.storage.getItem(key);
      this.logDebug(`Retrieved item with key: ${key}`, value ? 'Found' : 'Not found');
      return value;
    } catch (error) {
      this.logError('Error retrieving item:', error);
      return null;
    }
  }

  /**
   * Remove a specific item
   */
  removeItem(key: string): void {
    try {
      this.storage.removeItem(key);
      this.logDebug(`Removed item with key: ${key}`);
    } catch (error) {
      this.logError('Error removing item:', error);
    }
  }

  /**
   * Clear all OAuth2 related storage
   */
  clearAll(): void {
    try {
      Object.values(OAUTH2_STORAGE_KEYS).forEach(key => {
        this.storage.removeItem(key);
      });
      this.logDebug('Cleared all OAuth2 storage');
    } catch (error) {
      this.logError('Error clearing storage:', error);
    }
  }

  /**
   * Clear only token-related storage, preserve OAuth2 flow storage
   */
  clearTokens(): void {
    try {
      const tokenKeys = [
        OAUTH2_STORAGE_KEYS.ACCESS_TOKEN,
        OAUTH2_STORAGE_KEYS.REFRESH_TOKEN,
        OAUTH2_STORAGE_KEYS.TOKEN_EXPIRES_AT,
        OAUTH2_STORAGE_KEYS.TOKEN_TYPE,
        OAUTH2_STORAGE_KEYS.SCOPE,
        OAUTH2_STORAGE_KEYS.ID_TOKEN
      ];
      
      tokenKeys.forEach(key => {
        this.storage.removeItem(key);
      });
      
      this.logDebug('Cleared token storage (OAuth2 flow storage preserved)');
    } catch (error) {
      this.logError('Error clearing token storage:', error);
    }
  }

  /**
   * Clear temporary OAuth2 flow storage
   */
  clearTemporary(): void {
    try {
      this.storage.removeItem(OAUTH2_STORAGE_KEYS.CODE_VERIFIER);
      this.storage.removeItem(OAUTH2_STORAGE_KEYS.STATE);
      this.storage.removeItem(OAUTH2_STORAGE_KEYS.NONCE);
      this.logDebug('Cleared temporary OAuth2 storage');
    } catch (error) {
      this.logError('Error clearing temporary storage:', error);
    }
  }

  /**
   * Check if storage is available
   */
  isAvailable(): boolean {
    return isPlatformBrowser(this.platformId);
  }

  /**
   * Get all stored keys (for debugging)
   */
  getStoredKeys(): string[] {
    if (!this.isAvailable()) {
      return [];
    }

    try {
      const keys: string[] = [];
      for (let i = 0; i < (this.storage as any).length; i++) {
        const key = (this.storage as any).key(i);
        if (key && Object.values(OAUTH2_STORAGE_KEYS).includes(key)) {
          keys.push(key);
        }
      }
      return keys;
    } catch (error) {
      this.logError('Error getting stored keys:', error);
      return [];
    }
  }

  /**
   * Debug logging
   */
  private logDebug(message: string, ...args: any[]): void {
    if (this.logLevel === 'debug') {
      console.log(`[OAuth2StorageService] ${message}`, ...args);
    }
  }

  /**
   * Info logging
   */
  private logInfo(message: string, ...args: any[]): void {
    if (['debug', 'info'].includes(this.logLevel)) {
      console.info(`[OAuth2StorageService] ${message}`, ...args);
    }
  }

  /**
   * Warning logging
   */
  private logWarn(message: string, ...args: any[]): void {
    if (['debug', 'info', 'warn'].includes(this.logLevel)) {
      console.warn(`[OAuth2StorageService] ${message}`, ...args);
    }
  }

  /**
   * Error logging
   */
  private logError(message: string, error?: any): void {
    if (this.logLevel !== 'none') {
      console.error(`[OAuth2StorageService] ${message}`, error);
    }
  }
}