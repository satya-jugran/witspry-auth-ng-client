import { Component, OnInit, Inject, PLATFORM_ID } from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { OAuth2Service } from '../../services/oauth2.service';
import { OAuth2Config } from '../../models/oauth2-config.model';
import { OAUTH2_CONFIG_TOKEN } from '../../tokens/oauth2-config.token';

/**
 * OAuth2 Callback Component
 * Handles the OAuth2 authorization callback and processes the authorization code
 */
@Component({
  selector: 'lib-oauth2-callback',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="oauth2-callback-container">
      <div class="oauth2-callback-content">
        <div *ngIf="isLoading" class="loading-section">
          <div class="spinner"></div>
          <h2>Processing Authentication...</h2>
          <p>Please wait while we complete your login.</p>
        </div>

        <div *ngIf="success && !isLoading" class="success-section">
          <div class="success-icon">✓</div>
          <h2>Authentication Successful!</h2>
          <p>You will be redirected shortly...</p>
        </div>

        <div *ngIf="error && !isLoading && !success" class="error-section">
          <div class="error-icon">✗</div>
          <h2>Authentication Failed</h2>
          <p class="error-message">{{ error }}</p>
          <div class="error-actions">
            <button (click)="retryLogin()" class="retry-button">
              Try Again
            </button>
            <button (click)="goHome()" class="home-button">
              Go Home
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .oauth2-callback-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background-color: #f5f5f5;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    .oauth2-callback-content {
      background: white;
      border-radius: 8px;
      padding: 2rem;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      text-align: center;
      max-width: 400px;
      width: 100%;
      margin: 1rem;
    }

    .loading-section h2,
    .success-section h2,
    .error-section h2 {
      margin: 1rem 0 0.5rem 0;
      color: #333;
    }

    .loading-section p,
    .success-section p {
      color: #666;
      margin-bottom: 0;
    }

    .spinner {
      border: 3px solid #f3f3f3;
      border-top: 3px solid #007bff;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 0 auto 1rem auto;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    .success-icon {
      width: 60px;
      height: 60px;
      border-radius: 50%;
      background-color: #28a745;
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      font-weight: bold;
      margin: 0 auto 1rem auto;
    }

    .error-icon {
      width: 60px;
      height: 60px;
      border-radius: 50%;
      background-color: #dc3545;
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
      font-weight: bold;
      margin: 0 auto 1rem auto;
    }

    .error-message {
      color: #dc3545;
      margin: 1rem 0;
      padding: 0.5rem;
      background-color: #f8d7da;
      border: 1px solid #f5c6cb;
      border-radius: 4px;
      font-size: 0.9rem;
    }

    .error-actions {
      display: flex;
      gap: 1rem;
      justify-content: center;
      margin-top: 1.5rem;
    }

    .retry-button,
    .home-button {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      transition: background-color 0.2s;
    }

    .retry-button {
      background-color: #007bff;
      color: white;
    }

    .retry-button:hover {
      background-color: #0056b3;
    }

    .home-button {
      background-color: #6c757d;
      color: white;
    }

    .home-button:hover {
      background-color: #545b62;
    }

    @media (max-width: 480px) {
      .oauth2-callback-content {
        margin: 0.5rem;
        padding: 1.5rem;
      }

      .error-actions {
        flex-direction: column;
      }

      .retry-button,
      .home-button {
        width: 100%;
      }
    }
  `]
})
export class OAuth2CallbackComponent implements OnInit {
  isLoading = true;
  error: string | null = null;
  success = false;

  constructor(
    private oauth2Service: OAuth2Service,
    private router: Router,
    @Inject(PLATFORM_ID) private platformId: Object,
    @Inject(OAUTH2_CONFIG_TOKEN) private config: OAuth2Config
  ) {}

  async ngOnInit(): Promise<void> {
    // Only handle callback in browser environment
    if (!isPlatformBrowser(this.platformId)) {
      this.isLoading = false;
      this.error = 'Browser environment required for OAuth2 callback';
      return;
    }

    // Add a small delay to ensure the component is fully rendered on client side
    setTimeout(async () => {
      try {
        console.log('Starting OAuth2 callback processing...');
        console.log('Current URL:', window.location.href);
        console.log('LocalStorage available:', typeof(Storage) !== "undefined");
        
        // Handle the OAuth2 callback
        await this.oauth2Service.handleCallback();
        
        // Success
        this.isLoading = false;
        this.success = true;
        this.error = null; // Clear any previous error
        
        // Redirect after a short delay
        setTimeout(() => {
          // Use configurable redirect route from OAuth2Config, defaulting to '/'
          const redirectRoute = this.config.redirectRoute || '/';
          this.router.navigate([redirectRoute]);
        }, 2000);
        
      } catch (error) {
        console.error('OAuth2 callback error:', error);
        this.isLoading = false;
        this.error = error instanceof Error ? error.message : 'Authentication failed';
      }
    }, 100);
  }

  retryLogin(): void {
    if (!this.oauth2Service.isAuthenticationAvailable()) {
      this.error = 'Authentication not available in current environment';
      return;
    }

    this.isLoading = true;
    this.error = null;
    this.success = false;
    
    this.oauth2Service.startAuthorization().catch(error => {
      console.error('Retry login error:', error);
      this.isLoading = false;
      this.error = 'Failed to start authentication';
    });
  }

  goHome(): void {
    // Use configurable redirect route from OAuth2Config, defaulting to '/'
    const redirectRoute = this.config.redirectRoute || '/';
    this.router.navigate([redirectRoute]);
  }
}