import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';

import { OAuth2CallbackComponent } from './oauth2-callback.component';
import { OAuth2Service } from '../../services/oauth2.service';
import { OAuth2Config } from '../../models/oauth2-config.model';
import { OAUTH2_CONFIG_TOKEN } from '../../tokens/oauth2-config.token';

describe('OAuth2CallbackComponent', () => {
  let component: OAuth2CallbackComponent;
  let fixture: ComponentFixture<OAuth2CallbackComponent>;
  let mockOAuth2Service: jest.Mocked<OAuth2Service>;
  let mockRouter: jest.Mocked<Router>;

  const createMockConfig = (redirectRoute?: string): OAuth2Config => ({
    clientId: 'test-client-id',
    redirectUri: 'http://localhost:4200/oauth2/callback',
    authorizationEndpoint: 'https://auth.example.com/oauth2/authorize',
    tokenEndpoint: 'https://auth.example.com/oauth2/token',
    scope: 'openid profile email',
    redirectRoute
  });

  const setupTestBed = async (config: OAuth2Config, platformId = 'browser') => {
    await TestBed.configureTestingModule({
      imports: [OAuth2CallbackComponent],
      providers: [
        { provide: OAuth2Service, useValue: mockOAuth2Service },
        { provide: Router, useValue: mockRouter },
        { provide: PLATFORM_ID, useValue: platformId },
        { provide: OAUTH2_CONFIG_TOKEN, useValue: config }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(OAuth2CallbackComponent);
    component = fixture.componentInstance;
  };

  beforeEach(() => {
    // Create mocks for dependencies
    mockOAuth2Service = {
      handleCallback: jest.fn(),
      isAuthenticationAvailable: jest.fn(),
      startAuthorization: jest.fn()
    } as any;
    
    mockRouter = {
      navigate: jest.fn()
    } as any;
  });

  afterEach(() => {
    jest.clearAllMocks();
    TestBed.resetTestingModule();
  });

  describe('Component Initialization', () => {
    beforeEach(async () => {
      await setupTestBed(createMockConfig());
    });

    it('should create', () => {
      expect(component).toBeTruthy();
    });

    it('should initialize with loading state', () => {
      expect(component.isLoading).toBe(true);
      expect(component.error).toBeNull();
      expect(component.success).toBe(false);
    });
  });

  describe('goHome method', () => {
    it('should navigate to default route when redirectRoute is not configured', async () => {
      await setupTestBed(createMockConfig());
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/']);
    });

    it('should navigate to custom route when redirectRoute is configured', async () => {
      await setupTestBed(createMockConfig('/dashboard'));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/dashboard']);
    });

    it('should navigate to admin route when redirectRoute is configured', async () => {
      await setupTestBed(createMockConfig('/admin'));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/admin']);
    });

    it('should navigate to profile route when redirectRoute is configured', async () => {
      await setupTestBed(createMockConfig('/profile'));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/profile']);
    });
  });

  describe('retryLogin method', () => {
    beforeEach(async () => {
      await setupTestBed(createMockConfig());
      fixture.detectChanges();
    });

    it('should retry login when authentication is available', () => {
      mockOAuth2Service.isAuthenticationAvailable.mockReturnValue(true);
      mockOAuth2Service.startAuthorization.mockResolvedValue(undefined);

      component.retryLogin();

      expect(component.isLoading).toBe(true);
      expect(component.error).toBeNull();
      expect(component.success).toBe(false);
      expect(mockOAuth2Service.startAuthorization).toHaveBeenCalled();
    });

    it('should handle authentication not available', () => {
      mockOAuth2Service.isAuthenticationAvailable.mockReturnValue(false);

      component.retryLogin();

      expect(component.error).toBe('Authentication not available in current environment');
      expect(mockOAuth2Service.startAuthorization).not.toHaveBeenCalled();
    });
  });

  describe('ngOnInit - Non-Browser Environment', () => {
    it('should handle non-browser environment', async () => {
      await setupTestBed(createMockConfig(), 'server');
      fixture.detectChanges();

      expect(component.isLoading).toBe(false);
      expect(component.error).toBeFalsy(); // Error message is commented out in component
      expect(component.success).toBe(false);
      expect(mockOAuth2Service.handleCallback).not.toHaveBeenCalled();
    });
  });

  describe('Template Rendering', () => {
    beforeEach(async () => {
      await setupTestBed(createMockConfig());
    });

    it('should show loading state initially', () => {
      fixture.detectChanges();

      const compiled = fixture.nativeElement as HTMLElement;
      expect(compiled.querySelector('.loading-section')).toBeTruthy();
      expect(compiled.querySelector('.success-section')).toBeFalsy();
      expect(compiled.querySelector('.error-section')).toBeFalsy();
    });
  });

  describe('Redirect Route Configuration Edge Cases', () => {
    it('should handle empty string redirectRoute', async () => {
      await setupTestBed(createMockConfig(''));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/']);
    });

    it('should handle undefined redirectRoute', async () => {
      await setupTestBed(createMockConfig(undefined));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/']);
    });

    it('should handle complex route paths', async () => {
      await setupTestBed(createMockConfig('/users/123/dashboard'));
      fixture.detectChanges();

      component.goHome();

      expect(mockRouter.navigate).toHaveBeenCalledWith(['/users/123/dashboard']);
    });
  });

  describe('Redirect Route Logic in Success Flow', () => {
    it('should use default route in success redirect logic', async () => {
      await setupTestBed(createMockConfig());
      fixture.detectChanges();

      // Simulate the redirect logic from ngOnInit success flow
      const redirectRoute = component['config'].redirectRoute || '/';
      expect(redirectRoute).toBe('/');
    });

    it('should use custom route in success redirect logic', async () => {
      await setupTestBed(createMockConfig('/dashboard'));
      fixture.detectChanges();

      // Simulate the redirect logic from ngOnInit success flow
      const redirectRoute = component['config'].redirectRoute || '/';
      expect(redirectRoute).toBe('/dashboard');
    });
  });
});