import { setupZoneTestEnv } from 'jest-preset-angular/setup-env/zone';

// Setup Zone.js testing environment
setupZoneTestEnv();

// Mock global objects that might be needed
Object.defineProperty(window, 'CSS', { value: null });
Object.defineProperty(window, 'getComputedStyle', {
  value: () => {
    return {
      display: 'none',
      appearance: ['-webkit-appearance']
    };
  }
});

Object.defineProperty(document, 'doctype', {
  value: '<!DOCTYPE html>'
});

Object.defineProperty(document.body.style, 'transform', {
  value: () => {
    return {
      enumerable: true,
      configurable: true
    };
  }
});

// Mock crypto for PKCE tests
Object.defineProperty(globalThis, 'crypto', {
  value: {
    getRandomValues: (arr: any) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256);
      }
      return arr;
    },
    subtle: {
      digest: jest.fn().mockResolvedValue(new ArrayBuffer(32))
    }
  }
});

// Mock TextEncoder/TextDecoder
(globalThis as any).TextEncoder = TextEncoder;
(globalThis as any).TextDecoder = TextDecoder;

// Mock btoa/atob
(globalThis as any).btoa = (str: string) => Buffer.from(str, 'binary').toString('base64');
(globalThis as any).atob = (str: string) => Buffer.from(str, 'base64').toString('binary');