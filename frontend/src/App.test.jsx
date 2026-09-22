import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from '../app.jsx';

describe('App bootstrap', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the dashboard shell even if storage access throws', () => {
    const originalLocalStorage = window.localStorage;
    const originalSessionStorage = window.sessionStorage;

    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: {
        getItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
        setItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
        removeItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
      },
    });

    Object.defineProperty(window, 'sessionStorage', {
      configurable: true,
      value: {
        getItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
        setItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
        removeItem: vi.fn(() => {
          throw new Error('storage blocked');
        }),
      },
    });

    render(<App />);

    expect(screen.getByText('Scam Shield')).toBeInTheDocument();
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0);

    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: originalLocalStorage,
    });
    Object.defineProperty(window, 'sessionStorage', {
      configurable: true,
      value: originalSessionStorage,
    });
  });
});
