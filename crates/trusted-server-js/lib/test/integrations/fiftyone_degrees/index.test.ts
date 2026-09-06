import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

async function importModule() {
  vi.resetModules();
  return import('../../../src/integrations/fiftyone_degrees/index');
}

function cookieValue(name: string): string | undefined {
  const entry = document.cookie.split(';').find((part) => part.trim().startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.trim().slice(name.length + 1)) : undefined;
}

function clearCookies(): void {
  for (const name of [
    '51D_ScreenPixelsWidth',
    '51D_ScreenPixelsHeight',
    '51D_GetHighEntropyValues',
  ]) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
}

describe('fiftyone_degrees', () => {
  // The page state the edge injects. The default grants the permission this
  // module requires, so the gathering tests below hold.
  function setPageState(set: string[] | undefined): void {
    if (set === undefined) {
      delete window.tsjs;
      return;
    }
    window.tsjs = {
      whenPermissions: () => Promise.resolve({ set }),
    } as unknown as NonNullable<typeof window.tsjs>;
  }

  beforeEach(() => {
    clearCookies();
    sessionStorage.clear();
    setPageState(['necessary.operations.storage']);
  });

  afterEach(() => {
    clearCookies();
    sessionStorage.clear();
    delete window.tsjs;
    vi.resetModules();
  });

  it('gathers nothing when the permission to store on the device is not set', async () => {
    setPageState([]);
    const module = await importModule();

    const gathered = await module.gatherEvidence();

    expect(gathered).toBeNull();
    expect(cookieValue('51D_ScreenPixelsWidth')).toBeUndefined();
  });

  it('gathers nothing when the page carries no permission state at all', async () => {
    // A missing value is not permission. Writing to a visitor's device on the
    // strength of an absent check is the failure this guards.
    setPageState(undefined);
    const module = await importModule();

    expect(await module.gatherEvidence()).toBeNull();
  });

  it('writes the screen size where the server will read it', async () => {
    const module = await importModule();

    await module.gatherEvidence();

    expect(cookieValue('51D_ScreenPixelsWidth')).toBe(String(screen.width));
    expect(cookieValue('51D_ScreenPixelsHeight')).toBe(String(screen.height));
  });

  it('uses the cookie names the service its own JavaScript writes', async () => {
    // Matching the vendor's names is what lets the server read this evidence
    // whether this module or the vendor bundle wrote it. A rename here breaks
    // that silently, so it is asserted rather than left to the comment.
    const module = await importModule();

    await module.gatherEvidence();

    expect(document.cookie).toContain('51D_ScreenPixelsWidth=');
    expect(document.cookie).toContain('51D_ScreenPixelsHeight=');
  });

  it('keeps what it gathered for the rest of the session', async () => {
    const module = await importModule();

    await module.gatherEvidence();

    expect(module.readStoredEvidence()).not.toBeNull();
    expect(module.readStoredEvidence()?.['51D_ScreenPixelsWidth']).toBe(String(screen.width));
  });

  it('reuses stored client hints rather than asking the browser again', async () => {
    const module = await importModule();
    module.storeEvidence({ '51D_GetHighEntropyValues': 'stored-value' });

    await module.gatherEvidence();

    expect(cookieValue('51D_GetHighEntropyValues')).toBe('stored-value');
  });

  it('resolves no client hints on a browser without the API', async () => {
    // Every browser outside the Chromium family. Not a failure: the server
    // still has the User-Agent and answers from that.
    const module = await importModule();

    expect(await module.highEntropyValues()).toBeNull();
  });

  it('survives storage being unavailable', async () => {
    // A private window can throw on access rather than returning nothing.
    // Losing the cache costs nothing, because the cookies are what the server
    // reads, so this must not stop the gathering.
    const module = await importModule();
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('storage is unavailable');
    });

    const gathered = await module.gatherEvidence();

    expect(gathered).not.toBeNull();
    expect(cookieValue('51D_ScreenPixelsWidth')).toBe(String(screen.width));
    setItem.mockRestore();
  });
});
