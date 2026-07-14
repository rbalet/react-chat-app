import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpKeyServer } from '../http-key-server';
import type { PublishedKeys } from '../../signal';

const KEYS: PublishedKeys = {
  registrationId: 7,
  identityKey: 'aWRlbnRpdHk=',
  signedPreKey: { id: 1, publicKey: 'c3Br', signature: 'c2ln' },
  oneTimePreKeys: [{ id: 10, publicKey: 'b3Br' }],
};

const BUNDLE = {
  registrationId: 7,
  identityKey: 'aWRlbnRpdHk=',
  signedPreKey: { id: 1, publicKey: 'c3Br', signature: 'c2ln' },
  oneTimePreKey: { id: 10, publicKey: 'b3Br' },
};

function stubFetch(response: Response): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('HttpKeyServer', () => {
  it('publishKeys POSTs the bundle as JSON to /keys/:userId', async () => {
    const fetchMock = stubFetch(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    await new HttpKeyServer().publishKeys('alice', KEYS);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/keys/alice');
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(init.body as string)).toEqual(KEYS);
  });

  it('publishKeys throws with the status on a failed response', async () => {
    stubFetch(new Response('{"error":"INVALID_BUNDLE"}', { status: 400 }));

    await expect(new HttpKeyServer().publishKeys('alice', KEYS)).rejects.toThrow(
      /publishKeys failed: 400/,
    );
  });

  it('fetchPreKeyBundle GETs and returns the parsed bundle', async () => {
    const fetchMock = stubFetch(new Response(JSON.stringify(BUNDLE), { status: 200 }));

    const bundle = await new HttpKeyServer().fetchPreKeyBundle('bob');

    expect(fetchMock).toHaveBeenCalledWith('/keys/bob');
    expect(bundle).toEqual(BUNDLE);
  });

  it('fetchPreKeyBundle throws with the status on a missing bundle', async () => {
    stubFetch(new Response('{"error":"NO_BUNDLE"}', { status: 404 }));

    await expect(new HttpKeyServer().fetchPreKeyBundle('ghost')).rejects.toThrow(
      /fetchPreKeyBundle failed: 404/,
    );
  });

  it('honors a custom base URL', async () => {
    const fetchMock = stubFetch(new Response(JSON.stringify(BUNDLE), { status: 200 }));

    await new HttpKeyServer('http://localhost:4000/keys').fetchPreKeyBundle('bob');

    expect(fetchMock).toHaveBeenCalledWith('http://localhost:4000/keys/bob');
  });
});
