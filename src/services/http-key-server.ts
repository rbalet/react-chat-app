import type {
  KeyServerClient,
  PublishedKeys,
  SerializedPreKeyBundle,
} from "../signal";

/**
 * HTTP-based KeyServerClient — replaces the localStorage dummy.
 * Talks to the Express backend (POST/GET /keys/:userId).
 */
export class HttpKeyServer implements KeyServerClient {
  private readonly baseUrl: string;

  constructor(baseUrl = "/keys") {
    this.baseUrl = baseUrl;
  }

  async publishKeys(userId: string, keys: PublishedKeys): Promise<void> {
    const res = await fetch(`${this.baseUrl}/${userId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(keys),
    });
    if (!res.ok) {
      throw new Error(`publishKeys failed: ${res.status} ${await res.text()}`);
    }
  }

  async fetchPreKeyBundle(userId: string): Promise<SerializedPreKeyBundle> {
    const res = await fetch(`${this.baseUrl}/${userId}`);
    if (!res.ok) {
      throw new Error(`fetchPreKeyBundle failed: ${res.status} ${await res.text()}`);
    }
    return (await res.json()) as SerializedPreKeyBundle;
  }
}
