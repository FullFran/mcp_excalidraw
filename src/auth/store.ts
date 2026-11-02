import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomToken } from './crypto.js';

export type ClientAuthMethod = 'none' | 'client_secret_post' | 'client_secret_basic';

export interface RegisteredClient {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  authMethod: ClientAuthMethod;
  /** SHA-256 of the client secret, for confidential DCR clients only. */
  secretHash?: string;
  createdAt: number;
}

export interface TokenRecord {
  clientId: string;
  login: string;
  scope: string;
  resource: string;
  /** Seconds since epoch. */
  expiresAt: number;
  familyId: string;
}

export interface RefreshTokenRecord extends TokenRecord {
  /** Set once the token has been exchanged; a second exchange revokes the family. */
  usedAt?: number;
}

interface FamilyRecord {
  expiresAt: number;
  revokedAt?: number;
}

interface StoreData {
  version: 1;
  clients: Record<string, RegisteredClient>;
  accessTokens: Record<string, TokenRecord>;
  refreshTokens: Record<string, RefreshTokenRecord>;
  families: Record<string, FamilyRecord>;
}

function emptyData(): StoreData {
  return { version: 1, clients: {}, accessTokens: {}, refreshTokens: {}, families: {} };
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Durable token store: one JSON file, written atomically with mode 0600.
 * Keys of the token maps are SHA-256 hashes; raw tokens and client secrets
 * are never written. The data volume is tiny (one user, a few clients), so
 * the whole file is rewritten on every change.
 */
export class AuthStore {
  private data: StoreData;

  constructor(private readonly path: string) {
    this.data = this.load();
    this.prune();
  }

  private load(): StoreData {
    if (!existsSync(this.path)) return emptyData();
    const parsed = JSON.parse(readFileSync(this.path, 'utf8')) as Partial<StoreData>;
    if (parsed.version !== 1) throw new Error(`Unsupported auth store version in ${this.path}`);
    return { ...emptyData(), ...parsed, version: 1 };
  }

  private save(): void {
    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${process.pid}.${randomToken(6)}.tmp`;
    const descriptor = openSync(temporary, 'wx', 0o600);
    try {
      writeSync(descriptor, JSON.stringify(this.data));
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    try {
      renameSync(temporary, this.path);
    } catch (error) {
      try { unlinkSync(temporary); } catch { /* already gone */ }
      throw error;
    }
    chmodSync(this.path, 0o600);
  }

  private prune(): void {
    const now = nowSeconds();
    for (const [key, record] of Object.entries(this.data.accessTokens)) {
      if (record.expiresAt <= now) delete this.data.accessTokens[key];
    }
    for (const [key, record] of Object.entries(this.data.refreshTokens)) {
      if (record.expiresAt <= now) delete this.data.refreshTokens[key];
    }
    for (const [key, record] of Object.entries(this.data.families)) {
      if (record.expiresAt <= now) delete this.data.families[key];
    }
  }

  clientCount(): number {
    return Object.keys(this.data.clients).length;
  }

  getClient(clientId: string): RegisteredClient | undefined {
    return Object.prototype.hasOwnProperty.call(this.data.clients, clientId) ? this.data.clients[clientId] : undefined;
  }

  addClient(client: RegisteredClient): void {
    this.data.clients[client.clientId] = client;
    this.save();
  }

  /** Opens a new refresh-token family (one per authorization code grant). */
  createFamily(expiresAt: number): string {
    const id = randomToken(16);
    this.data.families[id] = { expiresAt };
    return id;
  }

  isFamilyActive(familyId: string): boolean {
    const family = this.data.families[familyId];
    return Boolean(family && !family.revokedAt && family.expiresAt > nowSeconds());
  }

  extendFamily(familyId: string, expiresAt: number): void {
    const family = this.data.families[familyId];
    if (family) family.expiresAt = Math.max(family.expiresAt, expiresAt);
  }

  /** Revokes every access and refresh token of a family. */
  revokeFamily(familyId: string): void {
    const family = this.data.families[familyId];
    if (family) family.revokedAt = nowSeconds();
    for (const [key, record] of Object.entries(this.data.accessTokens)) {
      if (record.familyId === familyId) delete this.data.accessTokens[key];
    }
    for (const record of Object.values(this.data.refreshTokens)) {
      if (record.familyId === familyId) record.usedAt ??= nowSeconds();
    }
    this.save();
  }

  /** Stores a token pair under their hashes. */
  putTokens(access: { hash: string; record: TokenRecord }, refresh: { hash: string; record: RefreshTokenRecord }): void {
    this.prune();
    this.data.accessTokens[access.hash] = access.record;
    this.data.refreshTokens[refresh.hash] = refresh.record;
    this.save();
  }

  getAccessToken(hash: string): TokenRecord | undefined {
    const record = this.data.accessTokens[hash];
    if (!record) return undefined;
    if (record.expiresAt <= nowSeconds() || !this.isFamilyActive(record.familyId)) return undefined;
    return record;
  }

  getRefreshToken(hash: string): RefreshTokenRecord | undefined {
    const record = this.data.refreshTokens[hash];
    if (!record || record.expiresAt <= nowSeconds()) return undefined;
    return record;
  }

  markRefreshTokenUsed(hash: string): void {
    const record = this.data.refreshTokens[hash];
    if (record) record.usedAt = nowSeconds();
  }
}
