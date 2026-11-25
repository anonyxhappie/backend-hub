import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export function validateStorageObjectPath(objectPath) {
  if (typeof objectPath !== 'string' || objectPath.length === 0 || objectPath.length > 320) {
    throw new Error('INVALID_PATH: object path must be a non-empty string');
  }
  const segments = objectPath.split('/');
  if (segments.length < 3) {
    throw new Error('INVALID_PATH: object path must contain app/owner/path segments');
  }
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..' || !/^[a-zA-Z0-9._-]+$/.test(seg)) {
      throw new Error('INVALID_PATH: illegal path segment');
    }
  }
}

export class PrivateStorageStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
  }

  async init() {
    await fs.mkdir(this.rootDir, { recursive: true });
  }

  resolveSafeObjectPath(bucketId, objectPath) {
    if (
      typeof bucketId !== 'string' ||
      !/^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$/.test(bucketId) ||
      typeof objectPath !== 'string'
    ) {
      throw new Error('INVALID_STORAGE_PATH');
    }

    validateStorageObjectPath(objectPath);
    const segments = objectPath.split('/');
    const resolved = path.resolve(this.rootDir, bucketId, ...segments);
    const bucketRoot = path.resolve(this.rootDir, bucketId);
    if (!resolved.startsWith(bucketRoot + path.sep)) {
      throw new Error('PATH_TRAVERSAL_BLOCKED');
    }
    return resolved;
  }

  async putObject(bucketId, objectPath, buffer) {
    const target = this.resolveSafeObjectPath(bucketId, objectPath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, buffer, { flag: 'w' });
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    return { sizeBytes: buffer.length, bytes: buffer.length, sha256, target };
  }

  async readObject(bucketId, objectPath) {
    const target = this.resolveSafeObjectPath(bucketId, objectPath);
    return fs.readFile(target);
  }

  async getObject(bucketId, objectPath) {
    return this.readObject(bucketId, objectPath);
  }

  async deleteObject(bucketId, objectPath) {
    const target = this.resolveSafeObjectPath(bucketId, objectPath);
    await fs.rm(target, { force: true });
  }

  async exists(bucketId, objectPath) {
    const target = this.resolveSafeObjectPath(bucketId, objectPath);
    try {
      await fs.access(target);
      return true;
    } catch {
      return false;
    }
  }
}

export { PrivateStorageStore as LocalPrivateStorageStore };
