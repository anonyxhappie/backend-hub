import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const TEXT_EXTS = ['.js', '.mjs', '.ts', '.sql', '.json', '.md', '.html', '.css', '.yml', '.toml'];

async function walk(dir) {
  const out = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === '.local-hub') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await walk(full)));
    } else if (TEXT_EXTS.some((ext) => e.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

async function main() {
  const files = await walk(ROOT);
  const errors = [];

  for (const file of files) {
    const content = await fs.readFile(file, 'utf8');
    if (content.includes('\r\n')) {
      errors.push(`${path.relative(ROOT, file)}: contains CRLF line endings`);
    }
    if (file.endsWith('.json')) {
      try {
        JSON.parse(content);
      } catch (err) {
        errors.push(`${path.relative(ROOT, file)}: invalid JSON (${err.message})`);
      }
    }
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (/[ \t]+$/.test(lines[i])) {
        errors.push(`${path.relative(ROOT, file)}:${i + 1}: trailing whitespace`);
        break;
      }
    }
  }

  if (errors.length > 0) {
    console.error('Format check failed:\n' + errors.join('\n'));
    process.exit(1);
  }
  console.log(`Format check passed across ${files.length} files.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
