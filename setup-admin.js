'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const envPath = path.join(__dirname, '.env');

if (fs.existsSync(envPath)) {
  console.error('.env already exists. It was left unchanged. Review it locally before restarting the server.');
  process.exit(1);
}

const password = crypto.randomBytes(24).toString('base64url');
const dataKey = crypto.randomBytes(32).toString('base64');
const config = [
  'PORT=3000',
  'HOST=127.0.0.1',
  'ADMIN_USERNAME=admin',
  `ADMIN_PASSWORD=${password}`,
  `APPLICATION_DATA_KEY=${dataKey}`,
  'APPLICATION_DATA_DIR=.private-data',
  ''
].join('\n');

fs.writeFileSync(envPath, config, { flag: 'wx', mode: 0o600 });
console.log('Private inbox credentials and encryption key were generated in the ignored .env file.');
console.log('Open .env locally to retrieve the one-time generated admin password; do not share or commit it.');
