/**
 * Team-account seeder.
 *
 * Creates the operator accounts listed in a JSON file (or the AIA_SEED_USERS env var),
 * hashing each password through the app's real scrypt KDF -- no plaintext is ever stored,
 * and none lives in the codebase. Safe to run repeatedly: an account that already exists is
 * skipped, never overwritten. Importing the accounts module also runs the schema migration,
 * so this doubles as a way to bring an existing database up to the current version.
 *
 *   npm run seed:users                 # reads ./seed-users.json
 *   npm run seed:users -- team.json    # reads a specific file
 *
 * The same accounts are created automatically at server boot when AIA_SEED_USERS_FILE or
 * AIA_SEED_USERS is set, so a fresh node (e.g. the cloud VM) reproduces them without this
 * script.
 */
import 'dotenv/config';

const fileArg = process.argv[2];
if (fileArg) {
  process.env.AIA_SEED_USERS_FILE = fileArg;
} else if (!process.env.AIA_SEED_USERS && !process.env.AIA_SEED_USERS_FILE) {
  process.env.AIA_SEED_USERS_FILE = 'seed-users.json';
}

const { seedConfiguredAccounts, listUsers } = await import('../server/security/accounts.js');
const { closeDatabase } = await import('../server/db/index.js');

const created = seedConfiguredAccounts();

if (created.length === 0) {
  console.log('No new accounts created (all configured users already exist, or none configured).');
} else {
  console.log(`Created ${created.length} account(s): ${created.join(', ')}`);
}

console.log('\nAccounts on this node:');
for (const user of listUsers()) {
  console.log(`  - ${user.username.padEnd(16)} ${user.role}${user.disabled ? '  (disabled)' : ''}`);
}

closeDatabase();
process.exit(0);
