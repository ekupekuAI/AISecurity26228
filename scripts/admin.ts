/**
 * Local operator CLI for account management.
 *
 * An air-gapped node has no mail server, so there is no "forgot password" path and no
 * self-service reset. Recovery is a physical-access operation: whoever can run this
 * command already has the database file, which is a strictly larger capability than
 * holding a console password. Every action writes to the audit ledger, so a reset is
 * visible to anyone who later verifies the chain.
 *
 * Deliberately not an HTTP endpoint. A password-reset route reachable over the network
 * is an authentication bypass waiting for one authorisation mistake.
 *
 *   npx tsx scripts/admin.ts list
 *   npx tsx scripts/admin.ts reset <username> [--password <value>]
 *   npx tsx scripts/admin.ts create <username> <role> [--password <value>]
 *   npx tsx scripts/admin.ts disable <username>
 *   npx tsx scripts/admin.ts enable <username>
 */

import 'dotenv/config';
import type { UserRole } from '../src/types.js';
import { ROLE_CAPABILITIES, createUser, listUsers } from '../server/security/accounts.js';
import { checkPasswordPolicy, generatePassword, hashPassword } from '../server/security/passwords.js';
import { appendAuditEvent } from '../server/db/audit.js';
import { closeDatabase, db } from '../server/db/index.js';
import { getKeyring } from '../server/security/keyring.js';

const ROLES = Object.keys(ROLE_CAPABILITIES) as UserRole[];

function usage(): never {
  process.stdout.write(
    '\n' +
      '  Local operator CLI - requires filesystem access to the node.\n\n' +
      '    npx tsx scripts/admin.ts list\n' +
      '    npx tsx scripts/admin.ts reset   <username> [--password <value>]\n' +
      '    npx tsx scripts/admin.ts create  <username> <role> [--password <value>]\n' +
      '    npx tsx scripts/admin.ts disable <username>\n' +
      '    npx tsx scripts/admin.ts enable  <username>\n\n' +
      `  roles: ${ROLES.join(', ')}\n\n` +
      '  Omitting --password generates one and prints it once. A supplied password is\n' +
      '  checked against the same policy the console enforces.\n\n'
  );
  process.exit(2);
}

function flag(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(`--${name}`);
  if (index < 0) return undefined;
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) usage();
  return value;
}

function findUser(username: string): { id: string; username: string; name: string; role: string } {
  const row = db
    .prepare(`SELECT id, username, name, role FROM users WHERE username = ?`)
    .get(username.trim().toLowerCase()) as { id: string; username: string; name: string; role: string } | undefined;
  if (!row) {
    process.stderr.write(`\n  No account named '${username}'. Run 'list' to see what exists.\n\n`);
    process.exit(1);
  }
  return row;
}

/** Shown once, on stdout, never through the logger: a log shipper must not capture it. */
function announce(username: string, password: string, generated: boolean): void {
  process.stdout.write(
    '\n' +
      '='.repeat(78) + '\n' +
      `  CREDENTIAL FOR ${username} - shown once, stored only as a scrypt hash\n` +
      '='.repeat(78) + '\n' +
      `  username : ${username}\n` +
      `  password : ${password}\n` +
      (generated ? '  Generated locally with crypto.randomBytes.\n' : '') +
      '  Every session for this account was destroyed. Sign in again to continue.\n' +
      '='.repeat(78) + '\n\n'
  );
}

function resolvePassword(supplied: string | undefined, context: string[]): { password: string; generated: boolean } {
  if (!supplied) return { password: generatePassword(28), generated: true };
  const verdict = checkPasswordPolicy(supplied, context);
  if (!verdict.ok) {
    process.stderr.write(`\n  Refused:\n${verdict.problems.map((p) => `    - ${p}`).join('\n')}\n\n`);
    process.exit(1);
  }
  return { password: supplied, generated: false };
}

function setPassword(userId: string, password: string): void {
  const { hash, salt, params } = hashPassword(password);
  db.prepare(
    `UPDATE users SET password_hash = ?, password_salt = ?, kdf_params = ?,
                      must_change_password = 0, failed_attempts = 0, locked_until = NULL
     WHERE id = ?`
  ).run(hash, salt, JSON.stringify(params), userId);

  // A password change must not leave a live session behind: the point of the reset is
  // usually that the old credential is suspect.
  db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
}

function main(): void {
  const argv = process.argv.slice(2);
  const command = argv[0];
  if (!command) usage();

  // Audit blocks are signed; touching the keyring first means a reset is recorded
  // with a signature rather than as an unsigned block.
  getKeyring();

  switch (command) {
    case 'list': {
      const users = listUsers();
      process.stdout.write('\n');
      for (const user of users) {
        process.stdout.write(
          `  ${user.username.padEnd(20)} ${user.role.padEnd(26)} ${user.badgeId.padEnd(14)}` +
            `${user.disabled ? ' DISABLED' : ''}${user.isDemoAccount ? ' (evaluation)' : ''}\n`
        );
      }
      process.stdout.write(`\n  ${users.length} account(s).\n\n`);
      break;
    }

    case 'reset': {
      const username = argv[1];
      if (!username) usage();
      const user = findUser(username);
      const { password, generated } = resolvePassword(flag(argv, 'password'), [
        user.username,
        user.name,
      ]);
      setPassword(user.id, password);
      appendAuditEvent({
        eventType: 'PASSWORD_RESET_LOCAL',
        assetName: user.username,
        severity: 'HIGH',
        actor: 'local-operator',
        description: `Password for '${user.username}' was reset from the local operator CLI and all sessions were revoked.`,
        metadata: { role: user.role, passwordSource: generated ? 'generated' : 'supplied' },
      });
      announce(user.username, password, generated);
      break;
    }

    case 'create': {
      const username = argv[1];
      const role = argv[2] as UserRole;
      if (!username || !role) usage();
      if (!ROLES.includes(role)) {
        process.stderr.write(`\n  Unknown role '${role}'. Valid: ${ROLES.join(', ')}\n\n`);
        process.exit(1);
      }
      const existing = db.prepare(`SELECT id FROM users WHERE username = ?`).get(username.trim().toLowerCase());
      if (existing) {
        process.stderr.write(`\n  '${username}' already exists. Use 'reset' to change its password.\n\n`);
        process.exit(1);
      }
      const { password, generated } = resolvePassword(flag(argv, 'password'), [username]);
      const created = createUser({
        username,
        email: `${username.trim().toLowerCase()}@assurance.local`,
        name: username,
        role,
        password,
      });
      appendAuditEvent({
        eventType: 'ACCOUNT_CREATED_LOCAL',
        assetName: created.username,
        severity: 'MEDIUM',
        actor: 'local-operator',
        description: `Account '${created.username}' created from the local operator CLI with role ${role}.`,
        metadata: { role, badgeId: created.badgeId, passwordSource: generated ? 'generated' : 'supplied' },
      });
      announce(created.username, password, generated);
      break;
    }

    case 'disable':
    case 'enable': {
      const username = argv[1];
      if (!username) usage();
      const user = findUser(username);
      const disabled = command === 'disable' ? 1 : 0;
      db.prepare(`UPDATE users SET disabled = ? WHERE id = ?`).run(disabled, user.id);
      if (disabled) db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(user.id);
      appendAuditEvent({
        eventType: disabled ? 'ACCOUNT_DISABLED' : 'ACCOUNT_ENABLED',
        assetName: user.username,
        severity: 'HIGH',
        actor: 'local-operator',
        description: `Account '${user.username}' was ${disabled ? 'disabled' : 're-enabled'} from the local operator CLI.`,
        metadata: { role: user.role },
      });
      process.stdout.write(`\n  '${user.username}' is now ${disabled ? 'disabled' : 'enabled'}.\n\n`);
      break;
    }

    default:
      usage();
  }

  closeDatabase();
}

main();
