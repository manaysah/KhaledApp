import { ADMIN_EMAIL, isAdminEmail, normalizeEmail } from './email.js';

function nowIso() {
  return new Date().toISOString();
}

/** Ensure site admin is always on the allowlist. */
export async function ensureAdminSeeded(db) {
  const existing = await db
    .prepare('SELECT email, role FROM allowlist WHERE email = ?')
    .bind(ADMIN_EMAIL)
    .first();

  if (!existing) {
    await db
      .prepare(
        `INSERT INTO allowlist (email, role, created_at, created_by)
         VALUES (?, 'admin', ?, 'bootstrap')`,
      )
      .bind(ADMIN_EMAIL, nowIso())
      .run();
    return;
  }

  if (existing.role !== 'admin') {
    await db
      .prepare(`UPDATE allowlist SET role = 'admin' WHERE email = ?`)
      .bind(ADMIN_EMAIL)
      .run();
  }
}

export async function getAllowlistEntry(db, email) {
  const normalized = normalizeEmail(email);
  await ensureAdminSeeded(db);
  if (isAdminEmail(normalized)) {
    return { email: ADMIN_EMAIL, role: 'admin' };
  }
  return db
    .prepare('SELECT email, role, created_at, created_by FROM allowlist WHERE email = ?')
    .bind(normalized)
    .first();
}

export async function listAllowlist(db) {
  await ensureAdminSeeded(db);
  const { results } = await db
    .prepare(
      `SELECT email, role, created_at, created_by FROM allowlist ORDER BY role DESC, email ASC`,
    )
    .all();
  return results || [];
}

export async function addAllowlist(db, email, createdBy) {
  const normalized = normalizeEmail(email);
  const role = isAdminEmail(normalized) ? 'admin' : 'member';
  await db
    .prepare(
      `INSERT INTO allowlist (email, role, created_at, created_by)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET
         role = excluded.role`,
    )
    .bind(normalized, role, nowIso(), createdBy)
    .run();
  return getAllowlistEntry(db, normalized);
}

export async function removeAllowlist(db, email) {
  const normalized = normalizeEmail(email);
  if (isAdminEmail(normalized)) {
    return { ok: false, error: 'Cannot remove the site admin.' };
  }
  await db.prepare('DELETE FROM allowlist WHERE email = ?').bind(normalized).run();
  // Keep user row for audit but clear TOTP so a re-add must re-enroll
  await db
    .prepare(
      `UPDATE users SET totp_secret_enc = NULL, totp_confirmed = 0, updated_at = ? WHERE email = ?`,
    )
    .bind(nowIso(), normalized)
    .run();
  return { ok: true };
}

export async function getUser(db, email) {
  return db
    .prepare(
      `SELECT email, totp_secret_enc, totp_confirmed, created_at, updated_at FROM users WHERE email = ?`,
    )
    .bind(normalizeEmail(email))
    .first();
}

export async function upsertUserPendingTotp(db, email, secretEnc) {
  const normalized = normalizeEmail(email);
  const ts = nowIso();
  await db
    .prepare(
      `INSERT INTO users (email, totp_secret_enc, totp_confirmed, created_at, updated_at)
       VALUES (?, ?, 0, ?, ?)
       ON CONFLICT(email) DO UPDATE SET
         totp_secret_enc = excluded.totp_secret_enc,
         totp_confirmed = 0,
         updated_at = excluded.updated_at`,
    )
    .bind(normalized, secretEnc, ts, ts)
    .run();
}

export async function confirmUserTotp(db, email) {
  await db
    .prepare(`UPDATE users SET totp_confirmed = 1, updated_at = ? WHERE email = ?`)
    .bind(nowIso(), normalizeEmail(email))
    .run();
}
