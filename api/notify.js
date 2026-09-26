// Sends a student their grade and feedback by email.
// Only the LMS admin can call it: the request must carry the admin's Firebase sign-in token.
//
// Two ways to send (set ONE in Vercel > Settings > Environment Variables):
//   Option A, Google Apps Script (no App Password needed):
//     APPS_SCRIPT_URL     the web app URL of the "FTH LMS mailer" script (see apps-script/Code.gs)
//     APPS_SCRIPT_SECRET  the same secret you saved in the script's properties
//   Option B, Gmail SMTP:
//     SMTP_USER   the Gmail / Google Workspace address that sends the mail
//     SMTP_PASS   an App Password for that account
// Other variables:
//   ADMIN_EMAILS  optional, comma-separated; defaults to firsttechhub1@gmail.com
//   LMS_URL     optional, e.g. https://lms.firsttechhub.com (defaults to this site)
//   SMTP_HOST / SMTP_PORT  optional, default smtp.gmail.com / 465
//   FIREBASE_PROJECT_ID  already set for /api/config (used to check the admin's sign-in)

import crypto from 'node:crypto';

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'firsttechhub1@gmail.com').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Checks the admin's Firebase sign-in token directly against Google's public signing keys.
// (It doesn't use the web API key, which is often restricted to your website and would be refused here.)
let certCache = { at: 0, certs: null };
async function googleCerts() {
  if (certCache.certs && Date.now() - certCache.at < 60 * 60 * 1000) return certCache.certs;
  const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  if (!r.ok) throw new Error('could not fetch Google signing keys');
  certCache = { at: Date.now(), certs: await r.json() };
  return certCache.certs;
}
const fromB64 = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

async function verifyIdToken(token) {
  const [h, p, sig] = String(token).split('.');
  if (!h || !p || !sig) throw new Error('missing or malformed sign-in token');
  const header = JSON.parse(fromB64(h).toString('utf8'));
  const payload = JSON.parse(fromB64(p).toString('utf8'));
  if (header.alg !== 'RS256') throw new Error('unexpected token type');
  const certs = await googleCerts();
  let pem = certs[header.kid];
  if (!pem) { certCache.at = 0; pem = (await googleCerts())[header.kid]; }
  if (!pem) throw new Error('token signed with an unknown key');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey(pem), fromB64(sig));
  if (!ok) throw new Error('token signature is invalid');
  const projectId = process.env.FIREBASE_PROJECT_ID;
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID is not set in Vercel');
  if (payload.aud !== projectId || payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error('token belongs to a different Firebase project; check FIREBASE_PROJECT_ID');
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - 60) throw new Error('sign-in has expired; refresh the page and try again');
  return payload;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });

  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  let email;
  try { email = String((await verifyIdToken(token)).email || '').toLowerCase(); }
  catch (err) { console.error('token check failed', err); return res.status(401).json({ error: `your admin sign-in couldn’t be checked (${err.message}).` }); }
  if (!ADMIN_EMAILS.includes(email)) {
    return res.status(403).json({ error: `${email || 'this account'} isn’t on the admin list. If you set ADMIN_EMAILS in Vercel, make sure it includes this address.` });
  }

  const useScript = !!process.env.APPS_SCRIPT_URL;
  if (!useScript && (!process.env.SMTP_USER || !process.env.SMTP_PASS)) {
    return res.status(500).json({ error: 'email isn’t set up yet. Add APPS_SCRIPT_URL and APPS_SCRIPT_SECRET in Vercel (see SETUP.md).' });
  }

  let body = req.body || {};
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  const { to, studentName, courseTitle, assessmentTitle, assessmentId, grade, points, feedback } = body;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(to || ''))) return res.status(400).json({ error: 'the student has no valid email address.' });

  const base = (process.env.LMS_URL || `https://${req.headers.host}`).replace(/\/$/, '');
  const link = `${base}/#/assessment/${encodeURIComponent(String(assessmentId || ''))}`;
  const first = String(studentName || '').trim().split(/\s+/)[0] || 'there';
  const hasGrade = grade !== null && grade !== undefined && grade !== '';
  const gradeText = hasGrade ? `${grade}/${points}` : 'Returned';

  const html = `<!doctype html><html><body style="margin:0;background:#f4f2ef;font-family:Arial,Helvetica,sans-serif;color:#20150d">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f2ef;padding:24px 12px"><tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:18px;overflow:hidden">
      <tr><td style="background:#1c120b;padding:22px 28px"><img src="${base}/IMG/fth-logo-light.png" alt="First Tech Hub Solutions" width="170" style="display:block;border:0"></td></tr>
      <tr><td style="padding:28px">
        <p style="margin:0 0 6px;font-size:14px;color:#74685f">${esc(courseTitle)}</p>
        <h1 style="margin:0 0 18px;font-size:22px;line-height:1.3">Hi ${esc(first)}, your assessment has been graded</h1>
        <p style="margin:0 0 18px;font-size:15px;line-height:1.6"><strong>${esc(assessmentTitle)}</strong></p>
        <table role="presentation" cellpadding="0" cellspacing="0" style="background:#1c120b;border-radius:14px;margin:0 0 18px"><tr>
          <td style="padding:14px 22px;font-size:28px;font-weight:bold;color:#e2a23b">${esc(gradeText)}</td>
        </tr></table>
        ${feedback ? `<p style="margin:0 0 6px;font-size:14px;font-weight:bold">Feedback from your tutor</p>
        <div style="margin:0 0 22px;padding:14px 16px;background:#f4f2ef;border-radius:12px;font-size:15px;line-height:1.6;white-space:pre-wrap">${esc(feedback)}</div>` : ''}
        <a href="${esc(link)}" style="display:inline-block;background:#5c3214;color:#ffffff;text-decoration:none;font-weight:bold;padding:13px 22px;border-radius:12px;font-size:15px">View your assessment</a>
        <p style="margin:22px 0 0;font-size:13px;color:#74685f;line-height:1.5">Questions about your grade? Reply in the private comments on the assessment page.</p>
      </td></tr>
      <tr><td style="padding:16px 28px;background:#f9f7f5;font-size:12px;color:#74685f">First Tech Hub Solutions. Empower. Learn. Grow.</td></tr>
    </table>
  </td></tr></table></body></html>`;

  const text = `Hi ${first},\n\nYour assessment "${assessmentTitle}" in ${courseTitle} has been graded.\n\nGrade: ${gradeText}\n${feedback ? `\nFeedback from your tutor:\n${feedback}\n` : ''}\nView it here: ${link}\n\nFirst Tech Hub Solutions`;

  const subject = `Graded: ${assessmentTitle}`;
  try {
    if (useScript) {
      const r = await fetch(process.env.APPS_SCRIPT_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'follow',
        body: JSON.stringify({ secret: process.env.APPS_SCRIPT_SECRET || '', to, subject, html, text, replyTo: process.env.REPLY_TO || '' }),
      });
      const j = await r.json().catch(() => ({}));
      if (!j.ok) throw new Error(j.error || `Apps Script answered ${r.status}`);
    } else {
      const nodemailer = (await import('nodemailer')).default;
      const port = Number(process.env.SMTP_PORT || 465);
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com', port, secure: port === 465,
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      });
      await transporter.sendMail({
        from: `"First Tech Hub Solutions" <${process.env.SMTP_USER}>`,
        to, replyTo: process.env.REPLY_TO || process.env.SMTP_USER, subject, text, html,
      });
    }
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('notify failed', err);
    return res.status(502).json({ error: useScript
      ? `the Apps Script mailer refused it (${String(err.message || err).slice(0, 120)}). Check APPS_SCRIPT_URL and APPS_SCRIPT_SECRET.`
      : 'the mail server refused it. Check SMTP_USER and SMTP_PASS in Vercel.' });
  }
}
