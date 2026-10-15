import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], imgSrc: ["'self'", 'data:'], styleSrc: ["'self'", "'unsafe-inline'"],
  formAction: ["'self'"], frameAncestors: ["'self'", 'https://*.myshopify.com']
}}}));
app.use(express.urlencoded({ extended: false, limit: '12kb' }));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SITE_TITLE = process.env.SITE_TITLE || 'You Are Heard — Art & Expression';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 14) throw new Error('Set ADMIN_PASSWORD to a strong password of at least 14 characters.');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('Set SESSION_SECRET to a random secret of at least 32 characters.');

const db = new Database(path.join(DATA_DIR, 'art-submissions.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS submissions (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, caption TEXT NOT NULL DEFAULT '', display_name TEXT NOT NULL DEFAULT 'Anonymous',
 file_name TEXT NOT NULL, mime_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL, reviewed_at TEXT
)`);

const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-7', legacyHeaders: false, message: 'Please wait before submitting another artwork.' });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });
const storage = multer.diskStorage({
 destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
 filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({ storage, limits: { fileSize: 8 * 1024 * 1024, files: 1 }, fileFilter: (_req, file, cb) => {
  const allowed = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
  cb(allowed.has(file.mimetype) ? null : new Error('Please upload a JPG, PNG, WEBP, or GIF image.'), allowed.has(file.mimetype));
}});

function escapeHtml(value = '') {
 return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);
}
function hasValidImageSignature(filePath, mimeType) {
 const b = fs.readFileSync(filePath).subarray(0, 12);
 if (mimeType === 'image/jpeg') return b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
 if (mimeType === 'image/png') return b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
 if (mimeType === 'image/gif') return b.subarray(0, 6).toString('ascii') === 'GIF87a' || b.subarray(0, 6).toString('ascii') === 'GIF89a';
 if (mimeType === 'image/webp') return b.length >= 12 && b.subarray(0, 4).toString('ascii') === 'RIFF' && b.subarray(8, 12).toString('ascii') === 'WEBP';
 return false;
}
function sign(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex'); }
function sessionCookie() {
 const payload = Buffer.from(JSON.stringify({ admin: true, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
 return `${payload}.${sign(payload)}`;
}
function isAdmin(req) {
 const raw = req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith('yah_admin='))?.slice('yah_admin='.length);
 if (!raw) return false;
 const dot = raw.lastIndexOf('.'); if (dot < 1) return false;
 const payload = raw.slice(0, dot), signature = raw.slice(dot + 1), expected = sign(payload);
 const a = Buffer.from(signature), b = Buffer.from(expected);
 if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
 try { const data = JSON.parse(Buffer.from(payload, 'base64url').toString()); return data.admin === true && data.exp > Date.now(); } catch { return false; }
}
function requireAdmin(req, res, next) { if (!isAdmin(req)) return res.redirect('/admin/login'); next(); }
function page(title, body, admin = false) {
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#19191B"><title>${escapeHtml(title)} · You Are Heard</title><link rel="stylesheet" href="/styles.css"></head><body><header class="site-header"><a class="brand" href="/" aria-label="You Are Heard home"><span class="brand-mark" aria-hidden="true">♡</span><span class="brand-copy">You Are Heard <span class="brand-tagline">LISTEN. BELIEVE. SUPPORT.</span></span></a><nav><a href="/">Gallery</a><a href="/#submit">Submit art</a>${admin ? '<a href="/admin">Review queue</a><form class="inline" method="post" action="/admin/logout"><button class="nav-button">Log out</button></form>' : ''}</nav></header><main>${body}</main><footer><p>You deserve to express yourself, at your own pace.</p><p class="small">Submissions are reviewed before publication. Please do not include identifying or private information in artwork or captions.</p></footer></body></html>`;
}
function notice(text, kind = 'notice') { return `<div class="${kind}" role="status">${escapeHtml(text)}</div>`; }

app.use(express.static(path.join(__dirname, 'public'), { index: false, maxAge: '1h' }));
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/', (req, res) => {
 const arts = db.prepare("SELECT id,title,caption,display_name,created_at FROM submissions WHERE status='approved' ORDER BY reviewed_at DESC LIMIT 100").all();
 const cards = arts.length ? `<section class="gallery">${arts.map(a => `<article class="art-card"><a class="art-image" href="/art/${encodeURIComponent(a.id)}/image" target="_blank" rel="noopener"><img loading="lazy" src="/art/${encodeURIComponent(a.id)}/image" alt="Artwork: ${escapeHtml(a.title)}"></a><div class="art-copy"><h3>${escapeHtml(a.title)}</h3>${a.caption ? `<p>${escapeHtml(a.caption)}</p>` : ''}<p class="credit">Shared by ${escapeHtml(a.display_name || 'Anonymous')}</p></div></article>`).join('')}</section>` : '<div class="empty"><h3>The gallery is just beginning</h3><p>Your creative expression could be part of this space. Share only what feels right for you.</p></div>';
 const body = `<section class="hero"><div class="hero-copy"><p class="eyebrow">A COMMUNITY GALLERY</p><h1>Your story.<br><em>Your expression.</em></h1><p class="lede">Art can hold feelings that words cannot. Share a drawing, painting, photograph or digital artwork in a space built around care and choice.</p><a class="button" href="#submit">Share your art</a></div></section><section class="section"><div class="section-heading"><p class="eyebrow">COMMUNITY GALLERY</p><h2>Expressions, shared with care</h2><p>Only artwork approved by the site owner appears here.</p></div>${cards}</section><section class="submit-panel" id="submit"><p class="eyebrow">YOUR TURN, IF YOU WISH</p><h2>Share something you have made</h2><p>You can submit anonymously. You do not need to explain your experience or share personal details. Your work will stay private until it has been reviewed.</p><form method="post" action="/submit" enctype="multipart/form-data" class="submit-form"><label for="title">Artwork title <span>(optional)</span></label><input id="title" name="title" maxlength="100" placeholder="A name for your work"><label for="displayName">Display name <span>(optional; defaults to Anonymous)</span></label><input id="displayName" name="displayName" maxlength="40" placeholder="Anonymous"><label for="caption">A few words about your work <span>(optional)</span></label><textarea id="caption" name="caption" rows="4" maxlength="500" placeholder="Share only what you feel comfortable sharing"></textarea><label for="artwork">Upload your artwork <span>(required · JPG, PNG, WEBP or GIF · max 8 MB)</span></label><input id="artwork" name="artwork" type="file" accept="image/jpeg,image/png,image/webp,image/gif" required><label class="consent"><input type="checkbox" name="permission" value="yes" required><span>I confirm this is my work or I have permission to share it. I understand it will be reviewed privately and, if approved, displayed publicly with the title, caption and display name I provided.</span></label><label class="consent"><input type="checkbox" name="privacy" value="yes" required><span>I have avoided including private information about myself or anyone else. I understand I can contact the site owner to request removal after publication.</span></label><button class="button" type="submit">Send for review</button><p class="small">Submissions are not published automatically. Please don't upload explicit, identifying, or harmful content.</p></form></section>`;
 res.send(page(SITE_TITLE, body));
});

app.post('/submit', submitLimiter, (req, res) => {
 upload.single('artwork')(req, res, err => {
  if (err) return res.status(400).send(page('Submission issue', `<section class="message-page">${notice(err.code === 'LIMIT_FILE_SIZE' ? 'Your image is larger than 8 MB. Please choose a smaller file.' : err.message || 'We could not accept that file. Please try an image in JPG, PNG, WEBP, or GIF format.', 'error')}<a class="button" href="/#submit">Back to form</a></section>`));
  if (!req.file) return res.status(400).send(page('Submission issue', `<section class="message-page">${notice('Please choose an image to upload.', 'error')}<a class="button" href="/#submit">Back to form</a></section>`));
  if (!hasValidImageSignature(req.file.path, req.file.mimetype)) { fs.rmSync(req.file.path, { force: true }); return res.status(400).send(page('Submission issue', `<section class="message-page">${notice('That file does not appear to be a valid supported image. Please choose a JPG, PNG, WEBP, or GIF.', 'error')}<a class="button" href="/#submit">Back to form</a></section>`)); }
  if (req.body.permission !== 'yes' || req.body.privacy !== 'yes') { fs.rmSync(req.file.path, { force: true }); return res.status(400).send(page('Submission issue', `<section class="message-page">${notice('Please confirm both statements before submitting.', 'error')}<a class="button" href="/#submit">Back to form</a></section>`)); }
  const id = crypto.randomUUID();
  const title = String(req.body.title || '').trim().slice(0, 100) || 'Untitled expression';
  const caption = String(req.body.caption || '').trim().slice(0, 500);
  const displayName = String(req.body.displayName || '').trim().slice(0, 40) || 'Anonymous';
  db.prepare('INSERT INTO submissions (id,title,caption,display_name,file_name,mime_type,status,created_at) VALUES (?,?,?,?,?,?,?,?)').run(id,title,caption,displayName,req.file.filename,req.file.mimetype,'pending',new Date().toISOString());
  res.status(201).send(page('Submission received', `<section class="message-page"><p class="eyebrow">THANK YOU FOR SHARING</p><h1>Your art has been received.</h1><p>Your submission is private while it is reviewed. It will only appear in the gallery if approved. Thank you for trusting this space with your expression.</p><a class="button" href="/">Return to gallery</a></section>`));
 });
});

app.get('/art/:id/image', (req, res) => {
 const art = db.prepare("SELECT file_name,mime_type FROM submissions WHERE id=? AND status='approved'").get(req.params.id);
 if (!art) return res.sendStatus(404);
 const file = path.join(UPLOAD_DIR, path.basename(art.file_name));
 if (!fs.existsSync(file)) return res.sendStatus(404);
 res.setHeader('Content-Type', art.mime_type); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Cache-Control','public, max-age=300');
 res.sendFile(file);
});

app.get('/admin/login', (_req, res) => res.send(page('Admin sign in', `<section class="admin-login"><p class="eyebrow">PRIVATE ADMIN AREA</p><h1>Review submissions</h1><p>This area is for the site owner only.</p><form method="post" action="/admin/login" class="submit-form"><label for="password">Admin password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="button" type="submit">Sign in</button></form></section>`)));
app.post('/admin/login', loginLimiter, (req, res) => {
 const supplied = Buffer.from(String(req.body.password || ''));
 const expected = Buffer.from(ADMIN_PASSWORD);
 const ok = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
 if (!ok) return res.status(401).send(page('Sign in failed', `<section class="admin-login">${notice('That password was not recognised.', 'error')}<a href="/admin/login">Try again</a></section>`));
 res.setHeader('Set-Cookie', `yah_admin=${sessionCookie()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`); res.redirect('/admin');
});
app.post('/admin/logout', requireAdmin, (_req, res) => { res.setHeader('Set-Cookie','yah_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'); res.redirect('/admin/login'); });
app.get('/admin', requireAdmin, (req, res) => {
 const filter = ['pending','approved','rejected'].includes(req.query.status) ? req.query.status : 'pending';
 const items = db.prepare('SELECT * FROM submissions WHERE status=? ORDER BY created_at DESC LIMIT 200').all(filter);
 const tabs = ['pending','approved','rejected'].map(s => `<a class="tab ${filter===s?'active':''}" href="/admin?status=${s}">${s[0].toUpperCase()+s.slice(1)} (${db.prepare('SELECT count(*) AS n FROM submissions WHERE status=?').get(s).n})</a>`).join('');
 const list = items.length ? `<div class="review-list">${items.map(a => `<article class="review-card"><img src="/admin/${encodeURIComponent(a.id)}/image" alt="Private submission preview"><div class="review-info"><p class="eyebrow">${escapeHtml(new Date(a.created_at).toLocaleString('en-GB'))}</p><h2>${escapeHtml(a.title)}</h2><p>${escapeHtml(a.caption || 'No caption provided')}</p><p class="credit">Display name: ${escapeHtml(a.display_name)}</p><p class="small">Status: ${escapeHtml(a.status)}</p><div class="actions">${a.status!=='approved'?`<form method="post" action="/admin/${encodeURIComponent(a.id)}/approve"><button class="button" type="submit">Approve</button></form>`:''}${a.status!=='rejected'?`<form method="post" action="/admin/${encodeURIComponent(a.id)}/reject"><button class="button secondary" type="submit">Reject</button></form>`:''}<form method="post" action="/admin/${encodeURIComponent(a.id)}/delete" onsubmit="return confirm('Permanently delete this submission and its uploaded image?')"><button class="text-button" type="submit">Delete permanently</button></form></div></div></article>`).join('')}</div>` : `<div class="empty"><h3>No ${filter} submissions</h3><p>There is nothing in this section right now.</p></div>`;
 res.send(page('Moderation dashboard', `<section class="admin-page"><p class="eyebrow">PRIVATE ADMIN AREA</p><h1>Submission review</h1><p>Review each submission before it can appear in the public gallery.</p><div class="tabs">${tabs}</div>${list}</section>`, true));
});
app.get('/admin/:id/image', requireAdmin, (req,res) => { const a=db.prepare('SELECT file_name,mime_type FROM submissions WHERE id=?').get(req.params.id); if(!a) return res.sendStatus(404); const file=path.join(UPLOAD_DIR,path.basename(a.file_name)); if(!fs.existsSync(file)) return res.sendStatus(404); res.setHeader('Content-Type',a.mime_type); res.setHeader('Cache-Control','no-store'); res.sendFile(file); });
for (const status of ['approve','reject']) app.post(`/admin/:id/${status}`, requireAdmin, (req,res) => { const next=status==='approve'?'approved':'rejected'; db.prepare('UPDATE submissions SET status=?, reviewed_at=? WHERE id=?').run(next,new Date().toISOString(),req.params.id); res.redirect(`/admin?status=${next}`); });
app.post('/admin/:id/delete', requireAdmin, (req,res) => { const a=db.prepare('SELECT file_name FROM submissions WHERE id=?').get(req.params.id); if(a) fs.rmSync(path.join(UPLOAD_DIR,path.basename(a.file_name)),{force:true}); db.prepare('DELETE FROM submissions WHERE id=?').run(req.params.id); res.redirect('/admin?status=pending'); });
app.use((err, _req, res, _next) => { console.error('Request failed:', err?.message || 'Unknown error'); if (res.headersSent) return; res.status(500).send(page('Something went wrong', `<section class="message-page"><h1>We couldn't complete that action.</h1><p>Please try again. Your non-AI support options remain available.</p><a class="button" href="/">Return to gallery</a></section>`)); });
app.listen(PORT, '0.0.0.0', () => console.log(`Art & Expression app listening on port ${PORT}`));
