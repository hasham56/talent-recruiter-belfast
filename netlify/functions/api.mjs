import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import seed from './seed.mjs';

export const config = { path: '/api/*' };

const store = () => getStore({ name: 'site', consistency: 'strong' });

// ponytail: whole list in one blob, last write wins; fine for one recruiter editing
const loadJobs = async (s) => (await s.get('jobs', { type: 'json' })) ?? seed;

const json = (body, status = 200) => Response.json(body, { status });
const clean = (v, max) => String(v ?? '').trim().slice(0, max);
const scrypt = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
const same = (a, b) => {
  const x = crypto.createHash('sha256').update(a).digest();
  const y = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(x, y);
};

// Password set via /api/password wins; until then ADMIN_PASSWORD env var is used.
async function authed(req, s) {
  const pw = req.headers.get('x-admin-password') || '';
  const saved = await s.get('auth', { type: 'json' });
  if (saved) return same(scrypt(pw, saved.salt), saved.hash);
  return !!process.env.ADMIN_PASSWORD && same(pw, process.env.ADMIN_PASSWORD);
}

const jobFrom = (b) => ({
  title: clean(b.title, 100),
  sector: clean(b.sector, 60),
  location: clean(b.location, 80),
  description: clean(b.description, 1000),
});

export default async (req) => {
  const s = store();
  const path = new URL(req.url).pathname.replace(/\/+$/, '');
  const body = async () => { try { return await req.json(); } catch { return {}; } };

  if (path === '/api/jobs' && req.method === 'GET') return json(await loadJobs(s));

  if (!(await authed(req, s))) return json({ error: 'Wrong password' }, 401);

  if (path === '/api/login' && req.method === 'POST') return json({ ok: true });

  if (path === '/api/password' && req.method === 'POST') {
    const { password } = await body();
    if (typeof password !== 'string' || password.length < 8)
      return json({ error: 'New password must be at least 8 characters' }, 400);
    const salt = crypto.randomBytes(16).toString('hex');
    await s.setJSON('auth', { salt, hash: scrypt(password, salt) });
    return json({ ok: true });
  }

  if (path === '/api/jobs' && req.method === 'POST') {
    const job = { id: crypto.randomUUID(), ...jobFrom(await body()) };
    if (!job.title) return json({ error: 'Title is required' }, 400);
    await s.setJSON('jobs', [job, ...(await loadJobs(s))]);
    return json(job, 201);
  }

  const id = path.match(/^\/api\/jobs\/([\w-]+)$/)?.[1];
  if (id && req.method === 'PUT') {
    const job = { id, ...jobFrom(await body()) };
    if (!job.title) return json({ error: 'Title is required' }, 400);
    const jobs = await loadJobs(s);
    const i = jobs.findIndex((j) => j.id === id);
    if (i < 0) return json({ error: 'Job not found' }, 404);
    jobs[i] = job;
    await s.setJSON('jobs', jobs);
    return json(job);
  }

  if (id && req.method === 'DELETE') {
    await s.setJSON('jobs', (await loadJobs(s)).filter((j) => j.id !== id));
    return new Response(null, { status: 204 });
  }

  return json({ error: 'Not found' }, 404);
};
