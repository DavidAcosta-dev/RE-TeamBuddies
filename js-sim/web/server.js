import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const publicDir = path.resolve(__dirname);

function send(res, code, body, headers = {}) {
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', ...headers });
  res.end(body);
}

function serveStatic(req, res) {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    const p = path.join(publicDir, 'index.html');
    const body = fs.readFileSync(p);
    return send(res, 200, body, { 'content-type': 'text/html; charset=utf-8' });
  }
  if (u.pathname === '/main.js') {
    const p = path.join(publicDir, 'main.js');
    const body = fs.readFileSync(p);
    return send(res, 200, body, { 'content-type': 'application/javascript; charset=utf-8' });
  }
  if (u.pathname === '/findings') {
    const p = path.join(root, 'findings.json');
    if (!fs.existsSync(p)) return send(res, 404, 'findings.json not found');
    const body = fs.readFileSync(p);
    return send(res, 200, body, { 'content-type': 'application/json; charset=utf-8' });
  }
  // ESM imports from src
  if (u.pathname.startsWith('/src/')) {
    const p = path.join(root, u.pathname);
    if (!fs.existsSync(p)) return send(res, 404, 'not found');
    const body = fs.readFileSync(p);
    return send(res, 200, body, { 'content-type': 'application/javascript; charset=utf-8' });
  }
  return send(res, 404, 'not found');
}

const server = http.createServer((req, res) => {
  try { serveStatic(req, res); } catch (e) { console.error(e); send(res, 500, 'internal error'); }
});

const PORT = process.env.PORT || 5173;
server.listen(PORT, () => console.log(`web sim at http://localhost:${PORT}`));
