// ═══════════════════════════════════════════════════════════
//  VisaTrack Pro — Cloudflare Worker
//  Routes:
//    POST   /auth/signup              — create account
//    POST   /auth/login               — login, returns session token
//    POST   /auth/logout              — invalidate session
//    GET    /me                       — get current user + cases + documents
//    POST   /cases                    — add a case
//    DELETE /cases/:receipt           — remove a case
//    GET    /case-status/:num         — USCIS proxy (authenticated)
//    POST   /documents/upload         — upload file to R2
//    GET    /documents                — list user's documents
//    GET    /documents/:id/download   — download a file
//    DELETE /documents/:id            — delete document
//
//  Bindings required in Cloudflare dashboard:
//    DB     → D1 database  (visatrack-db)
//    BUCKET → R2 bucket    (visatrack-docs)
//
//  Environment Variables & Secrets (set in Cloudflare dashboard):
//    USCIS_CLIENT_ID     → USCIS OAuth client ID
//    USCIS_CLIENT_SECRET → USCIS OAuth client secret  [Secret]
//    GROQ_API_KEY        → Groq API key               [Secret]
// ═══════════════════════════════════════════════════════════

const USCIS_TOKEN_URL = 'https://api-int.uscis.gov/oauth/accesstoken';
const USCIS_CASE_BASE = 'https://api-int.uscis.gov/case-status';
const GROQ_URL        = 'https://api.groq.com/openai/v1/chat/completions';

// Upgraded to Llama 3.3 for text generation
const GROQ_MODEL  = 'llama-3.3-70b-versatile';

// Upgraded to Llama 4 Scout for image/document analysis
const GROQ_VISION = 'meta-llama/llama-4-scout-17b-16e-instruct';

const ALLOWED_TYPES = [
  'image/jpeg',
  'image/png'
];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

// ── CORS headers ─────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-File-Name, X-File-Type, X-Case-Num, X-Doc-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── Password hashing ──────────────────────────────────────
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data    = encoder.encode(password);
  const hash    = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session token ─────────────────────────────────────────
function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Auth middleware ───────────────────────────────────────
async function authenticate(request, db) {
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;

  const row = await db.prepare(
    `SELECT users.* FROM sessions
     JOIN users ON sessions.user_id = users.id
     WHERE sessions.token = ? AND sessions.expires_at > ?`
  ).bind(token, Date.now()).first();

  return row || null;
}

// ── USCIS OAuth token cache ───────────────────────────────
let _uscisToken = null;
// Simple memory cache for case analysis
const _analysisCache = new Map();

async function getUscisToken(clientId, clientSecret) {
  if (_uscisToken && Date.now() < _uscisToken.expiresAt) return _uscisToken.value;

  const resp = await fetch(USCIS_TOKEN_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    new URLSearchParams({
      grant_type:    'client_credentials',
      client_id:     clientId,
      client_secret: clientSecret,
    }),
  });

  const data = await resp.json();
  if (!data.access_token) throw new Error('USCIS token fetch failed');
  _uscisToken = {
    value:     data.access_token,
    expiresAt: Date.now() + (data.expires_in - 30) * 1000,
  };
  return _uscisToken.value;
}

// ── DB setup ──────────────────────────────────────────────
async function setupDb(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      role       TEXT DEFAULT 'applicant',
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS cases (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL,
      receipt_num  TEXT NOT NULL,
      visa_type    TEXT DEFAULT '',
      processing   TEXT DEFAULT 'Regular',
      api_data     TEXT DEFAULT NULL,
      api_cached_at INTEGER DEFAULT NULL,
      added_at     INTEGER DEFAULT (strftime('%s','now') * 1000),
      UNIQUE(user_id, receipt_num),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS documents (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      case_num    TEXT DEFAULT '',
      doc_type    TEXT DEFAULT 'Document',
      file_name   TEXT NOT NULL,
      file_type   TEXT NOT NULL,
      file_size   INTEGER DEFAULT 0,
      r2_key      TEXT NOT NULL,
      uploaded_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

// ── Groq AI helper ─────────────────────────────────────────
async function askGroq(prompt, groqApiKey) {
  const resp = await fetch(GROQ_URL, {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${groqApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: GROQ_MODEL,
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
      max_tokens: 1024
    }),
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || 'Groq error');
  return data.choices?.[0]?.message?.content || 'No response';
}

async function askGroqWithVision(prompt, base64Data, mimeType, groqApiKey) {
  const resp = await fetch(GROQ_URL, {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${groqApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: GROQ_VISION,
      messages: [{
        role: 'user',
        content: [
          { type: 'text', text: prompt },
          { type: 'image_url', image_url: { url: `data:${mimeType};base64,${base64Data}` } }
        ]
      }],
      temperature: 0.4,
      max_tokens: 1024
    }),
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error?.message || 'Groq Vision error');
  return data.choices?.[0]?.message?.content || 'No response';
}

// ═══════════════════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const db     = env.DB;
    const bucket = env.BUCKET;

    // ── Load secrets from environment ──────────────────────
    const GROQ_API_KEY    = env.GROQ_API_KEY;
    const CLIENT_ID       = env.USCIS_CLIENT_ID;
    const CLIENT_SECRET   = env.USCIS_CLIENT_SECRET;

    if (!GROQ_API_KEY || !CLIENT_ID || !CLIENT_SECRET) {
      return err('Server misconfiguration: missing required environment secrets.', 500);
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    try { await setupDb(db); } catch (_) {}
    // Migration: add api_data columns to existing cases tables
    try {
      await db.exec("ALTER TABLE cases ADD COLUMN api_data TEXT DEFAULT NULL");
    } catch (_) {} // column already exists — ignore
    try {
      await db.exec("ALTER TABLE cases ADD COLUMN api_cached_at INTEGER DEFAULT NULL");
    } catch (_) {}

    // ── POST /auth/signup ─────────────────────────────────
    if (path === '/auth/signup' && request.method === 'POST') {
      const { username, password, role } = await request.json();
      if (!username || !password) return err('Username and password required');
      if (username.length < 3)    return err('Username must be at least 3 characters');
      if (password.length < 6)    return err('Password must be at least 6 characters');

      const hashed = await hashPassword(password);
      try {
        const result = await db.prepare(
          'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
        ).bind(username.toLowerCase().trim(), hashed, role || 'applicant').run();

        const token     = generateToken();
        const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
        await db.prepare(
          'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
        ).bind(token, result.meta.last_row_id, expiresAt).run();

        return json({ token, username: username.toLowerCase().trim(), role: role || 'applicant' });
      } catch (e) {
        if (e.message?.includes('UNIQUE')) return err('Username already taken', 409);
        return err('Signup failed: ' + e.message, 500);
      }
    }

    // ── POST /auth/login ──────────────────────────────────
    if (path === '/auth/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password) return err('Username and password required');

      const user = await db.prepare(
        'SELECT * FROM users WHERE username = ?'
      ).bind(username.toLowerCase().trim()).first();

      if (!user) return err('Invalid username or password', 401);

      const hashed = await hashPassword(password);
      if (hashed !== user.password) return err('Invalid username or password', 401);

      const token     = generateToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      await db.prepare(
        'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
      ).bind(token, user.id, expiresAt).run();

      return json({ token, username: user.username, role: user.role });
    }

    // ── POST /auth/logout ─────────────────────────────────
    if (path === '/auth/logout' && request.method === 'POST') {
      const auth  = request.headers.get('Authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      if (token) await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
      return json({ ok: true });
    }

    // ── All routes below require auth ─────────────────────
    const user = await authenticate(request, db);

    // ── GET /me ───────────────────────────────────────────
    if (path === '/me' && request.method === 'GET') {
      if (!user) return err('Not authenticated', 401);

      const cases = await db.prepare(
        'SELECT id, receipt_num, visa_type, processing, added_at, api_data, api_cached_at FROM cases WHERE user_id = ? ORDER BY added_at DESC'
      ).bind(user.id).all();
      // Parse api_data JSON strings back to objects
      cases.results = cases.results.map(c => ({
        ...c,
        api_data: c.api_data ? JSON.parse(c.api_data) : null,
      }));

      const docs = await db.prepare(
        `SELECT id, case_num, doc_type, file_name, file_type, file_size, uploaded_at
         FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC`
      ).bind(user.id).all();

      return json({
        id:        user.id,
        username:  user.username,
        role:      user.role,
        cases:     cases.results,
        documents: docs.results,
      });
    }

    // ── POST /cases ───────────────────────────────────────
    if (path === '/cases' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { receipt_num, visa_type, processing } = await request.json();
      if (!receipt_num) return err('Receipt number required');

      try {
        await db.prepare(
          'INSERT INTO cases (user_id, receipt_num, visa_type, processing) VALUES (?, ?, ?, ?)'
        ).bind(user.id, receipt_num.toUpperCase(), visa_type || '', processing || 'Regular').run();
        return json({ ok: true });
      } catch (e) {
        if (e.message?.includes('UNIQUE')) return err('Case already added', 409);
        return err('Failed to add case: ' + e.message, 500);
      }
    }

    // ── POST /cases/:receipt/api-data ────────────────────
    // Saves the USCIS API response into the database for offline access
    if (path.match(/^\/cases\/[^/]+\/api-data$/) && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const receipt = path.split('/')[2]?.toUpperCase();
      const apiData = await request.json();
      await db.prepare(
        'UPDATE cases SET api_data = ?, api_cached_at = ? WHERE user_id = ? AND receipt_num = ?'
      ).bind(JSON.stringify(apiData), Date.now(), user.id, receipt).run();
      return json({ ok: true });
    }

    // ── DELETE /cases/:receipt ────────────────────────────
    if (path.startsWith('/cases/') && request.method === 'DELETE') {
      if (!user) return err('Not authenticated', 401);
      const receipt = path.split('/')[2]?.toUpperCase();
      await db.prepare(
        'DELETE FROM cases WHERE user_id = ? AND receipt_num = ?'
      ).bind(user.id, receipt).run();
      return json({ ok: true });
    }

    // ── GET /case-status/:num ─────────────────────────────
    if (path.startsWith('/case-status/') && request.method === 'GET') {
      if (!user) return err('Not authenticated', 401);
      const num = path.split('/')[2]?.toUpperCase();
      if (!num) return err('Receipt number required');

      try {
        const token = await getUscisToken(CLIENT_ID, CLIENT_SECRET);
        const resp  = await fetch(`${USCIS_CASE_BASE}/${num}`, {
          headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        });
        const data = await resp.json();
        return json(data);
      } catch (e) {
        return err('USCIS API error: ' + e.message, 502);
      }
    }

    // ── POST /documents/upload ────────────────────────────
    // File bytes sent as raw request body.
    // Metadata in headers:
    //   X-File-Name  — original filename
    //   X-File-Type  — MIME type
    //   X-Case-Num   — receipt number to attach to (optional)
    //   X-Doc-Type   — document category label
    if (path === '/documents/upload' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);

      const fileName = request.headers.get('X-File-Name') || 'document';
      const fileType = request.headers.get('X-File-Type') || 'application/octet-stream';
      const caseNum  = request.headers.get('X-Case-Num')  || '';
      const docType  = request.headers.get('X-Doc-Type')  || 'Document';

      if (!ALLOWED_TYPES.includes(fileType)) {
        return err('File type not allowed. Upload PDF, JPG, or PNG.');
      }

      const fileBytes = await request.arrayBuffer();
      if (fileBytes.byteLength > MAX_FILE_SIZE) {
        return err('File too large. Maximum size is 10 MB.');
      }

      // R2 key: userId/timestamp-sanitized-filename
      const safeFileName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
      const r2Key = `${user.id}/${Date.now()}-${safeFileName}`;

      await bucket.put(r2Key, fileBytes, {
        httpMetadata: { contentType: fileType },
        customMetadata: {
          userId:   String(user.id),
          caseNum,
          docType,
          fileName,
        },
      });

      const result = await db.prepare(
        `INSERT INTO documents (user_id, case_num, doc_type, file_name, file_type, file_size, r2_key)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        user.id,
        caseNum.toUpperCase(),
        docType,
        fileName,
        fileType,
        fileBytes.byteLength,
        r2Key
      ).run();

      return json({
        ok:          true,
        id:          result.meta.last_row_id,
        file_name:   fileName,
        file_type:   fileType,
        file_size:   fileBytes.byteLength,
        case_num:    caseNum.toUpperCase(),
        doc_type:    docType,
        uploaded_at: Date.now(),
      });
    }

    // ── GET /documents ────────────────────────────────────
    if (path === '/documents' && request.method === 'GET') {
      if (!user) return err('Not authenticated', 401);

      const docs = await db.prepare(
        `SELECT id, case_num, doc_type, file_name, file_type, file_size, uploaded_at
         FROM documents WHERE user_id = ? ORDER BY uploaded_at DESC`
      ).bind(user.id).all();

      return json({ documents: docs.results });
    }

    // ── GET /documents/:id/download ───────────────────────
    if (path.match(/^\/documents\/\d+\/download$/) && request.method === 'GET') {
      if (!user) return err('Not authenticated', 401);

      const docId = parseInt(path.split('/')[2]);
      const doc   = await db.prepare(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?'
      ).bind(docId, user.id).first();

      if (!doc) return err('Document not found', 404);

      const object = await bucket.get(doc.r2_key);
      if (!object) return err('File not found in storage', 404);

      return new Response(object.body, {
        headers: {
          ...CORS,
          'Content-Type':        doc.file_type,
          'Content-Disposition': `attachment; filename="${doc.file_name}"`,
        },
      });
    }

    // ── DELETE /documents/:id ─────────────────────────────
    if (path.match(/^\/documents\/\d+$/) && request.method === 'DELETE') {
      if (!user) return err('Not authenticated', 401);

      const docId = parseInt(path.split('/')[2]);
      const doc   = await db.prepare(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?'
      ).bind(docId, user.id).first();

      if (!doc) return err('Document not found', 404);

      await bucket.delete(doc.r2_key);
      await db.prepare('DELETE FROM documents WHERE id = ?').bind(docId).run();

      return json({ ok: true });
    }

    // ── POST /ai/case-analysis ───────────────────────────────
    // Body: { receipt_num, visa_type, status, description, form_type, submitted_date, modified_date }
    if (path === '/ai/case-analysis' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { receipt_num, visa_type, status, description, form_type, submitted_date, modified_date } = await request.json();

      // Create a unique key based on the receipt number and the current status
      const cacheKey = `${receipt_num}_${status}`;

      // Check if we already analyzed this exact status recently
      if (_analysisCache.has(cacheKey)) {
        return json({ analysis: _analysisCache.get(cacheKey) });
      }

      const prompt = `Act as an immigration assistant. Explain this USCIS case status in plain English.
Case: ${receipt_num} (${visa_type}, Form ${form_type})
Filed: ${submitted_date} | Updated: ${modified_date}
Status: ${status} - ${description}

Provide:
1. **Meaning**: What this status means.
2. **Next Steps**: What USCIS will likely do next.
3. **Timeline**: Realistic estimate.
4. **Action Items**: What the user must do.
5. **Risks**: Any red flags.
Be concise, practical, and avoid legal jargon. Use bold headers.`;

      try {
        const analysis = await askGroq(prompt, GROQ_API_KEY);
        // Save to cache before returning
        _analysisCache.set(cacheKey, analysis);

        // Prevent cache from growing infinitely
        if (_analysisCache.size > 100) {
          const firstKey = _analysisCache.keys().next().value;
          _analysisCache.delete(firstKey);
        }

        return json({ analysis });
      } catch(e) {
        return err('AI analysis failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/chat ─────────────────────────────────────
    // Body: { message, context: { cases, role } }
    if (path === '/ai/chat' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { message, context } = await request.json();
      if (!message) return err('Message required');

      // Only send up to 3 cases to save input tokens
      const caseSummary = (context?.cases || [])
        .slice(0, 3)
        .map(c => `- ${c.receiptNum} (${c.visaType || 'Unknown'}): ${c.apiData?.label || 'Status unknown'}`)
        .join('\n') || 'No cases tracked yet.';

      const prompt = `You are an expert US immigration attorney assistant inside VisaTrack Pro, an immigration case tracking platform. You help users understand their cases, immigration processes, and next steps.

User's tracked cases:
${caseSummary}

User role: ${context?.role || 'applicant'}

User's question: ${message}

Provide a helpful, accurate, and empathetic response. If relevant, reference their specific cases. Use plain English. Keep the response concise but complete. Format important points in **bold**.`;

      try {
        const reply = await askGroq(prompt, GROQ_API_KEY);
        return json({ reply });
      } catch(e) {
        return err('AI chat failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/document-analysis ────────────────────────
    // Body: { document_id } — fetches file from R2 and analyzes it
    if (path === '/ai/document-analysis' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { document_id } = await request.json();
      if (!document_id) return err('document_id required');

      const doc = await db.prepare(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?'
      ).bind(document_id, user.id).first();
      if (!doc) return err('Document not found', 404);

      // Only analyze standard images (Groq Vision supports JPEG and PNG natively)
      const supported = ['image/jpeg', 'image/png'];
      if (!supported.includes(doc.file_type)) {
        return err('Groq currently only supports analyzing images (JPG/PNG). PDFs are not supported.');
      }

      // Fetch file from R2
      const object = await bucket.get(doc.r2_key);
      if (!object) return err('File not found in storage', 404);

      const arrayBuf = await object.arrayBuffer();
      const bytes    = new Uint8Array(arrayBuf);

      // Safely convert the byte array to a binary string piece by piece
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }

      const base64 = btoa(binary);

      const prompt = `You are an expert US immigration attorney assistant. Please analyze this immigration document and provide:

1. **Document Type** — What kind of document is this? (e.g. I-797 Receipt Notice, RFE, Approval Notice, etc.)
2. **Key Information** — Extract the most important details: receipt numbers, dates, deadlines, names, case types
3. **What It Means** — Explain in plain English what this document means for the applicant
4. **Required Actions** — Are there any deadlines or actions the applicant must take? Be very specific about dates
5. **Important Warnings** — Any red flags, expiring dates, or critical items to be aware of

Be thorough but clear. Use **bold** for important dates and deadlines. If this is not an immigration document, say so and describe what it actually is.`;

      try {
        const analysis = await askGroqWithVision(prompt, base64, doc.file_type, GROQ_API_KEY);
        // Save analysis back to DB for caching
        await db.prepare(
          'UPDATE documents SET doc_type = doc_type WHERE id = ?'
        ).bind(document_id).run();
        return json({ analysis, file_name: doc.file_name, file_type: doc.file_type });
      } catch(e) {
        return err('Document analysis failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/hr-workforce ─────────────────────────────
    // Body: { cases: [...], company_name }
    // Returns AI workforce planning & compliance insights for HR
    if (path === '/ai/hr-workforce' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { cases, company_name } = await request.json();
      if (!cases || !cases.length) return err('cases array required');

      const cacheKey = 'hr_workforce_' + cases.map(c => c.receiptNum + '_' + (c.apiData?.label||'')).join('|');
      if (_analysisCache.has(cacheKey)) {
        return json({ analysis: _analysisCache.get(cacheKey) });
      }

      const total    = cases.length;
      const approved = cases.filter(c => /approved/i.test(c.apiData?.label || '')).length;
      const rfe      = cases.filter(c => /rfe/i.test(c.apiData?.label || '')).length;
      const pending  = total - approved;
      const visaTypes = [...new Set(cases.map(c => c.visaType || 'Unknown'))].join(', ');
      const caseSummary = cases.slice(0, 8).map(c =>
        `- ${c.receiptNum} | ${c.visaType || 'Unknown'} | ${c.processing || 'Regular'} | Status: ${c.apiData?.label || 'Tracked'} | Filed: ${c.apiData?.submittedDate || 'N/A'}`
      ).join('\n');

      const prompt = `You are an expert immigration compliance advisor for corporate HR teams.

Company: ${company_name || 'This organization'}
Portfolio Summary:
- Total sponsored employees: ${total}
- Approved: ${approved} | Pending: ${pending} | RFE Pending: ${rfe}
- Visa types in portfolio: ${visaTypes}

Individual cases:
${caseSummary}

Provide a professional HR workforce compliance report with these sections:

**1. Portfolio Health Assessment**
Rate the overall visa portfolio health (0-100%) and explain key risk factors.

**2. Immediate Action Items**
List any urgent tasks — especially RFE responses, expiring statuses, or compliance risks.

**3. Workforce Risk Analysis**
Identify employees at risk of work authorization gaps and business impact.

**4. Compliance Recommendations**
Specific steps to improve compliance posture for the next 90 days.

**5. Hiring Timeline Guidance**
Based on current case mix, advise on realistic timelines for new sponsorships.

**6. Cost & Budget Notes**
Brief notes on premium processing opportunities and expected filing costs.

Be direct, practical, and data-driven. Use **bold** for critical items and deadlines.`;

      try {
        const analysis = await askGroq(prompt, GROQ_API_KEY);
        _analysisCache.set(cacheKey, analysis);
        if (_analysisCache.size > 100) {
          _analysisCache.delete(_analysisCache.keys().next().value);
        }
        return json({ analysis });
      } catch(e) {
        return err('HR AI analysis failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/hr-forecast ──────────────────────────────
    // Body: { visa_type, filing_date, processing_type, headcount, department }
    // Returns AI-powered hiring timeline forecast
    if (path === '/ai/hr-forecast' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { visa_type, filing_date, processing_type, headcount, department, existing_cases } = await request.json();
      if (!visa_type) return err('visa_type required');

      const cacheKey = `hr_forecast_${visa_type}_${filing_date}_${processing_type}_${headcount}`;
      if (_analysisCache.has(cacheKey)) {
        return json({ forecast: _analysisCache.get(cacheKey) });
      }

      const existingSummary = (existing_cases || []).slice(0, 5).map(c =>
        `- ${c.visaType || 'Unknown'}: ${c.apiData?.label || 'In Progress'} (filed ${c.apiData?.submittedDate || 'N/A'})`
      ).join('\n') || 'No existing cases in portfolio.';

      const prompt = `You are an expert US immigration attorney and workforce planning specialist.

Forecast Request:
- Visa Type: ${visa_type}
- Target Filing Date: ${filing_date || 'ASAP'}
- Processing Type: ${processing_type || 'Regular'}
- Headcount to sponsor: ${headcount || 1}
- Department/Role: ${department || 'Not specified'}

Existing portfolio for context:
${existingSummary}

Provide a detailed hiring timeline forecast with these sections:

**1. Processing Time Estimate**
P25 (optimistic), P50 (median), P75 (conservative) timelines in days and target approval dates.

**2. Month-by-Month Action Plan**
A clear timeline from now to expected approval: what HR must do each month.

**3. Key Milestones & Deadlines**
Filing windows, USCIS processing milestones, and any cap/lottery deadlines (especially H-1B).

**4. Risk Factors**
What could delay this timeline and probability of each risk.

**5. Premium Processing Recommendation**
Should they pay for premium processing? Cost-benefit analysis.

**6. Parallel Hiring Strategy**
Should they hire a backup candidate? When to make the call.

**7. Budget Estimate**
Estimated total government filing fees + attorney fees range.

Format timelines clearly. Use **bold** for dates and critical deadlines. Be specific with numbers.`;

      try {
        const forecast = await askGroq(prompt, GROQ_API_KEY);
        _analysisCache.set(cacheKey, forecast);
        if (_analysisCache.size > 100) {
          _analysisCache.delete(_analysisCache.keys().next().value);
        }
        return json({ forecast });
      } catch(e) {
        return err('HR forecast AI failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/dso-risk-report ──────────────────────────
    // Body: { total, rfe, approved, opt, j1, visaTypes, caseSummary, institution }
    // Returns AI student compliance risk report for DSOs
    if (path === '/ai/dso-risk-report' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { total, rfe, approved, opt, j1, visaTypes, caseSummary, institution } = await request.json();

      const cacheKey = 'dso_risk_' + total + '_' + rfe + '_' + (caseSummary||'').slice(0, 80);
      if (_analysisCache.has(cacheKey)) {
        return json({ analysis: _analysisCache.get(cacheKey) });
      }

      const pending = total - approved;
      const compPct = total ? Math.round(((total - rfe) / total) * 100) : 100;

      const prompt = `You are a SEVP compliance expert and Designated School Official (DSO) advisor.

Institution: ${institution || 'This University'}
Student Portfolio Summary:
- Total international students tracked: ${total}
- Approved / Active: ${approved} | Pending: ${pending} | RFE / Issues: ${rfe}
- OPT students: ${opt} | J-1 exchange visitors: ${j1}
- Visa types in portfolio: ${visaTypes || 'F-1, J-1'}
- Estimated SEVP compliance score: ${compPct}%

Individual case records:
${caseSummary || 'No cases on file.'}

Provide a comprehensive DSO student compliance risk report with the following sections:

**1. Portfolio Health Assessment**
Assess the overall health of the international student portfolio (score 0-100%) and identify key risk factors.

**2. Immediate DSO Action Items**
List urgent tasks — especially any RFE responses, SEVIS termination risks, OPT deadline alerts, or reporting failures.

**3. SEVIS Compliance Risk Analysis**
Identify students at risk of SEVIS record issues, unauthorized employment, or enrollment violations.

**4. OPT / STEM OPT Status Review**
Summarize the OPT/STEM OPT situation and flag any authorization gaps or approaching end dates.

**5. I-20 / DS-2019 Maintenance Recommendations**
Steps to ensure all I-20s and DS-2019s are current and accurately reflect each student's program.

**6. Upcoming SEVIS Reporting Deadlines**
Key SEVIS reporting milestones and how to prepare for the next reporting cycle.

**7. Risk Mitigation Recommendations**
3-5 specific actions to improve the institution's SEVP compliance posture in the next 60 days.

Be direct and practical. Use **bold** for deadlines and critical items. Write from the perspective of advising the DSO, not the student.`;

      try {
        const analysis = await askGroq(prompt, GROQ_API_KEY);
        _analysisCache.set(cacheKey, analysis);
        if (_analysisCache.size > 100) {
          _analysisCache.delete(_analysisCache.keys().next().value);
        }
        return json({ analysis });
      } catch(e) {
        return err('DSO AI risk report failed: ' + e.message, 502);
      }
    }

    // ── POST /ai/dso-sevp-audit ───────────────────────────
    // Body: { cases: [...], caseSummary, institution }
    // Returns AI-powered SEVP compliance audit for the institution
    if (path === '/ai/dso-sevp-audit' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { cases, caseSummary, institution } = await request.json();
      if (!cases || !cases.length) return err('cases array required');

      const cacheKey = 'dso_sevp_' + cases.map(c => c.receiptNum + '_' + (c.apiData?.label||'')).join('|');
      if (_analysisCache.has(cacheKey)) {
        return json({ audit: _analysisCache.get(cacheKey) });
      }

      const total    = cases.length;
      const rfe      = cases.filter(c => /rfe/i.test(c.apiData?.label || '')).length;
      const approved = cases.filter(c => /approved/i.test(c.apiData?.label || '')).length;
      const f1Cases  = cases.filter(c => /f-1|f1/i.test(c.visaType || '')).length;
      const j1Cases  = cases.filter(c => /j-1|j1/i.test(c.visaType || '')).length;
      const optCases = cases.filter(c => /opt/i.test(c.visaType || '')).length;
      const stemCases= cases.filter(c => /stem/i.test(c.visaType || '')).length;

      const prompt = `You are a senior SEVP compliance auditor conducting a formal institutional review.

Institution: ${institution || 'This University'}
SEVIS Record Inventory:
- Total records: ${total}
- F-1 students: ${f1Cases} | J-1 exchange visitors: ${j1Cases}
- OPT authorizations: ${optCases} | STEM OPT extensions: ${stemCases}
- Approved / Active: ${approved} | RFE / Issues: ${rfe}

Detailed SEVIS records:
${caseSummary}

Conduct a formal SEVP compliance audit with these sections:

**SEVP COMPLIANCE AUDIT REPORT**
Institution: ${institution || 'This University'}
Audit Date: ${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}

**Section 1 — Enrollment Compliance**
Review full-time enrollment requirements for all F-1 students. Identify any who may be at risk of reduced course load violations.

**Section 2 — OPT Authorization Review**
Audit all OPT and STEM OPT cases for timeline compliance, employer reporting requirements, and upcoming expiration dates.

**Section 3 — J-1 Program Compliance**
Review DS-2019 status, J-1 program duration, and any two-year home residency requirement risks.

**Section 4 — SEVIS Reporting Compliance**
Assess whether all required SEVIS updates — enrollment, address changes, employment authorization — are being made within regulatory deadlines.

**Section 5 — I-20 / DS-2019 Document Integrity**
Review the accuracy and currency of all travel documents. Flag any that may need reissuance or extension.

**Section 6 — RFE & Pending Case Risk**
Analyze the ${rfe} RFE case(s) and other pending matters for SEVP impact. Provide a response strategy.

**Section 7 — Audit Findings & Score**
Give an overall compliance score (0-100), list findings by severity (Critical / Moderate / Advisory), and provide a remediation roadmap.

**Section 8 — Recommended DSO Actions (Next 30 Days)**
Prioritized action list for the DSO to bring the institution into full compliance.

Use **bold** for all deadlines, compliance scores, and critical findings. Write in formal audit language.`;

      try {
        const audit = await askGroq(prompt, GROQ_API_KEY);
        _analysisCache.set(cacheKey, audit);
        if (_analysisCache.size > 100) {
          _analysisCache.delete(_analysisCache.keys().next().value);
        }
        return json({ audit });
      } catch(e) {
        return err('SEVP audit AI failed: ' + e.message, 502);
      }
    }

    // ══════════════════════════════════════════════════════════
    // SELF-SERVICE ACCOUNT ROUTES
    // ══════════════════════════════════════════════════════════

    // ── POST /account/username ────────────────────────────
    if (path === '/account/username' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { new_username, current_password } = await request.json();
      if (!new_username || new_username.length < 3) return err('Username must be at least 3 characters');
      if (!current_password) return err('Current password required');
      if (!/^[a-z0-9_.-]+$/.test(new_username)) return err('Username can only contain lowercase letters, numbers, underscores, dots, and hyphens');

      // Verify current password
      const currentHash = await hashPassword(current_password);
      if (currentHash !== user.password_hash) return err('Incorrect current password', 401);

      // Check if new username is already taken
      const existing = await db.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
        .bind(new_username, user.id).first();
      if (existing) return err('Username already taken');

      await db.prepare('UPDATE users SET username = ? WHERE id = ?')
        .bind(new_username, user.id).run();

      // Invalidate all sessions for this user so they re-login with new username
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();

      return json({ ok: true, message: 'Username updated. Please log in again.' });
    }

    // ── POST /account/password ────────────────────────────
    if (path === '/account/password' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { current_password, new_password } = await request.json();
      if (!current_password) return err('Current password required');
      if (!new_password || new_password.length < 6) return err('New password must be at least 6 characters');

      // Verify current password
      const currentHash = await hashPassword(current_password);
      if (currentHash !== user.password_hash) return err('Incorrect current password', 401);

      const newHash = await hashPassword(new_password);
      await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .bind(newHash, user.id).run();

      return json({ ok: true, message: 'Password updated successfully.' });
    }

    // ── POST /account/delete ──────────────────────────────
    if (path === '/account/delete' && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      const { confirm_username } = await request.json();
      if (confirm_username !== user.username) return err('Username confirmation does not match');

      // Delete all user documents from R2
      const docs = await db.prepare('SELECT r2_key FROM documents WHERE user_id = ?')
        .bind(user.id).all();
      for (const doc of (docs.results || [])) {
        await bucket.delete(doc.r2_key).catch(() => {});
      }

      // Delete DB records in order
      await db.prepare('DELETE FROM documents WHERE user_id = ?').bind(user.id).run();
      await db.prepare('DELETE FROM cases WHERE user_id = ?').bind(user.id).run();
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
      await db.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();

      return json({ ok: true });
    }

    // ══════════════════════════════════════════════════════════
    // ADMIN ROUTES  (role = 'admin' required for all)
    // ══════════════════════════════════════════════════════════

    // ── GET /admin/users ──────────────────────────────────
    if (path === '/admin/users' && request.method === 'GET') {
      if (!user) return err('Not authenticated', 401);
      if (user.role !== 'admin') return err('Admin access required', 403);

      const result = await db.prepare(
        'SELECT id, username, role, created_at FROM users ORDER BY created_at DESC'
      ).all();

      return json({ users: result.results || [] });
    }

    // ── PATCH /admin/users/:id ────────────────────────────
    if (path.startsWith('/admin/users/') && !path.includes('reset-password') && request.method === 'PATCH') {
      if (!user) return err('Not authenticated', 401);
      if (user.role !== 'admin') return err('Admin access required', 403);

      const targetId = parseInt(path.split('/')[3]);
      if (!targetId) return err('Invalid user ID');

      const { username: newUsername, role: newRole } = await request.json();
      const validRoles = ['applicant', 'attorney', 'hr', 'dso', 'admin'];

      if (!newUsername || newUsername.length < 3) return err('Username must be at least 3 characters');
      if (!validRoles.includes(newRole)) return err('Invalid role');
      if (!/^[a-z0-9_.-]+$/.test(newUsername)) return err('Invalid username format');

      // Check username taken by someone else
      const existing = await db.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
        .bind(newUsername, targetId).first();
      if (existing) return err('Username already taken');

      const target = await db.prepare('SELECT id FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return err('User not found', 404);

      await db.prepare('UPDATE users SET username = ?, role = ? WHERE id = ?')
        .bind(newUsername, newRole, targetId).run();

      // Invalidate the target user's sessions on any change
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId).run();

      return json({ ok: true });
    }

    // ── POST /admin/users/:id/reset-password ─────────────
    if (path.includes('/reset-password') && request.method === 'POST') {
      if (!user) return err('Not authenticated', 401);
      if (user.role !== 'admin') return err('Admin access required', 403);

      const targetId = parseInt(path.split('/')[3]);
      if (!targetId) return err('Invalid user ID');

      const { new_password } = await request.json();
      if (!new_password || new_password.length < 6) return err('Password must be at least 6 characters');

      const target = await db.prepare('SELECT id FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return err('User not found', 404);

      const newHash = await hashPassword(new_password);
      await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .bind(newHash, targetId).run();

      // Invalidate all sessions so user must re-login with new password
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId).run();

      return json({ ok: true });
    }

    // ── DELETE /admin/users/:id ───────────────────────────
    if (path.startsWith('/admin/users/') && !path.includes('reset-password') && request.method === 'DELETE') {
      if (!user) return err('Not authenticated', 401);
      if (user.role !== 'admin') return err('Admin access required', 403);

      const targetId = parseInt(path.split('/')[3]);
      if (!targetId) return err('Invalid user ID');
      if (targetId === user.id) return err('Cannot delete your own admin account');

      const target = await db.prepare('SELECT id FROM users WHERE id = ?').bind(targetId).first();
      if (!target) return err('User not found', 404);

      // Delete all user documents from R2
      const docs = await db.prepare('SELECT r2_key FROM documents WHERE user_id = ?')
        .bind(targetId).all();
      for (const doc of (docs.results || [])) {
        await bucket.delete(doc.r2_key).catch(() => {});
      }

      await db.prepare('DELETE FROM documents WHERE user_id = ?').bind(targetId).run();
      await db.prepare('DELETE FROM cases WHERE user_id = ?').bind(targetId).run();
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId).run();
      await db.prepare('DELETE FROM users WHERE id = ?').bind(targetId).run();

      return json({ ok: true });
    }

    return err('Not found', 404);
  },
};
