// server.js
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const readline = require('readline');
const path = require('path');
const crypto = require('crypto');
const iconv = require('iconv-lite');

const upload = multer({ dest: 'uploads/' });
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use(express.urlencoded({ extended: true }));

/**
 * Flexible timestamp detection:
 * - bracketed or unbracketed
 * - separators: '-' or '_'
 * - time separators: ':' or '_'
 * - optional fractional seconds (',mmm' or '.mmm')
 *
 * Examples matched:
 *  [2025-09-12 00:30:30]
 *  [2025-09-12 00:30:30,123]
 *  [2025_09_08_17_37_30]
 *  2025-07-26 23:45:20,391
 */
const timestampStartRe = /^\s*\[?\d{4}[-_]\d{2}[-_]\d{2}[_\s:-]\d{2}[:_]\d{2}[:_]\d{2}(?:[.,]\d{1,6})?\]?\s*/;

// level token detection anywhere on the line (case-insensitive)
const levelFindRe = /\b(INFO|DEBUG|ERROR|WARN|TRACE)\b/i;

// heuristic keywords -> treat as ERROR if no explicit level
const heuristicErrorRe = /\b(error|exception|failed|fatal)\b/i;

/**
 * detectEncoding(filePath)
 */
function detectEncoding(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.allocUnsafe(4);
    const bytes = fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);

    if (bytes >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) return 'utf8bom';
    if (bytes >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) return 'utf16le';
    if (bytes >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) return 'utf16be';
    return 'utf8';
  } catch (err) {
    return 'utf8';
  }
}

/**
 * processAndCategorize(filePath)
 */
async function processAndCategorize(filePath) {
  const categories = { INFO: [], DEBUG: [], ERROR: [], WARN: [], TRACE: [], OTHER: [] };

  const encoding = detectEncoding(filePath);
  let input = fs.createReadStream(filePath);
  input = input.pipe(iconv.decodeStream(encoding === 'utf16le' || encoding === 'utf16be' ? encoding : 'utf8'));

  const rl = readline.createInterface({ input, crlfDelay: Infinity });

  let current = null;
  let idx = 0;

  for await (const rawLine of rl) {
    const line = rawLine.replace(/\r?\n$/, '');

    if (timestampStartRe.test(line)) {
      // new entry -> flush previous
      if (current) {
        const canonical = normalizeLevel(current.level);
        categories[canonical].push({ raw: current.raw, level: canonical, index: current.index });
      }

      // detect explicit level token
      let level = null;
      const lm = line.match(levelFindRe);
      if (lm) level = lm[1].toUpperCase();
      else if (heuristicErrorRe.test(line)) level = 'ERROR';

      current = { raw: line, level, index: idx++ };
    } else {
      // continuation line
      if (current) {
        current.raw += '\n' + line;
      } else {
        // standalone
        let level = null;
        const lm = line.match(levelFindRe);
        if (lm) level = lm[1].toUpperCase();
        else if (heuristicErrorRe.test(line)) level = 'ERROR';
        current = { raw: line, level, index: idx++ };
      }
    }
  }

  // flush last
  if (current) {
    const canonical = normalizeLevel(current.level);
    categories[canonical].push({ raw: current.raw, level: canonical, index: current.index });
  }

  const all = Object.values(categories).flat().sort((a, b) => a.index - b.index);
  return { categories, all, total: idx };
}

// helper to normalize levels
function normalizeLevel(lvl) {
  if (!lvl) return 'OTHER';
  const upper = lvl.toUpperCase();
  if (['INFO','DEBUG','ERROR','WARN','TRACE'].includes(upper)) return upper;
  if (upper === 'WARNING') return 'WARN';   // alias
  return 'OTHER';
}


// --- routes (same as before) ---
app.get('/', (req, res) => res.render('index'));

app.post('/upload', upload.single('logfile'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).send('No file uploaded');

  const jobId = crypto.randomBytes(8).toString('hex');
  try {
    const { categories, all, total } = await processAndCategorize(file.path);

    global.JOBS = global.JOBS || {};
    global.JOBS[jobId] = {
      createdAt: new Date().toISOString(),
      categories,
      all,
      total
    };
  } catch (err) {
    console.error('parse error', err);
    return res.status(500).send('Error processing file: ' + err.message);
  } finally {
    fs.unlink(file.path, () => {});
  }

  res.redirect(`/results/${jobId}`);
});

app.get('/results/:jobId', (req, res) => {
  const job = global.JOBS && global.JOBS[req.params.jobId];
  if (!job) return res.status(404).send('Job not found');

  const level = (req.query.level || 'ALL').toUpperCase();
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const perPage = Math.min(1000, Math.max(10, parseInt(req.query.perPage || '200', 10)));

  const source = (level === 'ALL') ? job.all : (job.categories[level] || []);
  const totalMatches = source.length;
  const totalPages = Math.max(1, Math.ceil(totalMatches / perPage));
  const start = (page - 1) * perPage;
  const pageItems = source.slice(start, start + perPage);

  res.render('results_simple', {
    jobId: req.params.jobId,
    createdAt: job.createdAt,
    level,
    page,
    perPage,
    totalMatches,
    totalPages,
    pageItems,
    totalLines: job.total
  });
});

app.get('/api/job/:jobId/lines', (req, res) => {
  const job = global.JOBS && global.JOBS[req.params.jobId];
  if (!job) return res.status(404).json({ error: 'not found' });

  const level = (req.query.level || 'ALL').toUpperCase();
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const perPage = Math.min(1000, Math.max(10, parseInt(req.query.perPage || '200', 10)));
console.log("Available categories:", Object.keys(job.categories));

  // choose source based on level
  const source = (level === 'ALL') ? job.all : (job.categories[level] || []);
  const rawText = (req.query.text || '').trim();

  console.log('Incoming query:', req.query);
  console.log('Source length:', source.length);
  if (source.length > 0) {
    // log a sample item shape to help debugging
    console.log('Sample source[0] type:', typeof source[0], 'value:', source[0]);
  }

  // helper to extract searchable text from a line item
  const extractText = (line) => {
    if (line == null) return '';
    if (typeof line === 'string') return line;
    // prefer properties commonly used by your template
    if (typeof line.raw === 'string') return line.raw;
    if (typeof line.message === 'string') return line.message;
    // if the object has nested .meta or .text, try those
    if (typeof line.text === 'string') return line.text;
    if (line.payload && typeof line.payload === 'string') return line.payload;
    // fallback to JSON string (not ideal for very large objects)
    try {
      return JSON.stringify(line);
    } catch (err) {
      return String(line);
    }
  };

  let filtered = source;

  if (rawText.length > 0) {
    const needle = rawText.toLowerCase();
    filtered = source.filter(line => {
      const hay = extractText(line).toLowerCase();
      return hay.includes(needle);
    });
    console.log('Raw text filter:', rawText, 'Filtered down to:', filtered.length);
  } else {
    console.log('Raw text filter: <empty>');
  }

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const start = (page - 1) * perPage;
  const items = filtered.slice(start, start + perPage);

  res.json({ total, page, perPage, totalPages, items });
});



// --- Add this after your existing routes ---

/**
 * Normalize a log entry first line to create a fingerprint.
 * Strategy:
 *  - strip leading timestamp and bracket tokens
 *  - remove level words (INFO/DEBUG/ERROR/WARN/TRACE)
 *  - collapse numbers, hex, uuids, file paths and long digits into place-holders
 *  - trim and shorten to a fixed length for grouping
 */
function stripTimestampAndLevel(line) {
  // remove leading bracketed timestamp or unbracketed timestamp
  line = line.replace(/^\s*\[?\d{4}[-_]\d{2}[-_]\d{2}[_\s:-]\d{2}[:_]\d{2}[:_]\d{2}(?:[.,]\d{1,6})?\]?\s*/,'');
  // remove common level tokens at beginning
  line = line.replace(/^\s*(INFO|DEBUG|ERROR|WARN|TRACE)\b[:\-\s]*/i,'');
  return line.trim();
}

function fingerprint(text, maxLen = 120) {
  if (!text) return 'empty';
  // operate on first line only
  const firstLine = text.split(/\r?\n/)[0];
  let s = stripTimestampAndLevel(firstLine);

  // normalize GUIDs/UUIDs
  s = s.replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '<UUID>');
  // normalize long hex tokens (e.g. object ids, md5)
  s = s.replace(/\b0x[0-9a-fA-F]{6,}\b/g, '<HEX>');
  s = s.replace(/\b[0-9a-fA-F]{16,}\b/g, '<HEX>');
  // normalize numbers and timestamps inside the line
  s = s.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/g, '<ISO>');
  s = s.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<IP>');
  s = s.replace(/\b\d+\b/g, '<NUM>');
  // normalize file paths (unix/windows)
  s = s.replace(/[A-Za-z]?:?([\\/][\w\-. ]+)+/g, '<PATH>');
  // collapse repeated whitespace
  s = s.replace(/\s+/g, ' ').trim();
  // cut to length
  if (s.length > maxLen) s = s.slice(0, maxLen) + '…';
  return s || 'normalized_empty';
}

/**
 * Build summary for a job (counts + fingerprint aggregation)
 */
function buildJobSummary(job, topN = 10) {
  const counts = { INFO:0, DEBUG:0, ERROR:0, WARN:0, TRACE:0, OTHER:0, TOTAL:0 };
  const fingerprintMap = new Map(); // fingerprint => {count, examples: [raws], level}
  const topMessages = new Map(); // raw first-line => count

  for (const entry of job.all) {
    const lvl = (entry.level || 'OTHER').toUpperCase();
    const canonicalLevel = (['INFO','DEBUG','ERROR','WARN','TRACE'].includes(lvl)) ? lvl : 'OTHER';
    counts[canonicalLevel] = (counts[canonicalLevel] || 0) + 1;
    counts.TOTAL++;

    // fingerprint only for ERROR and OTHER entries that look like errors (optional: could include WARN)
    const fp = fingerprint(entry.raw);
    const meta = fingerprintMap.get(fp) || { count: 0, examples: [], level: canonicalLevel };
    meta.count++;
    if (meta.examples.length < 3) meta.examples.push(entry.raw.split(/\r?\n/)[0]); // store short examples
    fingerprintMap.set(fp, meta);

    // top message based on first line (raw)
    const first = entry.raw.split(/\r?\n/)[0].trim();
    topMessages.set(first, (topMessages.get(first) || 0) + 1);
  }

  // convert maps to arrays sorted by count
  const fingerprintList = Array.from(fingerprintMap.entries()).map(([fp, meta]) => ({ fingerprint: fp, count: meta.count, examples: meta.examples, level: meta.level }));
  fingerprintList.sort((a,b) => b.count - a.count);

  const topMessageList = Array.from(topMessages.entries()).map(([msg, count]) => ({ message: msg, count })).sort((a,b) => b.count - a.count);

  // enrich top fingerprints with a very small heuristic-suggested remediation
  const topFingerprints = fingerprintList.slice(0, topN).map(item => {
    let suggestion = 'Investigate stack trace / correlate with timestamps.';
    if (/timeout|timed out/i.test(item.fingerprint)) suggestion = 'Check network timeouts, retries and external dependencies.';
    else if (/connection refused|ECONNREFUSE/i.test(item.fingerprint)) suggestion = 'Check target service health, DNS, firewall and connection limits.';
    else if (/outofmemory|oom|java.lang.OutOfMemoryError/i.test(item.fingerprint)) suggestion = 'Check memory usage; consider heap sizing, OOM dumps and memory leak detection.';
    else if (/permission|EACCES|access denied/i.test(item.fingerprint)) suggestion = 'Revisit filesystem/credential permissions and service account rights.';
    return Object.assign({}, item, { suggestion });
  });

  // counts percentages
  const pct = {};
  for (const k of Object.keys(counts)) {
    if (k === 'TOTAL') continue;
    pct[k] = counts.TOTAL ? Math.round((counts[k]/counts.TOTAL)*10000)/100 : 0;
  }

  return {
    counts, pct,
    topFingerprints,
    topMessages: topMessageList.slice(0, topN)
  };
}

/**
 * GET /api/job/:jobId/summary
 * returns JSON summary with counts and top errors
 */
app.get('/api/job/:jobId/summary', (req, res) => {
  const job = global.JOBS && global.JOBS[req.params.jobId];
  if (!job) return res.status(404).json({ error: 'not found' });
  try {
    const summary = buildJobSummary(job, 15);
    return res.json({ jobId: req.params.jobId, createdAt: job.createdAt, totalLines: job.total, summary });
  } catch (err) {
    console.error('summary error', err);
    return res.status(500).json({ error: 'summary generation failed', message: err.message });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening: http://localhost:${PORT}`));
