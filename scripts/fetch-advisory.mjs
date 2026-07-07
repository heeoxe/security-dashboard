import { writeFile } from 'node:fs/promises';

const TOKEN = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY = process.env.DEEPL_API_KEY || '';
const DAYS = 30;
const PER_PAGE = 100;
const MAX_PAGES_PER_TYPE = 20;

const since = new Date(Date.now() - DAYS * 86400000).toISOString().slice(0, 10);

function authHeaders() {
  const h = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

function nextUrlFromLinkHeader(linkHeader) {
  if (!linkHeader) return null;
  const parts = linkHeader.split(',');
  const next = parts.find((p) => p.includes('rel="next"'));
  if (!next) return null;
  const m = next.match(/<([^>]+)>/);
  return m ? m[1] : null;
}

async function fetchType(type) {
  const items = [];
  const params = new URLSearchParams({
    per_page: String(PER_PAGE),
    sort: 'published',
    direction: 'desc',
    type,
    published: `>=${since}`,
  });
  let url = `https://api.github.com/advisories?${params.toString()}`;
  let page = 0;

  while (url && page < MAX_PAGES_PER_TYPE) {
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`[${type}] GET ${url} -> HTTP ${res.status} ${body.slice(0, 300)}`);
    }
    const data = await res.json();
    items.push(...data);
    url = nextUrlFromLinkHeader(res.headers.get('link'));
    page += 1;
  }
  return items;
}

function normalize(a) {
  const vulns = a.vulnerabilities || [];
  return {
    ghsa: a.ghsa_id,
    cve: a.cve_id || null,
    title: a.summary || '',
    desc: a.description || '',
    severity: (a.severity || '').toUpperCase(),
    cvss: a.cvss?.score ?? a.cvss_severities?.cvss_v3?.score ?? null,
    cwes: (a.cwes || []).map((c) => c.cwe_id).filter(Boolean),
    published: (a.published_at || '').slice(0, 10),
    updated: (a.updated_at || '').slice(0, 10),
    type: a.type,
    ecosystems: [...new Set(vulns.map((v) => v.package?.ecosystem).filter(Boolean))],
    packages: [...new Set(vulns.map((v) => v.package?.name).filter(Boolean))].slice(0, 8),
    url: a.html_url,
    withdrawn: !!a.withdrawn_at,
  };
}

// DeepL 배치 번역 — 명사형 말투 지정
async function deepLTranslate(texts) {
  if (!DEEPL_KEY || !texts.length) return texts;
  try {
    const params = new URLSearchParams();
    texts.forEach(t => params.append('text', t));
    params.append('source_lang', 'EN');
    params.append('target_lang', 'KO');
    // formality 파라미터로 말투 제어 (prefer_less = 비격식/간결체)
    params.append('formality', 'prefer_less');

    const res = await fetch('https://api-free.deepl.com/v2/translate', {
      method: 'POST',
      headers: {
        'Authorization': `DeepL-Auth-Key ${DEEPL_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
    if (!res.ok) throw new Error(`DeepL HTTP ${res.status}`);
    const data = await res.json();
    return data.translations.map(t => t.text);
  } catch (e) {
    console.warn('[WARN] DeepL 번역 오류:', e.message);
    return texts;
  }
}

async function main() {
  const [reviewed, unreviewed] = await Promise.all([
    fetchType('reviewed'),
    fetchType('unreviewed'),
  ]);

  const byGhsa = new Map();
  for (const a of [...reviewed, ...unreviewed]) {
    if (a.withdrawn_at) continue;
    byGhsa.set(a.ghsa_id, normalize(a));
  }

  const merged = [...byGhsa.values()].sort((a, b) =>
    (b.published || '').localeCompare(a.published || '')
  );

  // DeepL로 title 번역
  if (DEEPL_KEY && merged.length) {
    console.log(`DeepL 번역 시작 (${merged.length}개)...`);
    const titles = merged.map(a => a.title);
    const translated = await deepLTranslate(titles);
    merged.forEach((a, i) => { a.title_ko = translated[i]; });
    console.log('번역 완료!');
  }

  await writeFile('advisory.json', JSON.stringify(merged, null, 2));
  console.log(
    `advisory.json 저장 완료: reviewed=${reviewed.length}, unreviewed=${unreviewed.length}, ` +
    `중복 제거 후=${merged.length} (최근 ${DAYS}일, since=${since})`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

function authHeaders() {
  const h = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

function nextUrlFromLinkHeader(linkHeader) {
  if (!linkHeader) return null;
  const parts = linkHeader.split(',');
  const next = parts.find((p) => p.includes('rel="next"'));
  if (!next) return null;
  const m = next.match(/<([^>]+)>/);
  return m ? m[1] : null;
}

async function fetchType(type) {
  const items = [];
  const params = new URLSearchParams({
    per_page: String(PER_PAGE),
    sort: 'published',
    direction: 'desc',
    type,
    published: `>=${since}`,
  });
  let url = `https://api.github.com/advisories?${params.toString()}`;
  let page = 0;

  while (url && page < MAX_PAGES_PER_TYPE) {
    const res = await fetch(url, { headers: authHeaders() });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`[${type}] GET ${url} -> HTTP ${res.status} ${body.slice(0, 300)}`);
    }
    const data = await res.json();
    items.push(...data);
    url = nextUrlFromLinkHeader(res.headers.get('link'));
    page += 1;
  }
  return items;
}

function normalize(a) {
  const vulns = a.vulnerabilities || [];
  return {
    ghsa: a.ghsa_id,
    cve: a.cve_id || null,
    title: a.summary || '',
    desc: a.description || '',
    severity: (a.severity || '').toUpperCase(),
    cvss: a.cvss?.score ?? a.cvss_severities?.cvss_v3?.score ?? null,
    cwes: (a.cwes || []).map((c) => c.cwe_id).filter(Boolean),
    published: (a.published_at || '').slice(0, 10),
    updated: (a.updated_at || '').slice(0, 10),
    type: a.type, // 'reviewed' | 'unreviewed'
    ecosystems: [...new Set(vulns.map((v) => v.package?.ecosystem).filter(Boolean))],
    packages: [...new Set(vulns.map((v) => v.package?.name).filter(Boolean))].slice(0, 8),
    url: a.html_url,
    withdrawn: !!a.withdrawn_at,
  };
}

async function main() {
  const [reviewed, unreviewed] = await Promise.all([
    fetchType('reviewed'),
    fetchType('unreviewed'),
  ]);

  const byGhsa = new Map();
  for (const a of [...reviewed, ...unreviewed]) {
    if (a.withdrawn_at) continue;
    byGhsa.set(a.ghsa_id, normalize(a));
  }

  const merged = [...byGhsa.values()].sort((a, b) =>
    (b.published || '').localeCompare(a.published || '')
  );

  await writeFile('advisory.json', JSON.stringify(merged, null, 2));
  console.log(
    `advisory.json 저장 완료: reviewed=${reviewed.length}, unreviewed=${unreviewed.length}, ` +
    `중복 제거 후=${merged.length} (최근 ${DAYS}일, since=${since})`
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
