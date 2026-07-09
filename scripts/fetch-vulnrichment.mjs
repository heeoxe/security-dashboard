// scripts/fetch-vulnrichment.mjs
// CISA Vulnrichment — GitHub Tree API로 최근 수정된 CVE 파일 수집

import { writeFile } from 'node:fs/promises';

const TOKEN     = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY = process.env.DEEPL_API_KEY || '';
const DAYS      = 7;
const MAX       = 300;
const OWNER     = 'cisagov';
const REPO      = 'vulnrichment';
const BRANCH    = 'develop';

const sinceMs   = Date.now() - DAYS * 86400000;
const sinceDate = new Date(sinceMs).toISOString().slice(0, 10);

function ghHeaders() {
  const h = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

// 현재 연도 폴더 전체 tree를 가져와서 최근 N일치 파일만 필터
async function getRecentPaths() {
  const year = new Date().getFullYear();
  const paths = [];

  // tree API — 현재연도 폴더 재귀 조회
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/git/trees/${BRANCH}?recursive=0`;
  const res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) throw new Error(`tree API: HTTP ${res.status}`);
  const root = await res.json();

  // 연도 폴더 목록 (예: 2025, 2026)
  const yearFolders = (root.tree || [])
    .filter(t => t.type === 'tree' && /^\d{4}$/.test(t.path) && parseInt(t.path) >= year - 1)
    .map(t => t.path);

  console.log(`연도 폴더: ${yearFolders.join(', ')}`);

  for (const folder of yearFolders) {
    const r2 = await fetch(
      `https://api.github.com/repos/${OWNER}/${REPO}/git/trees/${BRANCH}:${folder}?recursive=1`,
      { headers: ghHeaders() }
    );
    if (!r2.ok) { console.warn(`  ${folder} tree 실패: HTTP ${r2.status}`); continue; }
    const data = await r2.json();
    for (const item of data.tree || []) {
      if (item.type === 'blob' && item.path.endsWith('.json') && item.path.includes('CVE-')) {
        paths.push(`${folder}/${item.path}`);
      }
    }
    console.log(`  ${folder}: ${data.tree?.filter(t => t.path.includes('CVE-')).length || 0}개 CVE 파일`);
    await new Promise(r => setTimeout(r, 500));
  }

  // 최근 커밋 기반으로 수정된 파일만 추리기
  console.log(`전체 CVE 파일: ${paths.length}개 — 최근 ${DAYS}일치 필터링 중...`);
  return await filterByRecentCommits(paths);
}

async function filterByRecentCommits(allPaths) {
  const recentPaths = new Set();
  // 최근 커밋 목록 (since 파라미터로 N일치만)
  let page = 1;
  while (recentPaths.size < MAX && page <= 5) {
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/commits?sha=${BRANCH}&since=${sinceDate}T00:00:00Z&per_page=100&page=${page}`;
    const res = await fetch(url, { headers: ghHeaders() });
    if (!res.ok) throw new Error(`commits API: HTTP ${res.status}`);
    const commits = await res.json();
    if (!commits.length) break;

    // 커밋별 변경 파일 (병렬 5개씩)
    for (let i = 0; i < commits.length; i += 5) {
      const batch = commits.slice(i, i + 5);
      await Promise.all(batch.map(async c => {
        const r = await fetch(
          `https://api.github.com/repos/${OWNER}/${REPO}/commits/${c.sha}`,
          { headers: ghHeaders() }
        );
        if (!r.ok) return;
        const d = await r.json();
        for (const f of d.files || []) {
          if (f.filename.endsWith('.json') && f.filename.includes('CVE-')) {
            recentPaths.add(f.filename);
          }
        }
      }));
      if (recentPaths.size >= MAX) break;
    }

    console.log(`  커밋 페이지 ${page}: 현재까지 ${recentPaths.size}개 파일`);
    if (commits.length < 100) break;
    page++;
    await new Promise(r => setTimeout(r, 1000));
  }

  // allPaths와 교집합 (실제 존재하는 파일만)
  const allSet = new Set(allPaths);
  return [...recentPaths].filter(p => allSet.has(p)).slice(0, MAX);
}

async function fetchCveJson(path) {
  const url = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/${path}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'security-dashboard' } });
  if (!res.ok) return null;
  try { return await res.json(); } catch { return null; }
}

function parseCve(raw, path) {
  const meta = raw.cveMetadata || {};
  const cveId = meta.cveId || path.split('/').pop().replace('.json', '');
  const cna = raw.containers?.cna || {};
  const adp = (raw.containers?.adp || []).find(a => a.providerMetadata?.shortName === 'CISA-ADP') || {};

  const title = cna.title || (cna.descriptions || []).find(d => d.lang === 'en')?.value?.slice(0, 120) || cveId;
  const desc  = (cna.descriptions || []).find(d => d.lang === 'en')?.value || '';

  let cvss = null, severity = '';
  for (const m of [...(cna.metrics || []), ...(adp.metrics || [])]) {
    if (m.cvssV3_1) { cvss = m.cvssV3_1.baseScore; severity = m.cvssV3_1.baseSeverity?.toUpperCase(); break; }
    if (m.cvssV3_0) { cvss = m.cvssV3_0.baseScore; severity = m.cvssV3_0.baseSeverity?.toUpperCase(); break; }
  }

  let exploitation = '';
  for (const m of adp.metrics || []) {
    if (m.other?.type === 'ssvc') {
      exploitation = m.other.content?.options?.find(o => o.Exploitation)?.Exploitation || '';
      break;
    }
  }

  const cwes = (cna.problemTypes || [])
    .flatMap(p => (p.descriptions || []).filter(d => d.type === 'CWE').map(d => d.cweId))
    .filter(Boolean);

  const affected = (cna.affected || []).map(a => ({
    vendor: a.vendor || '', product: a.product || '',
  })).slice(0, 5);

  const isKev = (adp.metrics || []).some(m => m.other?.type === 'kev');
  const refUrl = (cna.references || [])[0]?.url || `https://www.cve.org/CVERecord?id=${cveId}`;

  return {
    cve: cveId,
    title: title.slice(0, 200),
    desc: desc.slice(0, 400),
    cvss,
    severity: severity || (cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : cvss > 0 ? 'LOW' : ''),
    cwes, affected, exploitation, isKev,
    published: (meta.datePublished || '').slice(0, 10),
    updated:   (meta.dateUpdated   || '').slice(0, 10),
    url: refUrl,
    source: 'CISA Vulnrichment',
  };
}

async function deepLTranslate(texts) {
  if (!DEEPL_KEY || !texts.length) return texts;
  const results = [];
  for (let i = 0; i < texts.length; i += 50) {
    const batch = texts.slice(i, i + 50);
    try {
      const params = new URLSearchParams();
      batch.forEach(t => params.append('text', t));
      params.append('source_lang', 'EN');
      params.append('target_lang', 'KO');
      params.append('formality', 'prefer_less');
      const res = await fetch('https://api-free.deepl.com/v2/translate', {
        method: 'POST',
        headers: { 'Authorization': `DeepL-Auth-Key ${DEEPL_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      });
      if (!res.ok) throw new Error(`DeepL HTTP ${res.status}`);
      const data = await res.json();
      results.push(...data.translations.map(t => t.text));
    } catch (e) {
      console.warn(`[WARN] DeepL 오류:`, e.message);
      results.push(...batch);
    }
  }
  return results;
}

async function main() {
  console.log(`CISA Vulnrichment 수집 시작 (최근 ${DAYS}일, 최대 ${MAX}개)`);
  const paths = await getRecentPaths();
  console.log(`수집 대상: ${paths.length}개`);

  const results = [];
  for (let i = 0; i < paths.length; i += 5) {
    const batch = paths.slice(i, i + 5);
    const fetched = await Promise.all(batch.map(p => fetchCveJson(p)));
    for (let j = 0; j < fetched.length; j++) {
      if (fetched[j]) {
        const parsed = parseCve(fetched[j], batch[j]);
        if (parsed.cve) results.push(parsed);
      }
    }
    if ((i + 5) % 50 === 0) console.log(`  파싱: ${Math.min(i+5, paths.length)}/${paths.length}`);
  }

  results.sort((a, b) => (b.updated || b.published || '').localeCompare(a.updated || a.published || ''));

  if (DEEPL_KEY && results.length) {
    console.log(`DeepL 번역 (${results.length}개)...`);
    const translated = await deepLTranslate(results.map(r => r.title));
    results.forEach((r, i) => { r.title_ko = translated[i]; });
    console.log('번역 완료!');
  }

  await writeFile('vulnrichment.json', JSON.stringify(results, null, 2));
  console.log(`✅ 완료: ${results.length}개 저장 (since ${sinceDate})`);
}

main().catch(e => { console.error(e); process.exit(1); });
