// scripts/fetch-vulnrichment.mjs
// CISA Vulnrichment — 최근 커밋 기반으로 실제 업데이트된 CVE 수집
// since 날짜 없이 최근 N개 커밋에서 변경 파일만 추림

import { writeFile } from 'node:fs/promises';

const TOKEN     = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY = process.env.DEEPL_API_KEY || '';
const MAX       = 600;        // 최대 수집 CVE 수
const MAX_COMMITS = 30;       // 최근 커밋 몇 개까지 볼지
const OWNER     = 'cisagov';
const REPO      = 'vulnrichment';
const BRANCH    = 'develop';

function ghHeaders() {
  const h = {
    'User-Agent': 'security-dashboard',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

async function getRecentPaths() {
  const paths = new Set();

  // 최근 MAX_COMMITS개 커밋 목록 (since 없음 — 항상 최신 커밋부터)
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/commits?sha=${BRANCH}&per_page=${MAX_COMMITS}`;
  const res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) throw new Error(`commits API: HTTP ${res.status}`);
  const commits = await res.json();
  console.log(`최근 커밋 ${commits.length}개 확인`);

  // 커밋별 변경 파일 순차 조회
  for (let i = 0; i < commits.length; i++) {
    if (paths.size >= MAX) break;
    const c = commits[i];
    const r = await fetch(
      `https://api.github.com/repos/${OWNER}/${REPO}/commits/${c.sha}`,
      { headers: ghHeaders() }
    );
    if (!r.ok) { console.warn(`  커밋 ${c.sha.slice(0,7)} 조회 실패: HTTP ${r.status}`); continue; }
    const d = await r.json();
    let added = 0;
    for (const f of d.files || []) {
      if (f.filename?.endsWith('.json') && f.filename.includes('CVE-')) {
        paths.add(f.filename);
        added++;
      }
    }
    if ((i + 1) % 5 === 0) console.log(`  커밋 ${i+1}/${commits.length} 처리 — 누적 ${paths.size}개`);
    // rate limit 방지
    await new Promise(r => setTimeout(r, 200));
  }

  return [...paths].slice(0, MAX);
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
    updated:   (meta.dateUpdated || meta.datePublished || '').slice(0, 10),
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
        headers: {
          'Authorization': `DeepL-Auth-Key ${DEEPL_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
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
  console.log(`CISA Vulnrichment 수집 시작 (최근 커밋 ${MAX_COMMITS}개 기준, 최대 ${MAX}개)`);

  const paths = await getRecentPaths();
  console.log(`수집 대상: ${paths.length}개`);

  if (!paths.length) {
    console.error('수집된 파일이 없습니다. GITHUB_TOKEN 권한을 확인해주세요.');
    await writeFile('vulnrichment.json', '[]');
    return;
  }

  // 5개씩 병렬 fetch
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

  // updated 기준 내림차순
  results.sort((a, b) => (b.updated || b.published || '').localeCompare(a.updated || a.published || ''));

  await writeFile('vulnrichment.json', JSON.stringify(results, null, 2));
  console.log(`✅ 완료: ${results.length}개 저장`);
}

main().catch(e => { console.error(e); process.exit(1); });
