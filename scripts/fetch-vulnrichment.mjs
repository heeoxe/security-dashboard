// scripts/fetch-vulnrichment.mjs
// CISA Vulnrichment — GitHub Search API로 최근 N일치 CVE 수집
// Palo Alto, Cisco, Microsoft, Fortinet 등 상용 벤더 + 오픈소스 모두 포함

import { writeFile } from 'node:fs/promises';

const TOKEN       = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY   = process.env.DEEPL_API_KEY || '';
const DAYS        = 7;          // 최근 7일 (Vulnrichment는 매우 활발해서 30일은 너무 많음)
const MAX_RESULTS = 200;        // 최대 수집 개수
const OWNER       = 'cisagov';
const REPO        = 'vulnrichment';
const BRANCH      = 'develop';

const since = new Date(Date.now() - DAYS * 86400000).toISOString().slice(0, 10);

function ghHeaders() {
  const h = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

// GitHub Search API로 최근 수정된 CVE 파일 경로 수집
async function getRecentCvePaths() {
  const paths = new Set();
  let page = 1;

  while (paths.size < MAX_RESULTS && page <= 4) {
    // Search API: 레포 내 최근 N일 이후 수정된 JSON 파일 검색
    const q = encodeURIComponent(`repo:${OWNER}/${REPO} path:/ extension:json CVE- pushed:>=${since}`);
    const url = `https://api.github.com/search/code?q=${q}&per_page=100&page=${page}`;
    const res = await fetch(url, {
      headers: { ...ghHeaders(), Accept: 'application/vnd.github.text-match+json' }
    });

    if (res.status === 422 || res.status === 403) {
      console.warn(`Search API 제한 (HTTP ${res.status}), commits 방식으로 전환...`);
      return await getPathsByCommits();
    }
    if (!res.ok) throw new Error(`Search API: HTTP ${res.status}`);

    const data = await res.json();
    for (const item of data.items || []) {
      if (item.path?.match(/^\d{4}\/\d+xxx\/CVE-.+\.json$/)) {
        paths.add(item.path);
        if (paths.size >= MAX_RESULTS) break;
      }
    }

    const total = data.total_count || 0;
    console.log(`  Search 페이지 ${page}: ${data.items?.length || 0}개 (총 ${total}개 중)`);
    if (!data.items?.length || data.items.length < 100) break;
    page++;

    // Search API rate limit 방지
    await new Promise(r => setTimeout(r, 2000));
  }

  return [...paths];
}

// fallback: commits API (최근 커밋 20개만)
async function getPathsByCommits() {
  const paths = new Set();
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/commits?sha=${BRANCH}&since=${since}T00:00:00Z&per_page=20`;
  const res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) throw new Error(`commits API: HTTP ${res.status}`);
  const commits = await res.json();

  for (const c of commits.slice(0, 15)) {
    if (paths.size >= MAX_RESULTS) break;
    const detail = await fetch(
      `https://api.github.com/repos/${OWNER}/${REPO}/commits/${c.sha}`,
      { headers: ghHeaders() }
    );
    if (!detail.ok) continue;
    const data = await detail.json();
    for (const f of (data.files || []).slice(0, 50)) {
      if (f.filename?.match(/^\d{4}\/\d+xxx\/CVE-.+\.json$/)) {
        paths.add(f.filename);
        if (paths.size >= MAX_RESULTS) break;
      }
    }
    await new Promise(r => setTimeout(r, 300));
  }
  return [...paths];
}

// 개별 CVE JSON fetch
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

  const cwes = (cna.problemTypes || []).flatMap(p =>
    (p.descriptions || []).filter(d => d.type === 'CWE').map(d => d.cweId)
  ).filter(Boolean);

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
    cwes,
    affected,
    exploitation,
    isKev,
    published: (meta.datePublished || '').slice(0, 10),
    updated:   (meta.dateUpdated   || '').slice(0, 10),
    url: refUrl,
    source: 'CISA Vulnrichment',
  };
}

async function deepLTranslate(texts) {
  if (!DEEPL_KEY || !texts.length) return texts;
  // DeepL은 한 번에 50개씩 배치 처리
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
      console.warn(`[WARN] DeepL 배치 ${i}~${i+50} 오류:`, e.message);
      results.push(...batch); // 실패 시 원문
    }
  }
  return results;
}

async function main() {
  console.log(`최근 ${DAYS}일 Vulnrichment CVE 수집 중... (since: ${since}, 최대 ${MAX_RESULTS}개)`);

  const paths = await getRecentCvePaths();
  console.log(`수집 대상 파일: ${paths.length}개`);

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
    if ((i + 5) % 50 === 0) console.log(`  파싱 진행: ${i + 5}/${paths.length}`);
  }

  results.sort((a, b) => (b.updated || b.published || '').localeCompare(a.updated || a.published || ''));

  if (DEEPL_KEY && results.length) {
    console.log(`DeepL 번역 시작 (${results.length}개)...`);
    const translated = await deepLTranslate(results.map(r => r.title));
    results.forEach((r, i) => { r.title_ko = translated[i]; });
    console.log('번역 완료!');
  }

  await writeFile('vulnrichment.json', JSON.stringify(results, null, 2));
  console.log(`✅ vulnrichment.json 저장 완료: ${results.length}개 (since ${since})`);
}

main().catch(e => { console.error(e); process.exit(1); });
