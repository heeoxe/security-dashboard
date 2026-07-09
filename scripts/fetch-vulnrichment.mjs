// scripts/fetch-vulnrichment.mjs
// CISA Vulnrichment — Tree API로 전체 목록 조회 후 최신 N개 수집

import { writeFile } from 'node:fs/promises';

const TOKEN     = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY = process.env.DEEPL_API_KEY || '';
const MAX       = 200;   // 수집할 최대 CVE 수
const OWNER     = 'cisagov';
const REPO      = 'vulnrichment';
const BRANCH    = 'develop';

function ghHeaders() {
  const h = { 'User-Agent': 'security-dashboard', Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

// Tree API로 특정 폴더의 모든 CVE JSON 경로 수집
async function getPathsFromTree(yearFolder) {
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/git/trees/${BRANCH}:${yearFolder}?recursive=1`;
  const res = await fetch(url, { headers: ghHeaders() });
  if (!res.ok) {
    console.warn(`  ${yearFolder} tree 실패: HTTP ${res.status}`);
    return [];
  }
  const data = await res.json();
  if (data.truncated) console.warn(`  ${yearFolder}: tree 결과 truncated`);
  return (data.tree || [])
    .filter(t => t.type === 'blob' && t.path.endsWith('.json') && t.path.includes('CVE-'))
    .map(t => `${yearFolder}/${t.path}`);
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
    updated:   (meta.dateUpdated   || meta.datePublished || '').slice(0, 10),
    url: refUrl,
    source: 'CISA Vulnrichment',
  };
}

// CVE ID에서 숫자 추출해 정렬 (높을수록 최신)
function cveNumber(path) {
  const m = path.match(/CVE-(\d{4})-(\d+)\.json$/);
  if (!m) return 0;
  return parseInt(m[1]) * 1000000 + parseInt(m[2]);
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
  const year = new Date().getFullYear();
  console.log(`CISA Vulnrichment 수집 시작 (${year}년, 최대 ${MAX}개)`);

  // 현재 연도 + 이전 연도 폴더에서 파일 목록 수집
  const allPaths = [];
  for (const y of [year, year - 1]) {
    const paths = await getPathsFromTree(String(y));
    console.log(`  ${y}년: ${paths.length}개 파일`);
    allPaths.push(...paths);
    await new Promise(r => setTimeout(r, 500));
  }

  if (!allPaths.length) {
    console.error('파일 목록이 비어있습니다. GITHUB_TOKEN 권한을 확인해주세요.');
    await writeFile('vulnrichment.json', '[]');
    return;
  }

  // CVE 번호 내림차순 정렬 후 최신 MAX개만 선택
  allPaths.sort((a, b) => cveNumber(b) - cveNumber(a));
  const selected = allPaths.slice(0, MAX);
  console.log(`최신 ${selected.length}개 파일 fetch 중...`);

  // 5개씩 병렬 fetch
  const results = [];
  for (let i = 0; i < selected.length; i += 5) {
    const batch = selected.slice(i, i + 5);
    const fetched = await Promise.all(batch.map(p => fetchCveJson(p)));
    for (let j = 0; j < fetched.length; j++) {
      if (fetched[j]) {
        const parsed = parseCve(fetched[j], batch[j]);
        if (parsed.cve) results.push(parsed);
      }
    }
    if ((i + 5) % 50 === 0) console.log(`  파싱: ${Math.min(i+5, selected.length)}/${selected.length}`);
  }

  // updated 기준 내림차순 정렬
  results.sort((a, b) => (b.updated || b.published || '').localeCompare(a.updated || a.published || ''));

  // DeepL 번역
  if (DEEPL_KEY && results.length) {
    console.log(`DeepL 번역 (${results.length}개)...`);
    const translated = await deepLTranslate(results.map(r => r.title));
    results.forEach((r, i) => { r.title_ko = translated[i]; });
    console.log('번역 완료!');
  }

  await writeFile('vulnrichment.json', JSON.stringify(results, null, 2));
  console.log(`✅ 완료: ${results.length}개 저장`);
}

main().catch(e => { console.error(e); process.exit(1); });
