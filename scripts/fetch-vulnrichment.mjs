// scripts/fetch-vulnrichment.mjs
// CISA Vulnrichment 레포에서 최근 30일 커밋된 CVE JSON을 수집해 vulnrichment.json으로 저장
// Palo Alto, Cisco, Microsoft, Fortinet 등 상용 벤더 + 오픈소스 모두 포함

import { writeFile } from 'node:fs/promises';

const TOKEN = process.env.GITHUB_TOKEN || '';
const DEEPL_KEY = process.env.DEEPL_API_KEY || '';
const DAYS = 30;
const OWNER = 'cisagov';
const REPO = 'vulnrichment';
const BRANCH = 'develop';

const since = new Date(Date.now() - DAYS * 86400000).toISOString();

function ghHeaders() {
  const h = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

// 최근 N일치 커밋에서 변경된 CVE JSON 파일 목록 수집
async function getRecentCvePaths() {
  const paths = new Set();
  let page = 1;
  while (page <= 10) {
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/commits?sha=${BRANCH}&since=${since}&per_page=100&page=${page}`;
    const res = await fetch(url, { headers: ghHeaders() });
    if (!res.ok) throw new Error(`commits API: HTTP ${res.status}`);
    const commits = await res.json();
    if (!commits.length) break;

    for (const c of commits) {
      const detail = await fetch(
        `https://api.github.com/repos/${OWNER}/${REPO}/commits/${c.sha}`,
        { headers: ghHeaders() }
      );
      if (!detail.ok) continue;
      const data = await detail.json();
      for (const f of data.files || []) {
        if (f.filename.endsWith('.json') && f.filename.match(/^\d{4}\/\d+xxx\/CVE-/)) {
          paths.add(f.filename);
        }
      }
    }
    if (commits.length < 100) break;
    page++;
  }
  return [...paths];
}

// 개별 CVE JSON 파일 fetch & 파싱
async function fetchCveJson(path) {
  const url = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/${path}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'security-dashboard' } });
  if (!res.ok) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

function parseCve(raw, path) {
  const meta = raw.cveMetadata || {};
  const cveId = meta.cveId || path.split('/').pop().replace('.json', '');
  const cna = raw.containers?.cna || {};
  const adp = (raw.containers?.adp || []).find(a => a.providerMetadata?.shortName === 'CISA-ADP') || {};

  // 제목
  const title = cna.title || (cna.descriptions || []).find(d => d.lang === 'en')?.value?.slice(0, 120) || cveId;

  // 설명
  const desc = (cna.descriptions || []).find(d => d.lang === 'en')?.value || '';

  // CVSS — CNA 우선, 없으면 ADP
  let cvss = null, severity = '';
  const allMetrics = [...(cna.metrics || []), ...(adp.metrics || [])];
  for (const m of allMetrics) {
    if (m.cvssV3_1) { cvss = m.cvssV3_1.baseScore; severity = m.cvssV3_1.baseSeverity?.toUpperCase(); break; }
    if (m.cvssV3_0) { cvss = m.cvssV3_0.baseScore; severity = m.cvssV3_0.baseSeverity?.toUpperCase(); break; }
  }

  // SSVC (Exploitation 여부)
  let exploitation = '';
  for (const m of adp.metrics || []) {
    if (m.other?.type === 'ssvc') {
      exploitation = m.other.content?.options?.find(o => o.Exploitation)?.Exploitation || '';
      break;
    }
  }

  // CWE
  const cwes = (cna.problemTypes || []).flatMap(p =>
    (p.descriptions || []).filter(d => d.type === 'CWE').map(d => d.cweId)
  ).filter(Boolean);

  // 영향받는 제품
  const affected = (cna.affected || []).map(a => ({
    vendor: a.vendor || '',
    product: a.product || '',
  })).slice(0, 5);

  // KEV 여부
  const isKev = (adp.metrics || []).some(m => m.other?.type === 'kev');

  // 참조 링크
  const refUrl = (cna.references || [])[0]?.url || `https://www.cve.org/CVERecord?id=${cveId}`;

  return {
    cve: cveId,
    title: title.slice(0, 200),
    desc: desc.slice(0, 500),
    cvss,
    severity: severity || (cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : cvss > 0 ? 'LOW' : ''),
    cwes,
    affected,
    exploitation,
    isKev,
    published: (meta.datePublished || '').slice(0, 10),
    updated: (meta.dateUpdated || '').slice(0, 10),
    url: refUrl,
    source: 'CISA Vulnrichment',
  };
}

async function deepLTranslate(texts) {
  if (!DEEPL_KEY || !texts.length) return texts;
  try {
    const params = new URLSearchParams();
    texts.forEach(t => params.append('text', t));
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
    return data.translations.map(t => t.text);
  } catch (e) {
    console.warn('[WARN] DeepL 오류:', e.message);
    return texts;
  }
}

async function main() {
  console.log(`최근 ${DAYS}일 Vulnrichment CVE 수집 중... (since: ${since.slice(0,10)})`);
  const paths = await getRecentCvePaths();
  console.log(`변경된 CVE 파일: ${paths.length}개`);

  const results = [];
  // 병렬 처리 (10개씩 배치)
  for (let i = 0; i < paths.length; i += 10) {
    const batch = paths.slice(i, i + 10);
    const fetched = await Promise.all(batch.map(p => fetchCveJson(p)));
    for (let j = 0; j < fetched.length; j++) {
      if (fetched[j]) {
        const parsed = parseCve(fetched[j], batch[j]);
        if (parsed.cve) results.push(parsed);
      }
    }
    if (i % 50 === 0) console.log(`  진행: ${i}/${paths.length}`);
  }

  // 최신순 정렬
  results.sort((a, b) => (b.updated || b.published || '').localeCompare(a.updated || a.published || ''));

  // DeepL 번역
  if (DEEPL_KEY && results.length) {
    console.log(`DeepL 번역 시작 (${results.length}개)...`);
    const titles = results.map(r => r.title);
    const translated = await deepLTranslate(titles);
    results.forEach((r, i) => { r.title_ko = translated[i]; });
    console.log('번역 완료!');
  }

  await writeFile('vulnrichment.json', JSON.stringify(results, null, 2));
  console.log(`vulnrichment.json 저장 완료: ${results.length}개`);
}

main().catch(e => { console.error(e); process.exit(1); });
