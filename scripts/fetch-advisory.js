// scripts/fetch-advisory.js
// GitHub Advisory Database(REST API)를 수집해 advisory.json으로 저장한다.
// - type=reviewed   : GitHub이 큐레이션한 항목 (주로 오픈소스 패키지 취약점)
// - type=unreviewed : NVD 원본을 그대로 미러링한 항목 (Cisco/Microsoft/Palo Alto 등
//                      패키지 생태계에 얽매이지 않는 벤더 전반의 CVE가 여기 포함됨)
// 두 타입을 모두 가져와 합쳐야 "주요 벤더 CVE"까지 폭넓게 커버할 수 있다.
//
// 실행: GITHUB_TOKEN=xxx node scripts/fetch-advisory.js
// (GitHub Actions에서는 secrets.GITHUB_TOKEN 을 그대로 쓰면 됨 — 별도 PAT 불필요)

import { writeFile } from 'node:fs/promises';

const TOKEN = process.env.GITHUB_TOKEN || '';
const DAYS = 30;
const PER_PAGE = 100;
const MAX_PAGES_PER_TYPE = 20; // 안전장치: 타입당 최대 2,000건

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
