// === Data Store ===
let DATA = {
  components: [],
  repos: [],
  threats: [],
  controls: [],
  papers: [],
  ecosystem: { categories: [], repos: [] },
  skills: { stats: {}, categories: [], top_skills: [], clawhub_categories: [] },
  attacks: { stats: {}, distribution: [], kill_chain: [], attack_surfaces: [], cves: [], scenarios: [], mitre_mapping: [], references: [] },
  timeline: { stats: {}, phases: [], events: [], structural_causes: [] },
  basic: { stats: {}, naming_evolution: [], workspace_files: [], memory_system: {}, architecture: {}, releases: [], cli_commands: [], supported_providers: [], supported_channels: [] },
  moltbook: { stats: {}, overview: {}, timeline: [], security_incidents: [], controversies: [], key_figures: [], submolts: [], research_papers: [], media_coverage: [] },
};

let selectedResource = null;
let activeFilters = {};
let currentSort = 'risk';
let activePaperType = 'all';
let activeEcoCategory = 'all';
let activeEcoSort = 'stars';
let activeSkillCategory = 'all';
let activeSkillSort = 'downloads';
let activeAttackCategory = 'all';
let activeAttackPhase = 'all';
let activeTimelineYear = 'all';
let activeTimelineScope = 'all';

// === Init ===
document.addEventListener('DOMContentLoaded', async () => {
  await loadData();
  initTabs();
  initHashRouting();
  initFilters();
  initSearch();
  initSort();
  initDarkMode();
  initEcosystem();
  initSkills();
  renderOverview();
  renderDirectory();
  renderSecurity();
  renderSecurityMatrix();
  renderResearch();
  renderEcosystem();
  renderSkills();
  initAttacks();
  renderAttacks();
  initTimeline();
  renderTimeline();
  renderBasic();
  renderMoltbook();
});

// === Data Loading ===
async function loadData() {
  const files = ['components', 'repos', 'threats', 'controls', 'papers', 'ecosystem', 'skills', 'attacks', 'timeline', 'basic', 'moltbook'];
  const results = await Promise.all(
    files.map(f => fetch(`data/${f}.json`).then(r => {
      if (!r.ok) throw new Error(`Failed to load ${f}.json: ${r.status}`);
      return r.json();
    }).catch(err => {
      console.error(err);
      return f === 'ecosystem' ? { categories: [], repos: [] }
           : f === 'skills' ? { stats: {}, categories: [], top_skills: [], clawhub_categories: [] }
           : f === 'attacks' ? { stats: {}, distribution: [], kill_chain: [], attack_surfaces: [], cves: [], scenarios: [], mitre_mapping: [], references: [] }
           : f === 'timeline' ? { stats: {}, phases: [], events: [], structural_causes: [] }
           : f === 'basic' ? { stats: {}, naming_evolution: [], workspace_files: [], memory_system: {}, architecture: {}, releases: [], cli_commands: [], supported_providers: [], supported_channels: [] }
           : f === 'moltbook' ? { stats: {}, overview: {}, timeline: [], security_incidents: [], controversies: [], key_figures: [], submolts: [], research_papers: [], media_coverage: [] }
           : [];
    }))
  );
  files.forEach((f, i) => DATA[f] = results[i]);
}

// === Tab Navigation ===
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
    });
  });
}

// === Risk Calculation ===
function calcRiskLevel(repo, useControlGap = true) {
  // Use quantitative risk score if available
  if (repo.risk_score && repo.risk_score.level) {
    const l = repo.risk_score.level.toLowerCase();
    if (l === 'extreme') return 'critical';
    if (l === 'critical') return 'critical';
    if (l === 'high') return 'high';
    if (l === 'moderate') return 'medium';
    return 'low';
  }
  if (!repo.threat_ids || repo.threat_ids.length === 0) return 'none';
  const threatSeverities = repo.threat_ids.map(tid => {
    const t = DATA.threats.find(th => th.id === tid);
    return t ? t.severity : 'low';
  });
  const hasCritical = threatSeverities.includes('critical');
  const hasHigh = threatSeverities.includes('high');

  if (!useControlGap || !repo.control_ids) {
    if (hasCritical) return 'high';
    if (hasHigh) return 'medium';
    return 'low';
  }

  const controlCount = (repo.control_ids || []).length;
  const threatCount = repo.threat_ids.length;
  const coverageRatio = threatCount > 0 ? controlCount / threatCount : 1;
  if (hasCritical && coverageRatio < 0.5) return 'critical';
  if (hasCritical) return 'high';
  if (hasHigh && coverageRatio < 0.5) return 'high';
  if (hasHigh) return 'medium';
  return 'low';
}

function riskScoreLabel(score) {
  if (!score) return '';
  return score.total + '/100';
}

function policyBadgeHtml(policy) {
  if (!policy) return '';
  const colors = { Block:'#ff4757', Restricted:'#ff8c42', Sandbox:'#ffc312', Allow:'#00e6a7' };
  const c = colors[policy] || '#5a6d84';
  return '<span style="font-size:0.7rem;font-weight:700;padding:2px 7px;border-radius:4px;background:' + c + '22;color:' + c + ';border:1px solid ' + c + '44;margin-left:4px">' + policy + '</span>';
}

function riskOrder(level) {
  return { critical: 0, high: 1, medium: 2, low: 3, none: 4 }[level] ?? 5;
}

function severityColor(severity) {
  return {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e'
  }[severity] || '#64748b';
}

function renderThreatTag(threat) {
  return `<span class="threat-tag"><span class="severity-indicator" style="width:6px;height:6px;border-radius:50%;background:${severityColor(threat.severity)}"></span>${threat.name}</span>`;
}

function renderThreatTags(threatIds) {
  const threats = (threatIds || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
  return threats.map(renderThreatTag).join('');
}

function fuzzySearch(items, query, fields) {
  if (!query) return items;
  const q = query.toLowerCase().trim();
  return items.filter(item => {
    const searchable = fields.map(f => {
      const v = item[f];
      return Array.isArray(v) ? v.join(' ') : (v || '');
    }).join(' ').toLowerCase();
    return searchable.includes(q);
  });
}

// === Control Gap Analysis ===
function findControlGaps(repo) {
  const gaps = [];
  (repo.threat_ids || []).forEach(tid => {
    const threat = DATA.threats.find(t => t.id === tid);
    if (!threat) return;
    const neededControls = threat.controls || [];
    const repoControls = repo.control_ids || [];
    const missing = neededControls.filter(c => !repoControls.includes(c));
    if (missing.length > 0) {
      gaps.push({ threat: threat, missing });
    }
  });
  return gaps;
}

// === Overview ===
function renderOverview() {
  const ecoRepos = (DATA.ecosystem.repos || []).length;
  const skillCount = DATA.skills.stats?.total_clawhub || 0;
  document.getElementById('stat-repos').textContent = ecoRepos;
  document.getElementById('stat-skills').textContent = skillCount.toLocaleString();
  document.getElementById('stat-threats').textContent = DATA.threats.length;
  document.getElementById('stat-papers').textContent = DATA.papers.length;

  const scenarioEl = document.getElementById('stat-scenarios');
  if (scenarioEl) scenarioEl.textContent = (DATA.attacks.scenarios || []).length;
  const cveEl = document.getElementById('stat-cves');
  if (cveEl) cveEl.textContent = (DATA.attacks.cves || []).length;
  const malEl = document.getElementById('stat-malicious');
  if (malEl) malEl.textContent = (DATA.skills.stats?.flagged_malicious || 0).toLocaleString();
  const ctrlEl = document.getElementById('stat-controls');
  if (ctrlEl) ctrlEl.textContent = DATA.controls.length;

  // Risk distribution
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  DATA.repos.forEach(r => { riskCounts[calcRiskLevel(r)]++; });
  const total = DATA.repos.length;
  const distEl = document.getElementById('risk-distribution');
  distEl.innerHTML = Object.entries(riskCounts).map(([level, count]) => `
    <div class="flex items-center gap-3">
      <span class="risk-badge risk-${level}" style="width:70px; justify-content:center">${level}</span>
      <div class="flex-1 progress-bar">
        <div class="progress-fill" style="width:${(count/total*100)}%; background:${severityColor(level)}"></div>
      </div>
      <span class="text-sm text-gray-400" style="width:30px; text-align:right">${count}</span>
    </div>
  `).join('');

  // Top threats
  const threatCounts = DATA.threats.map(t => ({
    threat: t,
    count: DATA.repos.filter(r => (r.threat_ids || []).includes(t.id)).length
  })).sort((a, b) => b.count - a.count).slice(0, 6);

  document.getElementById('top-threats').innerHTML = threatCounts.map(({ threat, count }) => `
    <div class="flex items-center gap-3">
      <span class="severity-indicator" style="width:8px;height:8px;border-radius:50%;background:${severityColor(threat.severity)};flex-shrink:0"></span>
      <span class="text-sm flex-1">${threat.name}</span>
      <span class="text-sm text-gray-400">${count} items</span>
    </div>
  `).join('');

  // Layer overview
  document.getElementById('layer-overview').innerHTML = DATA.components.map(comp => {
    const layerRepos = DATA.repos.filter(r => r.layer === comp.id);
    const maxRisk = layerRepos.reduce((max, r) => {
      const rl = calcRiskLevel(r);
      return riskOrder(rl) < riskOrder(max) ? rl : max;
    }, 'none');
    return `
      <div class="layer-card" onclick="navigateToLayer('${comp.id}')">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-gray-500">${comp.code}</span>
          <span class="risk-badge risk-${maxRisk}">${maxRisk}</span>
        </div>
        <div class="font-semibold text-sm mb-1">${comp.name}</div>
        <div class="text-xs text-gray-500">${layerRepos.length} items</div>
      </div>
    `;
  }).join('');

  // === Phase 5: Enhanced Overview ===

  // 5.3.6 Executive Summary
  const execEl = document.getElementById('executive-summary');
  if (execEl) {
    const criticals = DATA.threats.filter(t => t.severity === 'critical').length;
    const events2026 = (DATA.timeline.events || []).filter(e => e.year >= 2026).length;
    const malicious = DATA.skills.stats?.flagged_malicious || 0;
    const cveCount = (DATA.attacks.cves || []).length;
    const gaps = DATA.repos.reduce((sum, r) => sum + findControlGaps(r).length, 0);
    const summary = `OpenClaw 생태계 현황: ${(DATA.ecosystem.repos || []).length}개 프로젝트, ${(DATA.skills.stats?.total_clawhub || 0).toLocaleString()}개 ClawHub 스킬이 운영 중이며, 이 중 ${malicious}개(${DATA.skills.stats?.flagged_percent || 0}%)가 악성으로 플래그됨. ${criticals}개 Critical 위협, ${cveCount}개 CVE가 식별되었고, 2026년에만 ${events2026}건의 보안 사건 발생. ${gaps > 0 ? `현재 ${gaps}개 컨트롤 갭이 미해결 상태.` : `모든 핵심 컴포넌트의 컨트롤 갭이 해소됨.`}`;
    execEl.textContent = summary;
  }

  // 5.3.1 Security Alert Banner
  const alertEl = document.getElementById('overview-alert-content');
  if (alertEl) {
    const alerts = [];
    const sevStyle = {
      critical: { bg: 'rgba(255,60,80,0.1)', border: '#5a1525', dot: '#ff4d6a', text: '#ffa0b0' },
      high:     { bg: 'rgba(255,140,66,0.08)', border: '#4a2a10', dot: '#ff8c42', text: '#ffc494' },
      medium:   { bg: 'rgba(255,195,18,0.06)', border: '#3a3010', dot: '#ffc312', text: '#ffe08a' }
    };
    (DATA.attacks.cves || []).forEach(c => {
      const s = c.severity === 'critical' ? 'critical' : 'high';
      alerts.push({ severity: s, html: `<span style="color:${sevStyle[s].dot};font-weight:700">${c.id}</span> <span style="color:${sevStyle[s].text}">${c.title}</span> <span class="risk-badge risk-${c.severity}" style="font-size:10px;padding:1px 6px">${c.severity}</span>` });
    });
    const malPct = DATA.skills.stats?.flagged_percent || 0;
    if (malPct > 5) alerts.push({ severity: 'high', html: `<span style="color:#ff8c42;font-weight:700">Malicious Skills</span> <span style="color:#ffc494">악성 스킬 비율 ${malPct}% — ClawHub 스킬 설치 전 소스 검토 필수</span>` });
    const recentCritical = (DATA.timeline.events || []).filter(e => e.severity === 'critical' && e.year >= 2026).slice(0, 3);
    recentCritical.forEach(e => alerts.push({ severity: 'critical', html: `<span style="color:#ff4d6a;font-weight:700">${e.date}</span> <span style="color:#ffa0b0">${e.title}</span>` }));
    alertEl.innerHTML = alerts.map(a => {
      const s = sevStyle[a.severity] || sevStyle.medium;
      return `<div class="flex items-center gap-2 px-3 py-1.5 rounded-lg" style="background:${s.bg};border:1px solid ${s.border}">
        <span class="w-1.5 h-1.5 rounded-full flex-shrink-0" style="background:${s.dot};box-shadow:0 0 6px ${s.dot}40"></span>
        <span class="text-xs">${a.html}</span>
      </div>`;
    }).join('');
    const countEl = document.getElementById('overview-alert-count');
    if (countEl) countEl.textContent = alerts.length + ' alerts';
    const alertBox = document.getElementById('overview-alert');
    if (alertBox) alertBox.classList.toggle('hidden', alerts.length === 0);
  }

  // 5.3.3 Recent Security Events
  const recentEl = document.getElementById('overview-recent-events');
  if (recentEl) {
    const recentEvents = [...(DATA.timeline.events || [])].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 5);
    recentEl.innerHTML = recentEvents.map(e => `
      <div class="flex items-center gap-3">
        <span class="risk-dot risk-${e.severity === 'critical' ? 'critical' : e.severity === 'high' ? 'high' : 'medium'}"></span>
        <span class="text-xs text-gray-500 w-20 flex-shrink-0">${e.date}</span>
        <span class="text-sm flex-1">${e.title}</span>
      </div>
    `).join('');
  }

  // 5.3.4 Attack Distribution
  const atkDistEl = document.getElementById('overview-attack-dist');
  if (atkDistEl) {
    const dist = DATA.attacks.distribution || [];
    const maxPct = Math.max(...dist.map(d => d.percent || 0), 1);
    atkDistEl.innerHTML = dist.map(d => `
      <div class="flex items-center gap-3">
        <span class="text-sm flex-1">${d.category}</span>
        <div class="w-32 progress-bar">
          <div class="progress-fill" style="width:${((d.percent||0)/maxPct*100)}%;background:${d.color || '#ff6b7a'}"></div>
        </div>
        <span class="text-sm text-gray-400 w-10 text-right">${d.percent}%</span>
      </div>
    `).join('');
  }

  // 5.3.5 Ecosystem Health
  const depNetEl = document.getElementById('overview-dep-network');
  if (depNetEl) {
    const net = DATA.ecosystem.dependency_network || {};
    depNetEl.innerHTML = `
      <div class="text-xs text-gray-400 space-y-2">
        <div>모델: <span class="text-sm font-semibold text-gray-300">${net.network_characteristics?.topology || 'Hub-and-Spoke'}</span></div>
        <div>의존성 유형: ${(net.dependency_types || []).length}개</div>
        <div>공급망 단계: ${net.supply_chain ? net.supply_chain.flow.length : 0}개</div>
      </div>`;
  }

  const skillSecEl = document.getElementById('overview-skill-security');
  if (skillSecEl) {
    const ss = DATA.skills.stats || {};
    const totalS = ss.total_clawhub || 0;
    const flaggedS = ss.flagged_malicious || 0;
    const safeP = totalS > 0 ? ((totalS - flaggedS) / totalS * 100).toFixed(1) : 100;
    skillSecEl.innerHTML = `
      <div class="text-2xl font-bold mb-2" style="color:${safeP > 95 ? '#00e6a7' : safeP > 90 ? '#ffc312' : '#ff4757'}">${safeP}%</div>
      <div class="text-xs text-gray-400">안전 스킬 비율 (${(totalS - flaggedS).toLocaleString()} / ${totalS.toLocaleString()})</div>
      <div class="progress-bar mt-3"><div class="progress-fill" style="width:${safeP}%;background:#00e6a7"></div></div>`;
  }

  const ctrlCovEl = document.getElementById('overview-control-coverage');
  if (ctrlCovEl) {
    const totalGaps = DATA.repos.reduce((sum, r) => sum + findControlGaps(r).length, 0);
    const coveredRepos = DATA.repos.filter(r => findControlGaps(r).length === 0).length;
    ctrlCovEl.innerHTML = `
      <div class="text-2xl font-bold mb-2" style="color:${totalGaps === 0 ? '#00e6a7' : '#ff8c42'}">${coveredRepos}/${DATA.repos.length}</div>
      <div class="text-xs text-gray-400">완전 방어 컴포넌트</div>
      ${totalGaps > 0 ? `<div class="text-xs mt-2 font-semibold" style="color:#ff8c42">⚠ ${totalGaps}개 컨트롤 갭 미해결</div>` : ''}`;
  }
}

function navigateToLayer(layerId) {
  // Switch to directory tab and filter by layer
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  document.querySelector('[data-tab="directory"]').classList.add('active');
  document.getElementById('tab-directory').classList.remove('hidden');

  // Uncheck all layers, check target
  document.querySelectorAll('#filter-layer input').forEach(cb => {
    cb.checked = cb.value === layerId;
  });
  renderDirectory();
}

// === Filters ===
function initFilters() {
  // Layer filters
  const layerEl = document.getElementById('filter-layer');
  layerEl.innerHTML = DATA.components.map(c => `
    <label class="filter-checkbox"><input type="checkbox" value="${c.id}" checked> ${c.name}</label>
  `).join('');

  // Language filters
  const languages = [...new Set(DATA.repos.map(r => r.language))].sort();
  document.getElementById('filter-language').innerHTML = languages.map(l => `
    <label class="filter-checkbox"><input type="checkbox" value="${l}" checked> ${l}</label>
  `).join('');

  // Threat type filters
  document.getElementById('filter-threat-type').innerHTML = DATA.threats.map(t => `
    <label class="filter-checkbox"><input type="checkbox" value="${t.id}" checked> ${t.name}</label>
  `).join('');

  // Attach listeners
  document.querySelectorAll('#tab-directory aside input[type="checkbox"]').forEach(cb => {
    cb.addEventListener('change', () => renderDirectory());
  });

  document.getElementById('directory-search').addEventListener('input', () => renderDirectory());

  document.getElementById('btn-reset-filters').addEventListener('click', () => {
    document.querySelectorAll('#tab-directory aside input[type="checkbox"]').forEach(cb => cb.checked = true);
    document.getElementById('directory-search').value = '';
    renderDirectory();
  });
}

function getActiveFilters() {
  const get = (id) => [...document.querySelectorAll(`#${id} input:checked`)].map(cb => cb.value);
  return {
    types: get('filter-type'),
    risks: get('filter-risk'),
    layers: get('filter-layer'),
    languages: get('filter-language'),
    threats: get('filter-threat-type'),
    controlStatus: get('filter-control-status'),
  };
}

function filterRepos() {
  const f = getActiveFilters();
  const query = document.getElementById('directory-search').value.toLowerCase();

  return DATA.repos.filter(r => {
    if (!f.types.includes(r.type)) return false;
    if (!f.risks.includes(calcRiskLevel(r))) return false;
    if (!f.layers.includes(r.layer)) return false;
    if (!f.languages.includes(r.language)) return false;

    // Threat type filter
    if (f.threats.length < DATA.threats.length) {
      const hasThreat = (r.threat_ids || []).some(tid => f.threats.includes(tid));
      if (!hasThreat && r.threat_ids.length > 0) return false;
    }

    // Control status filter
    const gaps = findControlGaps(r);
    const hasGaps = gaps.length > 0;
    if (!f.controlStatus.includes('gap') && hasGaps && r.threat_ids.length > 0) return false;
    if (!f.controlStatus.includes('covered') && !hasGaps && r.threat_ids.length > 0) return false;

    // Search
    if (query) {
      const searchable = [r.name, r.description, r.category, r.language, ...(r.threat_ids || []), ...(r.control_ids || [])].join(' ').toLowerCase();
      if (!searchable.includes(query)) return false;
    }

    return true;
  });
}

function sortRepos(repos) {
  return [...repos].sort((a, b) => {
    if (currentSort === 'risk') return riskOrder(calcRiskLevel(a)) - riskOrder(calcRiskLevel(b));
    if (currentSort === 'name') return a.name.localeCompare(b.name);
    if (currentSort === 'stars') return (b.stars || 0) - (a.stars || 0);
    return 0;
  });
}

// === Sort (Directory tab only) ===
function initSort() {
  document.querySelectorAll('.sort-btn[data-sort]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sort-btn[data-sort]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSort = btn.dataset.sort;
      renderDirectory();
    });
  });
}

// === Directory Rendering ===
function renderDirectory() {
  const filtered = sortRepos(filterRepos());
  document.getElementById('result-count').textContent = `${filtered.length} results`;

  const listEl = document.getElementById('resource-list');
  listEl.innerHTML = filtered.map(r => renderResourceCard(r)).join('');

  // Attach click listeners
  listEl.querySelectorAll('.resource-card').forEach(card => {
    card.addEventListener('click', () => {
      const repo = DATA.repos.find(r => r.id === card.dataset.id);
      selectResource(repo);
    });
  });
}

function renderResourceCard(r) {
  const risk = calcRiskLevel(r);
  const threats = (r.threat_ids || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
  const gaps = findControlGaps(r);
  const isSelected = selectedResource && selectedResource.id === r.id;

  let threatsHtml = '';
  if (threats.length > 0) {
    const threatTags = threats.map(renderThreatTag).join('');

    const gapHtml = gaps.length > 0
      ? `<div class="mt-2"><span class="control-gap-warning">&#x26a0; ${gaps.reduce((sum, g) => sum + g.missing.length, 0)} control gaps detected</span></div>`
      : '';

    threatsHtml = `
      <div class="threats-section">
        <div class="threats-section-title">&#x26a0; Known Threats (${threats.length})</div>
        <div class="flex flex-wrap">${threatTags}</div>
        ${gapHtml}
      </div>
    `;
  }

  const mitreTags = (r.mitre_ids || []).map(id => {
    const cls = id.startsWith('ATLAS') ? 'mitre-atlas' : id.startsWith('ATTACK') ? 'mitre-attack' : 'mitre-defend';
    return `<span class="mitre-badge ${cls}">${id}</span>`;
  }).join(' ');

  return `
    <div class="resource-card ${isSelected ? 'selected' : ''}" data-id="${r.id}">
      <div class="resource-header">
        <div class="flex items-center gap-2">
          <span style="font-size:1.1rem">${r.type === 'skill' ? '&#x1f9e9;' : '&#x1f4e6;'}</span>
          <span class="resource-name">${r.name}</span>
        </div>
        <div class="flex items-center gap-2">
          ${r.risk_score ? `<span class="text-xs font-bold" style="color:${r.risk_score.total >= 80 ? '#ff4757' : r.risk_score.total >= 60 ? '#ff8c42' : r.risk_score.total >= 40 ? '#ffc312' : '#00e6a7'}">${r.risk_score.total}/100</span>` : ''}
          <span class="risk-badge risk-${risk}">${risk}</span>
          ${r.risk_score ? policyBadgeHtml(r.risk_score.policy) : ''}
        </div>
      </div>
      <div class="resource-desc">${r.description}</div>
      <div class="resource-meta">
        <span class="px-2 py-0.5 rounded text-xs" style="background:#141c2e;color:#7a8ba3">${r.type}</span>
        <span class="px-2 py-0.5 rounded text-xs" style="background:#141c2e;color:#7a8ba3">${r.language}</span>
        <span class="text-gray-500">&#x2b50; ${(r.stars || 0).toLocaleString()}</span>
        ${mitreTags}
      </div>
      ${threatsHtml}
    </div>
  `;
}

// === Detail Panel ===
function selectResource(repo) {
  selectedResource = repo;
  const panel = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');
  panel.classList.remove('hidden');

  const risk = calcRiskLevel(repo);
  const threats = (repo.threat_ids || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
  const controls = (repo.control_ids || []).map(cid => DATA.controls.find(c => c.id === cid)).filter(Boolean);
  const papers = (repo.paper_ids || []).map(pid => DATA.papers.find(p => p.id === pid)).filter(Boolean);
  const gaps = findControlGaps(repo);
  const component = DATA.components.find(c => c.id === repo.layer);

  // Build detail
  content.innerHTML = `
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-lg font-bold">${repo.name}</h3>
      <button onclick="closeDetail()" class="text-gray-500 hover:text-gray-300 text-lg">&times;</button>
    </div>
    <span class="risk-badge risk-${risk} mb-3" style="display:inline-flex">${risk} risk</span>
    <p class="text-sm text-gray-400 mt-3 mb-4">${repo.description}</p>

    <!-- Meta -->
    <div class="detail-section">
      <div class="detail-section-title">Info</div>
      <div class="grid grid-cols-2 gap-2 text-sm">
        <div class="text-gray-500">Type</div><div>${repo.type}</div>
        <div class="text-gray-500">Layer</div><div>${component ? component.name : repo.layer}</div>
        <div class="text-gray-500">Language</div><div>${repo.language}</div>
        <div class="text-gray-500">Stars</div><div>&#x2b50; ${(repo.stars || 0).toLocaleString()}</div>
      </div>
    </div>

    <!-- Threats -->
    ${threats.length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">&#x26a0; Threats (${threats.length})</div>
      ${threats.map(t => `
        <div class="mb-3 p-3 rounded-lg" style="background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.1)">
          <div class="flex items-center gap-2 mb-1">
            <span class="severity-indicator" style="width:8px;height:8px;border-radius:50%;background:${severityColor(t.severity)}"></span>
            <span class="text-sm font-semibold">${t.name}</span>
            <span class="risk-badge risk-${t.severity}" style="font-size:0.6rem">${t.severity}</span>
          </div>
          <p class="text-xs text-gray-400 mb-2">${t.description}</p>
          <div class="text-xs text-gray-500">Kill Chain: <span class="text-gray-300">${t.kill_chain_phase.replace(/_/g, ' ')}</span></div>
          ${t.mitre_ids ? `<div class="mt-1">${t.mitre_ids.map(id => {
            const cls = id.startsWith('ATLAS') ? 'mitre-atlas' : id.startsWith('ATTACK') ? 'mitre-attack' : 'mitre-defend';
            return `<span class="mitre-badge ${cls}">${id}</span>`;
          }).join(' ')}</div>` : ''}
        </div>
      `).join('')}
    </div>
    ` : ''}

    <!-- Controls -->
    <div class="detail-section">
      <div class="detail-section-title">&#x1f6e1; Controls (${controls.length})</div>
      <div class="flex flex-wrap gap-1">
        ${controls.map(c => `<span class="control-badge" title="${c.description}">${c.name}</span>`).join('')}
      </div>
    </div>

    <!-- Control Gaps -->
    ${gaps.length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">&#x26a0; Control Gaps</div>
      ${gaps.map(g => `
        <div class="mb-2">
          <div class="text-xs font-semibold text-orange-400 mb-1">${g.threat.name}</div>
          <div class="flex flex-wrap gap-1">
            ${g.missing.map(cid => {
              const ctrl = DATA.controls.find(c => c.id === cid);
              return `<span class="control-gap-warning" style="font-size:0.65rem">${ctrl ? ctrl.name : cid}</span>`;
            }).join('')}
          </div>
        </div>
      `).join('')}
    </div>
    ` : `
    <div class="detail-section">
      <div class="text-xs text-green-400 flex items-center gap-1">&#x2705; All identified threats have corresponding controls</div>
    </div>
    `}

    <!-- Papers -->
    ${papers.length > 0 ? `
    <div class="detail-section">
      <div class="detail-section-title">&#x1f4c4; Related Papers (${papers.length})</div>
      ${papers.map(p => `
        <div class="mb-2">
          <div class="text-sm font-medium">${p.title}</div>
          <div class="flex items-center gap-2 mt-1">
            <span class="paper-type-badge paper-type-${p.type}">${p.type}</span>
            <span class="text-xs text-gray-500">${p.year}</span>
          </div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <!-- Links -->
    <div class="detail-section">
      <div class="detail-section-title">&#x1f517; Links</div>
      <a href="${repo.github_url}" target="_blank" class="detail-link">GitHub Repository &#x2197;</a>
    </div>
  `;

  // Highlight selected card
  document.querySelectorAll('.resource-card').forEach(card => {
    card.classList.toggle('selected', card.dataset.id === repo.id);
  });
}

function closeDetail() {
  selectedResource = null;
  document.getElementById('detail-panel').classList.add('hidden');
  document.querySelectorAll('.resource-card').forEach(c => c.classList.remove('selected'));
}

// === Security Tab ===
function renderSecurity() {
  // Threat Catalog
  document.getElementById('threat-catalog').innerHTML = DATA.threats.map(t => {
    const affected = DATA.repos.filter(r => (r.threat_ids || []).includes(t.id));
    const controlNames = (t.controls || []).map(cid => {
      const c = DATA.controls.find(ctrl => ctrl.id === cid);
      return c ? c.name : cid;
    });

    return `
      <div class="p-3 rounded-lg" style="border:1px solid #141c2e">
        <div class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="severity-indicator" style="width:8px;height:8px;border-radius:50%;background:${severityColor(t.severity)}"></span>
            <span class="font-semibold text-sm">${t.name}</span>
          </div>
          <span class="risk-badge risk-${t.severity}">${t.severity}</span>
        </div>
        <p class="text-xs text-gray-400 mb-2">${t.description}</p>
        <div class="text-xs text-gray-500 mb-1">Affected: <span class="text-gray-300">${affected.map(r => r.name.split('/').pop()).join(', ')}</span></div>
        <div class="text-xs text-gray-500 mb-1">Kill Chain: <span class="text-gray-300">${t.kill_chain_phase.replace(/_/g, ' ')}</span></div>
        <div class="flex flex-wrap gap-1 mt-2">
          ${(t.mitre_ids || []).map(id => {
            const cls = id.startsWith('ATLAS') ? 'mitre-atlas' : id.startsWith('ATTACK') ? 'mitre-attack' : 'mitre-defend';
            return `<span class="mitre-badge ${cls}">${id}</span>`;
          }).join('')}
        </div>
        <div class="flex flex-wrap gap-1 mt-2">
          ${controlNames.map(n => `<span class="control-badge">${n}</span>`).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Kill Chain
  const phases = (DATA.attacks.kill_chain || []).map(kc => ({
    id: kc.phase,
    name: kc.name,
    desc: kc.description
  }));

  document.getElementById('kill-chain').innerHTML = phases.map(phase => {
    const phaseThreats = DATA.threats.filter(t => t.kill_chain_phase === phase.id);
    return `
      <div class="kill-chain-phase">
        <div class="kill-chain-dot"></div>
        <div class="kill-chain-name">${phase.name}</div>
        <div class="text-xs text-gray-500 mb-2">${phase.desc}</div>
        <div class="flex flex-wrap gap-1">
          ${phaseThreats.map(renderThreatTag).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Control Catalog
  const controlCategories = [...new Set(DATA.controls.map(c => c.category))];
  document.getElementById('control-catalog').innerHTML = controlCategories.map(cat => {
    const catControls = DATA.controls.filter(c => c.category === cat);
    return `
      <div class="p-3 rounded-lg" style="border:1px solid #141c2e">
        <div class="text-xs font-bold text-gray-500 uppercase mb-2">${cat.replace(/_/g, ' ')}</div>
        ${catControls.map(c => {
          const mitigates = DATA.threats.filter(t => (t.controls || []).includes(c.id));
          return `
            <div class="mb-2">
              <div class="text-sm font-medium">${c.name}</div>
              <div class="text-xs text-gray-500">${c.description}</div>
              <div class="text-xs text-gray-500 mt-1">Mitigates: ${mitigates.map(t => t.name).join(', ') || 'N/A'}</div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }).join('');
}

function renderSecurityMatrix() {
  const matrixEl = document.getElementById('security-matrix');
  if (!matrixEl) return;

  const matrix = DATA.threats.map(t => {
    const neededControls = t.controls || [];
    const coveredControls = neededControls.filter(cid =>
      DATA.repos.some(r => (r.control_ids || []).includes(cid))
    );
    const gapControls = neededControls.filter(cid => !coveredControls.includes(cid));
    return { threat: t, needed: neededControls, covered: coveredControls, gaps: gapControls };
  });

  matrixEl.innerHTML = matrix.map(m => `
    <div class="p-3 rounded-lg" style="border:1px solid #141c2e">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          <span class="severity-indicator" style="width:8px;height:8px;border-radius:50%;background:${severityColor(m.threat.severity)}"></span>
          <span class="text-sm font-semibold">${m.threat.name}</span>
        </div>
        <span class="text-xs ${m.gaps.length > 0 ? 'text-orange-400' : 'text-green-400'}">${m.covered.length}/${m.needed.length} covered</span>
      </div>
      <div class="flex flex-wrap gap-1">
        ${m.needed.map(cid => {
          const ctrl = DATA.controls.find(c => c.id === cid);
          const isCovered = m.covered.includes(cid);
          return ctrl ? '<span class="' + (isCovered ? 'control-badge' : 'control-gap-warning') + '" style="font-size:0.7rem">' + ctrl.name + '</span>' : '';
        }).join('')}
      </div>
    </div>
  `).join('');
}

// === Research Tab ===
function renderResearch() {
  // Paper type filters
  const types = ['all', ...new Set(DATA.papers.map(p => p.type))];
  document.getElementById('paper-type-filters').innerHTML = types.map(t => `
    <button class="paper-filter-btn ${t === activePaperType ? 'active' : ''}" data-type="${t}">${t}</button>
  `).join('');

  document.querySelectorAll('.paper-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activePaperType = btn.dataset.type;
      renderResearch();
    });
  });

  // Paper list
  const filtered = activePaperType === 'all' ? DATA.papers : DATA.papers.filter(p => p.type === activePaperType);
  document.getElementById('paper-list').innerHTML = filtered.map(p => {
    const mappedThreats = (p.mapped_threats || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
    const mappedComps = (p.mapped_components || []).map(cid => DATA.components.find(c => c.id === cid)).filter(Boolean);

    return `
      <div class="paper-card">
        <div class="flex items-center gap-2 mb-2">
          <span class="paper-type-badge paper-type-${p.type}">${p.type}</span>
          <span class="text-xs text-gray-500">${p.year}</span>
        </div>
        <div class="font-semibold text-sm mb-2">${p.title}</div>
        <div class="flex flex-wrap gap-1 mb-2">
          ${(p.topic_tags || []).map(tag => `<span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${tag}</span>`).join('')}
        </div>
        <div class="text-xs text-gray-500">
          ${mappedComps.length > 0 ? `<div>Components: ${mappedComps.map(c => c.name).join(', ')}</div>` : ''}
          ${mappedThreats.length > 0 ? `<div class="mt-1">Threats: ${mappedThreats.map(t => `<span style="color:${severityColor(t.severity)}">${t.name}</span>`).join(', ')}</div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // Topic distribution
  const tagCounts = {};
  DATA.papers.forEach(p => (p.topic_tags || []).forEach(tag => {
    tagCounts[tag] = (tagCounts[tag] || 0) + 1;
  }));
  const sortedTags = Object.entries(tagCounts).sort((a, b) => b[1] - a[1]);
  const maxTagCount = sortedTags[0]?.[1] || 1;

  document.getElementById('topic-dist').innerHTML = sortedTags.map(([tag, count]) => `
    <div class="flex items-center gap-2">
      <span class="text-xs text-gray-400 w-28 truncate">${tag}</span>
      <div class="flex-1 progress-bar">
        <div class="progress-fill" style="width:${(count/maxTagCount*100)}%;background:#00e6a7"></div>
      </div>
      <span class="text-xs text-gray-500 w-4 text-right">${count}</span>
    </div>
  `).join('');

  // Paper-Component map
  const compPaperMap = {};
  DATA.papers.forEach(p => {
    (p.mapped_components || []).forEach(cid => {
      if (!compPaperMap[cid]) compPaperMap[cid] = [];
      compPaperMap[cid].push(p);
    });
  });

  document.getElementById('paper-component-map').innerHTML = Object.entries(compPaperMap).map(([cid, papers]) => {
    const comp = DATA.components.find(c => c.id === cid);
    return `
      <div class="p-2 rounded-lg" style="border:1px solid #141c2e">
        <div class="text-xs font-semibold mb-1">${comp ? comp.name : cid}</div>
        <div class="text-xs text-gray-500">${papers.map(p => p.title.split(':')[0].split(' ').slice(0, 3).join(' ')).join(', ')}</div>
        <div class="text-xs text-blue-400 mt-1">${papers.length} papers</div>
      </div>
    `;
  }).join('');
}

// === Global Search ===
function initSearch() {
  const input = document.getElementById('global-search');
  const dropdown = document.getElementById('search-results-dropdown');

  input.addEventListener('input', () => {
    const q = input.value.toLowerCase().trim();
    if (q.length < 2) {
      dropdown.classList.add('hidden');
      return;
    }

    const results = [];

    // Search repos
    DATA.repos.forEach(r => {
      const searchable = [r.name, r.description, r.category, r.language].join(' ').toLowerCase();
      if (searchable.includes(q)) {
        results.push({ type: 'repo', item: r, label: r.name, sub: r.description, icon: r.type === 'skill' ? '&#x1f9e9;' : '&#x1f4e6;' });
      }
    });

    // Search ecosystem repos
    (DATA.ecosystem.repos || []).forEach(r => {
      const searchable = [r.name, r.description, r.category, ...(r.tags || [])].join(' ').toLowerCase();
      if (searchable.includes(q)) {
        results.push({ type: 'ecosystem', item: r, label: r.name, sub: r.description, icon: '&#x1f99e;' });
      }
    });

    // Search skills
    (DATA.skills.top_skills || []).forEach(s => {
      const searchable = [s.name, s.description, s.category].join(' ').toLowerCase();
      if (searchable.includes(q)) {
        results.push({ type: 'skill', item: s, label: s.name, sub: s.description, icon: '&#x1f9e9;' });
      }
    });

    // Search threats
    DATA.threats.forEach(t => {
      if (t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)) {
        results.push({ type: 'threat', item: t, label: t.name, sub: t.description, icon: '&#x26a0;' });
      }
    });

    // Search papers
    DATA.papers.forEach(p => {
      if (p.title.toLowerCase().includes(q) || (p.topic_tags || []).some(tag => tag.includes(q))) {
        results.push({ type: 'paper', item: p, label: p.title, sub: p.type, icon: '&#x1f4c4;' });
      }
    });

    // Search controls
    DATA.controls.forEach(c => {
      if (c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)) {
        results.push({ type: 'control', item: c, label: c.name, sub: c.description, icon: '&#x1f6e1;' });
      }
    });

    // Search attack scenarios
    (DATA.attacks.scenarios || []).forEach(s => {
      const searchable = [s.name, s.description, s.category, ...(s.tags || [])].join(' ').toLowerCase();
      if (searchable.includes(q)) {
        results.push({ type: 'attack', item: s, label: s.name, sub: s.description, icon: '&#x1f4a5;' });
      }
    });

    // Search timeline events
    (DATA.timeline.events || []).forEach(e => {
      const searchable = [e.title, e.description, e.category, ...(e.issues || [])].join(' ').toLowerCase();
      if (searchable.includes(q)) {
        results.push({ type: 'timeline', item: e, label: `${e.date} — ${e.title}`, sub: e.description, icon: '&#x1f4c5;' });
      }
    });

    if (results.length === 0) {
      dropdown.innerHTML = '<div class="p-4 text-sm text-gray-500">No results found</div>';
    } else {
      dropdown.innerHTML = results.slice(0, 10).map((r, i) => `
        <div class="search-item" data-type="${r.type}" data-index="${i}">
          <div class="flex items-center gap-2">
            <span>${r.icon}</span>
            <div>
              <div class="text-sm font-medium">${highlightMatch(r.label, q)}</div>
              <div class="text-xs text-gray-500 truncate" style="max-width:400px">${r.sub}</div>
            </div>
          </div>
        </div>
      `).join('');

      // Click handlers
      dropdown.querySelectorAll('.search-item').forEach((el, i) => {
        el.addEventListener('click', () => {
          const result = results[i];
          dropdown.classList.add('hidden');
          input.value = '';
          handleSearchClick(result);
        });
      });
    }

    dropdown.classList.remove('hidden');
  });

  // Close dropdown on outside click
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#global-search') && !e.target.closest('#search-results-dropdown')) {
      dropdown.classList.add('hidden');
    }
  });
}

function highlightMatch(text, query) {
  const idx = text.toLowerCase().indexOf(query);
  if (idx === -1) return text;
  return text.slice(0, idx) + '<mark style="background:#fbbf24;color:#000;border-radius:2px;padding:0 1px">' + text.slice(idx, idx + query.length) + '</mark>' + text.slice(idx + query.length);
}

function handleSearchClick(result) {
  if (result.type === 'repo') {
    switchTab('directory');
    setTimeout(() => selectResource(result.item), 100);
  } else if (result.type === 'threat') {
    switchTab('security');
  } else if (result.type === 'paper') {
    switchTab('research');
  } else if (result.type === 'control') {
    switchTab('security');
  } else if (result.type === 'ecosystem') {
    switchTab('ecosystem');
  } else if (result.type === 'skill') {
    switchTab('skills');
  } else if (result.type === 'attack') {
    switchTab('attacks');
  } else if (result.type === 'timeline') {
    switchTab('timeline');
  }
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
  document.getElementById(`tab-${tabName}`).classList.remove('hidden');
}

function navigateToTab(tabName, options = {}) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  const btn = document.querySelector(`[data-tab="${tabName}"]`);
  if (btn) btn.classList.add('active');
  const tab = document.getElementById(`tab-${tabName}`);
  if (tab) tab.classList.remove('hidden');
  window.location.hash = tabName;

  if (options.highlightId) {
    setTimeout(() => {
      const el = document.getElementById(options.highlightId);
      if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.style.outline = '2px solid #00e6a7'; setTimeout(() => el.style.outline = '', 2000); }
    }, 200);
  }
}

function initHashRouting() {
  const hash = window.location.hash.slice(1);
  if (hash) {
    const btn = document.querySelector(`[data-tab="${hash}"]`);
    if (btn) btn.click();
  }
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      window.location.hash = btn.dataset.tab;
    });
  });
  window.addEventListener('hashchange', () => {
    const h = window.location.hash.slice(1);
    const btn = document.querySelector(`[data-tab="${h}"]`);
    if (btn && !btn.classList.contains('active')) btn.click();
  });
}

// === Dark Mode ===
function initDarkMode() {
  const btn = document.getElementById('btn-darkmode');
  const isLight = localStorage.getItem('theme') === 'light';
  if (isLight) document.body.classList.add('light');
  btn.textContent = isLight ? '☀️' : '🌙';

  btn.addEventListener('click', () => {
    document.body.classList.toggle('light');
    const nowLight = document.body.classList.contains('light');
    localStorage.setItem('theme', nowLight ? 'light' : 'dark');
    btn.textContent = nowLight ? '☀️' : '🌙';
  });
}

// =====================================================
// === Ecosystem Tab ===
// =====================================================

function initEcosystem() {
  // Sort buttons
  document.querySelectorAll('[data-ecosort]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-ecosort]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeEcoSort = btn.dataset.ecosort;
      renderEcosystem();
    });
  });

  // Search
  document.getElementById('eco-search').addEventListener('input', () => renderEcosystem());
}

function renderEcosystem() {
  const eco = DATA.ecosystem;
  const repos = eco.repos || [];
  const categories = eco.categories || [];

  // Stats
  document.getElementById('eco-stat-total').textContent = repos.length;
  document.getElementById('eco-stat-variants').textContent = repos.filter(r => r.category === 'lightweight' || r.category === 'hardware').length;
  document.getElementById('eco-stat-security').textContent = repos.filter(r => r.category === 'security-sandbox').length;
  document.getElementById('eco-stat-dashboards').textContent = repos.filter(r => r.category === 'control-monitoring' || r.category === 'cloud-hosted').length;

  // Dependency Network
  const depNet = eco.dependency_network;
  const depEl = document.getElementById('eco-dependency-network');
  if (depEl && depNet) {
    const depTypes = depNet.dependency_types || [];
    const supplyChain = depNet.supply_chain;
    const netChars = depNet.network_characteristics;

    depEl.innerHTML = `
      <div class="mb-4">
        <p class="text-xs text-gray-400 mb-4">${depNet.description}</p>
        <div class="grid grid-cols-1 md:grid-cols-5 gap-3 mb-6">
          ${depTypes.map(d => `
            <div class="p-3 rounded-lg text-center" style="border:1px solid #141c2e;background:#0a0e1a">
              <div class="text-xl mb-1">${d.icon}</div>
              <div class="text-xs font-semibold mb-1">${d.name}</div>
              <div class="text-xs text-gray-500 leading-relaxed">${d.description.split('.')[0]}</div>
            </div>
          `).join('')}
        </div>
      </div>
      ${supplyChain ? `
      <div class="mb-4">
        <div class="text-xs font-bold text-gray-500 uppercase mb-2">⚠ Supply Chain Attack Surface</div>
        <div class="flex items-center gap-2 flex-wrap mb-2">
          ${supplyChain.flow.map((step, i) => `
            <span class="text-xs px-3 py-1.5 rounded-lg font-semibold" style="background:#141c2e;color:#ffc312">${step}</span>
            ${i < supplyChain.flow.length - 1 ? '<span class="text-gray-600">→</span>' : ''}
          `).join('')}
        </div>
        <p class="text-xs text-orange-300">${supplyChain.risk}</p>
      </div>
      ` : ''}
      ${netChars ? `
      <div class="flex gap-4 flex-wrap">
        <div class="text-xs"><span class="text-gray-500">Topology:</span> <span class="font-semibold">${netChars.topology}</span></div>
        <div class="text-xs"><span class="text-gray-500">Properties:</span> <span class="font-semibold">${netChars.properties}</span></div>
        <div class="text-xs"><span class="text-gray-500">Hubs:</span> <span class="font-semibold">${netChars.hubs.join(', ')}</span></div>
      </div>
      ` : ''}
    `;
  }

  // Category filters
  const allCats = [{ id: 'all', name: 'All', icon: '📋', color: '#00e6a7' }, ...categories];
  document.getElementById('eco-category-filters').innerHTML = allCats.map(c => `
    <button class="eco-category-btn ${c.id === activeEcoCategory ? 'active' : ''}"
      data-ecocat="${c.id}"
      style="${c.id === activeEcoCategory ? 'background:' + c.color : ''}">
      ${c.icon} ${c.name}
    </button>
  `).join('');

  document.querySelectorAll('[data-ecocat]').forEach(btn => {
    btn.addEventListener('click', () => {
      activeEcoCategory = btn.dataset.ecocat;
      renderEcosystem();
    });
  });

  // Filter + search
  const query = document.getElementById('eco-search').value.toLowerCase().trim();
  let filtered = repos;
  if (activeEcoCategory !== 'all') {
    filtered = filtered.filter(r => r.category === activeEcoCategory);
  }
  if (query) {
    filtered = filtered.filter(r => {
      const s = [r.name, r.description, r.language, ...(r.tags || []), r.note || ''].join(' ').toLowerCase();
      return s.includes(query);
    });
  }

  // Sort
  filtered = [...filtered].sort((a, b) => {
    if (activeEcoSort === 'stars') return (b.stars || 0) - (a.stars || 0);
    if (activeEcoSort === 'name') return a.name.localeCompare(b.name);
    if (activeEcoSort === 'risk') {
      const ra = calcRiskLevel(a), rb = calcRiskLevel(b);
      return riskOrder(ra) - riskOrder(rb);
    }
    return 0;
  });

  document.getElementById('eco-result-count').textContent = `${filtered.length} repos`;

  // Render cards
  document.getElementById('eco-repo-list').innerHTML = filtered.map(r => {
    const cat = categories.find(c => c.id === r.category);
    const risk = calcRiskLevel(r);
    const threats = (r.threat_ids || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);

    return `
      <div class="eco-card" style="border-left-color:${cat ? cat.color : '#374151'}">
        <div class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span>${cat ? cat.icon : '📦'}</span>
            <span class="font-semibold text-sm">${r.name}</span>
          </div>
          ${risk !== 'none' ? `<span class="risk-badge risk-${risk}">${risk}</span>` : ''}
        </div>
        <p class="text-xs text-gray-400 mb-2 leading-relaxed">${r.description}</p>
        ${r.note ? `<p class="text-xs text-gray-500 mb-2 italic">${r.note}</p>` : ''}
        <div class="flex items-center gap-2 flex-wrap mb-2">
          ${r.language ? `<span class="eco-lang-badge">${r.language}</span>` : ''}
          ${r.stars > 0 ? `<span class="eco-stars">★ ${formatStars(r.stars)}</span>` : ''}
          ${(r.tags || []).slice(0, 4).map(tag => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:#141c2e;color:#5a6d84">${tag}</span>`).join('')}
        </div>
        ${threats.length > 0 ? `
        <div class="threats-section" style="margin-top:6px">
          <div class="threats-section-title">⚠ Known Threats (${threats.length})</div>
          <div class="flex flex-wrap">
            ${threats.map(renderThreatTag).join('')}
          </div>
        </div>
        ` : ''}
        <div class="mt-2">
          <a href="${r.url}" target="_blank" class="detail-link">GitHub →</a>
          ${r.category === 'skills-ecosystem' ? `
            <a href="#skills" onclick="navigateToTab('skills')" class="detail-link text-xs ml-3">Skills 탭 상세 →</a>
          ` : ''}
        </div>
      </div>
    `;
  }).join('');
}


function formatStars(n) {
  if (n >= 1000) return (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k';
  return n.toString();
}

// =====================================================
// === Skills Tab ===
// =====================================================

function initSkills() {
  // Sort buttons
  document.querySelectorAll('[data-skillsort]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-skillsort]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSkillSort = btn.dataset.skillsort;
      renderSkills();
    });
  });

  // Search
  document.getElementById('skill-search').addEventListener('input', () => renderSkills());
}

function renderSkills() {
  const skills = DATA.skills;
  const topSkills = skills.top_skills || [];
  const categories = skills.categories || [];

  // Stats
  document.getElementById('skill-stat-total').textContent = (skills.stats.total_clawhub || 0).toLocaleString();
  document.getElementById('skill-stat-curated').textContent = (skills.stats.curated_voltagen || 0).toLocaleString();
  document.getElementById('skill-stat-flagged').textContent = `${(skills.stats.flagged_malicious || 0)} (${skills.stats.flagged_percent || 0}%)`;
  document.getElementById('skill-stat-categories').textContent = skills.stats.categories_count || 0;

  // Security note
  document.getElementById('skill-security-note').textContent = skills.security_note || '';

  // Category sidebar
  const allCat = { id: 'all', name: 'All Categories', icon: '📋', count: topSkills.length };
  const catList = [allCat, ...categories];
  document.getElementById('skill-category-list').innerHTML = catList.map(c => {
    const isActive = c.id === activeSkillCategory;
    return `
      <div class="skill-cat-item ${isActive ? 'active' : ''}" data-skillcat="${c.id}">
        <span>${c.icon || '📦'}</span>
        <span class="flex-1 truncate">${c.name}</span>
        <span class="text-xs text-gray-500">${c.count}</span>
      </div>
    `;
  }).join('');

  document.querySelectorAll('[data-skillcat]').forEach(el => {
    el.addEventListener('click', () => {
      activeSkillCategory = el.dataset.skillcat;
      renderSkills();
    });
  });

  // ClawHub distribution
  const clawCats = skills.clawhub_categories || [];
  const maxClawCount = clawCats[0]?.count || 1;
  document.getElementById('clawhub-distribution').innerHTML = clawCats.map(c => `
    <div class="flex items-center gap-3">
      <span class="text-xs text-gray-400 w-24">${c.name}</span>
      <div class="flex-1 progress-bar">
        <div class="progress-fill" style="width:${(c.count / maxClawCount * 100)}%;background:#8b5cf6"></div>
      </div>
      <span class="text-xs text-gray-500 w-16 text-right">${c.count} (${c.percent}%)</span>
    </div>
  `).join('');

  // Filter + search skills
  const query = document.getElementById('skill-search').value.toLowerCase().trim();
  let filtered = topSkills;
  if (activeSkillCategory !== 'all') {
    filtered = filtered.filter(s => s.category === activeSkillCategory);
  }
  if (query) {
    filtered = filtered.filter(s => {
      return [s.name, s.description, s.category].join(' ').toLowerCase().includes(query);
    });
  }

  // Sort
  filtered = [...filtered].sort((a, b) => {
    if (activeSkillSort === 'downloads') return (b.downloads || 0) - (a.downloads || 0);
    if (activeSkillSort === 'name') return a.name.localeCompare(b.name);
    if (activeSkillSort === 'risk') return riskOrder(a.risk || 'none') - riskOrder(b.risk || 'none');
    return 0;
  });

  document.getElementById('skill-result-count').textContent = `${filtered.length} skills shown`;

  // Render skill list
  document.getElementById('skill-list').innerHTML = filtered.map((s, i) => {
    const threats = (s.threat_ids || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
    const catInfo = categories.find(c => c.id === s.category);
    const rank = i + 1;

    return `
      <div class="skill-item">
        <div class="skill-rank ${rank <= 3 ? 'top3' : ''}">${rank}</div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="font-semibold text-sm">${s.name}</span>
            ${s.risk_score ? `<span class="text-xs font-bold" style="color:${s.risk_score.total >= 80 ? '#ff4757' : s.risk_score.total >= 60 ? '#ff8c42' : s.risk_score.total >= 40 ? '#ffc312' : '#00e6a7'}">${s.risk_score.total}/100</span>` : ''}
            ${s.risk_score ? policyBadgeHtml(s.risk_score.policy) : (s.risk && s.risk !== 'low' ? `<span class="risk-badge risk-${s.risk}">${s.risk}</span>` : '')}
            ${catInfo ? `<span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${catInfo.icon} ${catInfo.name}</span>` : ''}
          </div>
          <p class="text-xs text-gray-400 mb-1">${s.description}</p>
          ${threats.length > 0 ? `
          <div class="flex flex-wrap gap-1">
            ${threats.map(renderThreatTag).join('')}
          </div>
          ` : ''}
        </div>
        <div class="text-right flex-shrink-0">
          <div class="skill-downloads">${(s.downloads || 0).toLocaleString()}</div>
          <div class="text-xs text-gray-500">downloads</div>
        </div>
      </div>
    `;
  }).join('');
}

// =====================================================
// === Attacks Tab ===
// =====================================================

function initAttacks() {
  document.getElementById('attack-search').addEventListener('input', () => renderAttacks());
}

function renderAttacks() {
  const atk = DATA.attacks;
  const scenarios = atk.scenarios || [];
  const surfaces = atk.attack_surfaces || [];
  const cves = atk.cves || [];
  const dist = atk.distribution || [];
  const killChain = atk.kill_chain || [];
  const refs = atk.references || [];
  const mitre = atk.mitre_mapping || [];
  const stats = atk.stats || {};

  // Stats
  document.getElementById('atk-stat-scenarios').textContent = stats.attack_scenarios || 0;
  document.getElementById('atk-stat-surfaces').textContent = stats.attack_surfaces || 0;
  document.getElementById('atk-stat-malicious').textContent = stats.malicious_skills || 0;
  document.getElementById('atk-stat-cves').textContent = stats.cves || 0;
  document.getElementById('atk-stat-vuln-rate').textContent = `${stats.vulnerability_rate_low || 0}-${stats.vulnerability_rate_high || 0}%`;

  // Attack Distribution
  const maxPct = Math.max(...dist.map(d => d.percent));
  document.getElementById('atk-distribution').innerHTML = dist.map(d => `
    <div class="flex items-center gap-3">
      <span class="text-xs text-gray-400 w-36">${d.category}</span>
      <div class="flex-1 progress-bar">
        <div class="progress-fill" style="width:${(d.percent / maxPct * 100)}%;background:${d.color}"></div>
      </div>
      <span class="text-xs font-semibold" style="color:${d.color};width:36px;text-align:right">${d.percent}%</span>
    </div>
  `).join('');

  // Kill Chain
  document.getElementById('atk-kill-chain').innerHTML = killChain.map(phase => {
    const phaseScenarios = scenarios.filter(s => s.phase === phase.phase);
    return `
      <div class="kill-chain-phase">
        <div class="kill-chain-dot"></div>
        <div class="kill-chain-name">${phase.name}</div>
        <div class="text-xs text-gray-500 mb-2">${phase.description}</div>
        <div class="flex flex-wrap gap-1">
          ${phaseScenarios.slice(0, 5).map(s => `
            <span class="threat-tag">
              <span class="severity-indicator" style="width:6px;height:6px;border-radius:50%;background:${severityColor(s.severity)}"></span>
              ${s.name}
            </span>
          `).join('')}
          ${phaseScenarios.length > 5 ? `<span class="text-xs text-gray-500">+${phaseScenarios.length - 5} more</span>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // CVEs
  document.getElementById('atk-cve-list').innerHTML = cves.map(c => `
    <div class="p-3 rounded-lg" style="border:1px solid #450a0a;background:rgba(239,68,68,0.05)">
      <div class="flex items-center justify-between mb-1">
        <span class="font-mono text-sm font-bold" style="color:#fca5a5">${c.id}</span>
        <span class="risk-badge risk-${c.severity}">${c.severity}</span>
      </div>
      <div class="text-sm font-semibold mb-1">${c.title}</div>
      <div class="text-xs text-gray-400 mb-1">${c.description}</div>
      <div class="text-xs text-gray-500">Source: ${c.reference}</div>
    </div>
  `).join('');

  // Attack Surfaces (7-layer)
  document.getElementById('atk-surfaces').innerHTML = surfaces.map(layer => {
    const critCount = layer.surfaces.filter(s => s.severity === 'critical').length;
    const highCount = layer.surfaces.filter(s => s.severity === 'high').length;
    return `
      <div class="p-3 rounded-lg" style="border:1px solid #141c2e">
        <div class="flex items-center justify-between mb-2">
          <div class="text-sm font-semibold">Layer ${layer.layer_num}: ${layer.layer}</div>
          <div class="flex gap-1">
            ${critCount > 0 ? `<span class="risk-badge risk-critical">${critCount} critical</span>` : ''}
            ${highCount > 0 ? `<span class="risk-badge risk-high">${highCount} high</span>` : ''}
          </div>
        </div>
        <div class="grid grid-cols-2 gap-1">
          ${layer.surfaces.map(s => `
            <div class="flex items-center gap-2 text-xs py-1">
              <span class="severity-indicator" style="width:6px;height:6px;border-radius:50%;background:${severityColor(s.severity)};flex-shrink:0"></span>
              <span class="text-gray-300">${s.name}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');

  // MITRE Mapping
  document.getElementById('atk-mitre-map').innerHTML = mitre.map(m => `
    <div class="flex items-center gap-2 text-xs py-1.5" style="border-bottom:1px solid #141c2e">
      <span class="w-28 text-gray-400 flex-shrink-0">${m.skill_type}</span>
      <span class="text-gray-600">&rarr;</span>
      <span class="w-32 text-gray-400 flex-shrink-0">${m.attack_vector}</span>
      <span class="text-gray-600">&rarr;</span>
      <span class="font-semibold text-gray-300">${m.technique}</span>
    </div>
  `).join('');

  // Phase + Category filter buttons
  const categories = ['all', ...new Set(scenarios.map(s => s.category))];
  const phases = ['all', ...new Set(scenarios.map(s => s.phase))];

  document.getElementById('atk-category-filters').innerHTML = categories.map(c => `
    <button class="paper-filter-btn ${c === activeAttackCategory ? 'active' : ''}" data-atkcat="${c}">${c.replace(/-/g, ' ')}</button>
  `).join('');

  document.getElementById('atk-phase-filters').innerHTML = phases.map(p => `
    <button class="paper-filter-btn ${p === activeAttackPhase ? 'active' : ''}" data-atkphase="${p}">${p.replace(/_/g, ' ')}</button>
  `).join('');

  document.querySelectorAll('[data-atkcat]').forEach(btn => {
    btn.addEventListener('click', () => { activeAttackCategory = btn.dataset.atkcat; renderAttacks(); });
  });
  document.querySelectorAll('[data-atkphase]').forEach(btn => {
    btn.addEventListener('click', () => { activeAttackPhase = btn.dataset.atkphase; renderAttacks(); });
  });

  // Filter scenarios
  const query = document.getElementById('attack-search').value.toLowerCase().trim();
  let filtered = scenarios;
  if (activeAttackCategory !== 'all') filtered = filtered.filter(s => s.category === activeAttackCategory);
  if (activeAttackPhase !== 'all') filtered = filtered.filter(s => s.phase === activeAttackPhase);
  if (query) {
    filtered = filtered.filter(s => [s.name, s.description, s.category, ...(s.tags || [])].join(' ').toLowerCase().includes(query));
  }

  document.getElementById('atk-scenario-count').textContent = `${filtered.length} scenarios`;

  // Render scenario list
  document.getElementById('atk-scenario-list').innerHTML = filtered.map(s => `
    <div class="p-3 rounded-lg" style="border:1px solid #141c2e">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">#${s.id}</span>
          <span class="text-sm font-semibold">${s.name}</span>
        </div>
        <span class="risk-badge risk-${s.severity}">${s.severity}</span>
      </div>
      <p class="text-xs text-gray-400 mb-2 leading-relaxed">${s.description}</p>
      <div class="flex items-center gap-2 flex-wrap">
        <span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${s.category.replace(/-/g, ' ')}</span>
        <span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${s.phase.replace(/_/g, ' ')}</span>
        ${s.reference ? `<span class="text-xs text-gray-500">&#x1f4ce; ${s.reference}</span>` : ''}
      </div>
      <div class="flex flex-wrap gap-1 mt-2">
        ${(s.tags || []).map(t => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:#0a0e1a;color:#5a6d84">${t}</span>`).join('')}
      </div>
      ${(s.control_ids || []).length > 0 ? `
        <div class="flex flex-wrap gap-1 mt-2">
          <span class="text-xs text-gray-500">Controls:</span>
          ${(s.control_ids || []).map(cid => {
            const ctrl = DATA.controls.find(c => c.id === cid);
            return ctrl ? '<span class="control-badge">' + ctrl.name + '</span>' : '';
          }).join('')}
        </div>
      ` : ''}
      ${(s.timeline_event_ids || []).length > 0 ? `
        <div class="mt-2">
          <a href="#timeline" onclick="navigateToTab('timeline')" class="detail-link text-xs">Timeline에서 보기 →</a>
        </div>
      ` : ''}
    </div>
  `).join('');

  // References
  document.getElementById('atk-references').innerHTML = refs.map(r => `
    <div class="flex items-center gap-2 text-xs py-1.5" style="border-bottom:1px solid #141c2e">
      <span class="font-semibold text-gray-300 w-36 flex-shrink-0">${r.source}</span>
      <span class="text-gray-400">${r.topic}</span>
    </div>
  `).join('');
}

// =====================================================
// === Timeline Tab ===
// =====================================================

function initTimeline() {
  document.getElementById('timeline-search').addEventListener('input', () => renderTimeline());
}

function timelineSeverityColor(sev) {
  return { critical: '#ff4757', high: '#ff8c42', medium: '#ffc312', low: '#00e6a7', info: '#00e6a7' }[sev] || '#5a6d84';
}

function timelineCategoryIcon(cat) {
  return { launch: '&#x1f680;', research: '&#x1f4d6;', vulnerability: '&#x1f41b;', incident: '&#x1f6a8;', attack: '&#x1f4a5;', cve: '&#x1f6d1;', audit: '&#x1f50d;' }[cat] || '&#x1f4cc;';
}

function renderTimeline() {
  const tl = DATA.timeline;
  const events = tl.events || [];
  const phases = tl.phases || [];
  const causes = tl.structural_causes || [];
  const stats = tl.stats || {};

  // Stats
  document.getElementById('tl-stat-events').textContent = stats.total_events || events.length;
  document.getElementById('tl-stat-growth').textContent = stats.framework_growth || '920%';
  document.getElementById('tl-stat-malicious').textContent = stats.malicious_skills_clawhavoc || 0;
  document.getElementById('tl-stat-vuln').textContent = stats.vulnerability_rate || '26-36%';

  // Evolution phases
  document.getElementById('tl-phases').innerHTML = phases.map(p => `
    <div class="flex-1 p-3 rounded-lg text-center" style="border:2px solid ${p.color};background:${p.color}11">
      <div class="text-lg font-bold" style="color:${p.color}">${p.year}</div>
      <div class="text-xs font-semibold mb-1">${p.name}</div>
      <div class="text-xs text-gray-500 leading-relaxed">${p.description}</div>
    </div>
  `).join('');

  // Structural causes
  document.getElementById('tl-causes').innerHTML = causes.map(c => `
    <div class="flex-1 p-3 rounded-lg" style="border:1px solid #7f1d1d;background:rgba(239,68,68,0.05)">
      <div class="text-sm font-semibold text-red-300 mb-1">${c.title}</div>
      <div class="text-xs text-gray-400">${c.description}</div>
    </div>
  `).join('');

  // Year + scope filter buttons
  const years = ['all', ...new Set(events.map(e => String(e.year)))];
  const scopes = ['all', ...new Set(events.map(e => e.scope))];

  document.getElementById('tl-year-filters').innerHTML = years.map(y => `
    <button class="paper-filter-btn ${y === activeTimelineYear ? 'active' : ''}" data-tlyear="${y}">${y}</button>
  `).join('');

  document.getElementById('tl-scope-filters').innerHTML = scopes.map(s => `
    <button class="paper-filter-btn ${s === activeTimelineScope ? 'active' : ''}" data-tlscope="${s}">${s.replace(/-/g, ' ')}</button>
  `).join('');

  document.querySelectorAll('[data-tlyear]').forEach(btn => {
    btn.addEventListener('click', () => { activeTimelineYear = btn.dataset.tlyear; renderTimeline(); });
  });
  document.querySelectorAll('[data-tlscope]').forEach(btn => {
    btn.addEventListener('click', () => { activeTimelineScope = btn.dataset.tlscope; renderTimeline(); });
  });

  // Filter events
  const query = document.getElementById('timeline-search').value.toLowerCase().trim();
  let filtered = events;
  if (activeTimelineYear !== 'all') filtered = filtered.filter(e => String(e.year) === activeTimelineYear);
  if (activeTimelineScope !== 'all') filtered = filtered.filter(e => e.scope === activeTimelineScope);
  if (query) {
    filtered = filtered.filter(e => [e.title, e.description, e.category, ...(e.issues || []), e.reference || ''].join(' ').toLowerCase().includes(query));
  }

  document.getElementById('tl-event-count').textContent = `${filtered.length} events`;

  // Year-grouped timeline
  const grouped = {};
  filtered.forEach(e => {
    if (!grouped[e.year]) grouped[e.year] = [];
    grouped[e.year].push(e);
  });

  const sortedYears = Object.keys(grouped).sort();
  document.getElementById('tl-event-list').innerHTML = sortedYears.map(year => {
    const phase = phases.find(p => p.year === year);
    const yearEvents = grouped[year];
    return `
      <div class="mb-6">
        <div class="flex items-center gap-3 mb-3">
          <div class="text-xl font-bold" style="color:${phase ? phase.color : '#00e6a7'}">${year}</div>
          ${phase ? `<span class="text-xs px-3 py-1 rounded-full font-semibold" style="background:${phase.color}22;color:${phase.color};border:1px solid ${phase.color}44">${phase.name}</span>` : ''}
          <span class="text-xs text-gray-500">${yearEvents.length} events</span>
        </div>
        <div class="space-y-2 pl-4" style="border-left:2px solid ${phase ? phase.color : '#374151'}">
          ${yearEvents.map(e => `
            <div class="p-3 rounded-lg relative" style="border:1px solid #141c2e">
              <div class="absolute -left-6 top-3 w-3 h-3 rounded-full" style="background:${timelineSeverityColor(e.severity)};border:2px solid #0a0e1a"></div>
              <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-mono text-gray-500">${e.date}</span>
                  <span>${timelineCategoryIcon(e.category)}</span>
                  <span class="text-sm font-semibold">${e.title}</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${e.scope.replace(/-/g, ' ')}</span>
                  ${e.severity !== 'info' ? `<span class="risk-badge risk-${e.severity}">${e.severity}</span>` : ''}
                </div>
              </div>
              <p class="text-xs text-gray-400 mb-2 leading-relaxed">${e.description}</p>
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs px-2 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${e.category}</span>
                ${(e.issues || []).map(t => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:#0a0e1a;color:#5a6d84">${t}</span>`).join('')}
                ${e.cvss ? `<span class="text-xs font-bold" style="color:#fca5a5">CVSS ${e.cvss}</span>` : ''}
                ${e.reference ? `<span class="text-xs text-gray-500">&#x1f4ce; ${e.reference}</span>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Year distribution chart
  const yearCounts = {};
  events.forEach(e => { yearCounts[e.year] = (yearCounts[e.year] || 0) + 1; });
  const maxYearCount = Math.max(...Object.values(yearCounts));
  document.getElementById('tl-year-dist').innerHTML = Object.entries(yearCounts).sort().map(([y, c]) => {
    const phase = phases.find(p => p.year === y);
    return `
      <div class="flex items-center gap-3">
        <span class="text-xs font-bold w-10" style="color:${phase ? phase.color : '#94a3b8'}">${y}</span>
        <div class="flex-1 progress-bar">
          <div class="progress-fill" style="width:${(c / maxYearCount * 100)}%;background:${phase ? phase.color : '#00e6a7'}"></div>
        </div>
        <span class="text-xs text-gray-500 w-8 text-right">${c}</span>
      </div>
    `;
  }).join('');

  // Severity distribution
  const sevCounts = {};
  events.forEach(e => { sevCounts[e.severity] = (sevCounts[e.severity] || 0) + 1; });
  document.getElementById('tl-severity-dist').innerHTML = Object.entries(sevCounts).sort((a, b) => {
    const ord = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (ord[a[0]] ?? 5) - (ord[b[0]] ?? 5);
  }).map(([sev, count]) => `
    <div class="flex items-center gap-3">
      <span class="risk-badge risk-${sev}" style="width:70px;justify-content:center">${sev}</span>
      <div class="flex-1 progress-bar">
        <div class="progress-fill" style="width:${(count / events.length * 100)}%;background:${timelineSeverityColor(sev)}"></div>
      </div>
      <span class="text-xs text-gray-500 w-8 text-right">${count}</span>
    </div>
  `).join('');
}

// =====================================================
// === Data Export ===
// =====================================================

function exportData(format, tabName) {
  let data, filename;
  switch(tabName) {
    case 'directory': data = DATA.repos; filename = 'openclaw-directory'; break;
    case 'ecosystem': data = DATA.ecosystem.repos; filename = 'openclaw-ecosystem'; break;
    case 'attacks': data = DATA.attacks.scenarios; filename = 'openclaw-attacks'; break;
    case 'timeline': data = DATA.timeline.events; filename = 'openclaw-timeline'; break;
    case 'skills': data = DATA.skills.top_skills; filename = 'openclaw-skills'; break;
    default: return;
  }

  if (format === 'csv') {
    if (!data || data.length === 0) return;
    const keys = Object.keys(data[0]);
    const csv = [keys.join(','), ...data.map(row => keys.map(k => {
      const v = row[k];
      const str = Array.isArray(v) ? v.join('; ') : (typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? ''));
      return '"' + str.replace(/"/g, '""') + '"';
    }).join(','))].join('\n');
    downloadFile(csv, filename + '.csv', 'text/csv');
  } else {
    downloadFile(JSON.stringify(data, null, 2), filename + '.json', 'application/json');
  }
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =====================================================
// === Social Tab ===
// =====================================================

function renderMoltbook() {
  const mb = DATA.moltbook;
  if (!mb || !mb.stats) return;

  const stats = mb.stats || {};
  const timeline = mb.timeline || [];
  const incidents = mb.security_incidents || [];
  const controversies = mb.controversies || [];
  const figures = mb.key_figures || [];
  const submolts = mb.submolts || [];
  const papers = mb.research_papers || [];
  const media = mb.media_coverage || [];
  const overview = mb.overview || {};

  // Stats
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('mb-stat-agents', stats.claimed_agents ? stats.claimed_agents.toLocaleString() : '-');
  el('mb-stat-humans', stats.actual_humans ? stats.actual_humans.toLocaleString() : '-');
  el('mb-stat-posts', stats.total_posts ? stats.total_posts.toLocaleString() : '-');
  el('mb-stat-incidents', incidents.length);
  el('mb-stat-submolts', stats.submolts ? stats.submolts.toLocaleString() : '-');
  el('mb-stat-leaked-keys', stats.exposed_api_keys ? stats.exposed_api_keys.toLocaleString() : '-');

  // Overview
  const overviewEl = document.getElementById('mb-overview');
  if (overviewEl) {
    overviewEl.innerHTML = `
      <p class="text-sm text-gray-300 mb-3">${overview.description || ''}</p>
      <p class="text-xs text-gray-400 italic mb-3">"${overview.tagline || ''}"</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div class="p-2 rounded" style="border:1px solid #141c2e">
          <div class="text-xs font-semibold mb-1" style="color:#00e6a7">Tech Stack</div>
          <div class="text-xs text-gray-400">${overview.tech_stack || ''}</div>
        </div>
        <div class="p-2 rounded" style="border:1px solid #141c2e">
          <div class="text-xs font-semibold mb-1" style="color:#00e6a7">Governance</div>
          <div class="text-xs text-gray-400">${overview.governance || ''}</div>
        </div>
      </div>
      <div class="flex items-center gap-4 mt-3 text-xs text-gray-500">
        <span>Launch: <strong class="text-gray-300">${stats.launch_date || ''}</strong></span>
        <span>Creator: <strong class="text-gray-300">${stats.creator || ''}</strong></span>
        <span>Agents/Human: <strong style="color:#ff8c42">${stats.agents_per_human || ''}</strong></span>
      </div>
    `;
  }

  // Timeline
  const timelineEl = document.getElementById('mb-timeline');
  if (timelineEl) {
    const sevColor = { critical: '#ff4757', high: '#ff8c42', medium: '#ffc312', info: '#00e6a7' };
    timelineEl.innerHTML = timeline.map(t => `
      <div class="flex gap-3 py-2" style="border-bottom:1px solid #0f1520">
        <div class="flex-shrink-0 w-2 rounded-full" style="background:${sevColor[t.severity] || '#5a6d84'}"></div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-0.5">
            <span class="text-xs font-mono text-gray-500 flex-shrink-0">${t.date}</span>
            <span class="text-xs font-semibold">${t.event}</span>
          </div>
          <div class="text-xs text-gray-400">${t.detail}</div>
        </div>
      </div>
    `).join('');
  }

  // Security Incidents
  const incEl = document.getElementById('mb-incidents');
  if (incEl) {
    incEl.innerHTML = incidents.map(inc => `
      <div class="p-3 rounded-lg mb-3" style="border:1px solid ${inc.severity === 'critical' ? '#450a0a' : '#141c2e'};background:${inc.severity === 'critical' ? 'rgba(239,68,68,0.05)' : 'transparent'}">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm font-bold">${inc.title}</span>
          <span class="risk-badge risk-${inc.severity}">${inc.severity}</span>
        </div>
        <div class="text-xs text-gray-500 mb-2">${inc.date} | ${inc.discoverer}</div>
        <p class="text-xs text-gray-400 mb-2 leading-relaxed">${inc.description}</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
          <div class="text-xs"><span class="text-gray-500">Root Cause:</span> <span class="text-gray-300">${inc.root_cause}</span></div>
          <div class="text-xs"><span class="text-gray-500">Resolution:</span> <span class="text-gray-300">${inc.resolution}</span></div>
        </div>
        <div class="text-xs font-semibold mt-2" style="color:#ff8c42">${inc.impact}</div>
        <div class="text-xs text-gray-500 mt-1">${(inc.references || []).join(', ')}</div>
      </div>
    `).join('');
  }

  // Controversies
  const contEl = document.getElementById('mb-controversies');
  if (contEl) {
    const sevIcon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    contEl.innerHTML = controversies.map(c => `
      <div class="p-3 rounded-lg mb-3" style="border:1px solid #141c2e">
        <div class="flex items-center gap-2 mb-2">
          <span>${sevIcon[c.severity] || '⚪'}</span>
          <span class="text-sm font-bold">${c.title}</span>
          <span class="risk-badge risk-${c.severity}">${c.severity}</span>
        </div>
        <p class="text-xs text-gray-400 leading-relaxed">${c.description}</p>
        <div class="text-xs text-gray-500 mt-2">${(c.sources || []).join(', ')}</div>
      </div>
    `).join('');
  }

  // Submolts
  const subEl = document.getElementById('mb-submolts');
  if (subEl) {
    const riskColor = { high: '#ff4757', medium: '#ffc312', low: '#00e6a7' };
    subEl.innerHTML = submolts.map(s => `
      <div class="flex items-center gap-3 py-2" style="border-bottom:1px solid #0f1520">
        <code class="text-xs font-bold" style="color:#00e6a7">${s.name}</code>
        <span class="text-xs text-gray-400 flex-1">${s.description}</span>
        <span class="w-2 h-2 rounded-full flex-shrink-0" style="background:${riskColor[s.risk] || '#5a6d84'}"></span>
      </div>
    `).join('');
  }

  // Key Figures
  const figEl = document.getElementById('mb-figures');
  if (figEl) {
    const roleColor = { 'Creator/CEO': '#00e6a7', Endorser: '#3b82f6', Critic: '#ff4757', Debunker: '#ff8c42', 'Security Researcher': '#ffc312' };
    figEl.innerHTML = figures.map(f => `
      <div class="flex items-center gap-3 p-2 rounded-lg" style="border:1px solid #141c2e">
        <div class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style="background:#141c2e;color:${roleColor[f.role] || '#00e6a7'}">
          ${f.name.charAt(0)}
        </div>
        <div>
          <div class="text-sm font-semibold">${f.name} <span class="text-xs font-normal" style="color:${roleColor[f.role] || '#7a8ba3'}">${f.role}</span></div>
          <div class="text-xs text-gray-400">${f.note}</div>
        </div>
      </div>
    `).join('');
  }

  // Research Papers
  const papEl = document.getElementById('mb-papers');
  if (papEl) {
    papEl.innerHTML = papers.map(p => `
      <div class="py-2" style="border-bottom:1px solid #0f1520">
        <a href="https://arxiv.org/abs/${p.arxiv_id}" target="_blank" class="text-xs font-semibold detail-link">${p.title}</a>
        <div class="text-xs text-gray-400 mt-0.5">${p.finding}</div>
      </div>
    `).join('');
  }

  // Media Coverage
  const medEl = document.getElementById('mb-media');
  if (medEl) {
    const toneColor = { critical: '#ff4757', negative: '#ff8c42', mixed: '#ffc312', neutral: '#94a3b8' };
    medEl.innerHTML = media.map(m => `
      <div class="flex items-center gap-2 py-1.5" style="border-bottom:1px solid #0f1520">
        <span class="w-2 h-2 rounded-full flex-shrink-0" style="background:${toneColor[m.tone] || '#94a3b8'}"></span>
        <span class="text-xs font-semibold text-gray-300 w-24 flex-shrink-0">${m.source}</span>
        <span class="text-xs text-gray-400 flex-1">${m.title}</span>
        <span class="text-xs text-gray-500 w-20 text-right">${m.date}</span>
      </div>
    `).join('');
  }
}

function renderBasic() {
  const basic = DATA.basic;
  if (!basic || !basic.releases) return;

  const releases = basic.releases || [];
  const naming = basic.naming_evolution || [];
  const wsFiles = basic.workspace_files || [];
  const memory = basic.memory_system || {};
  const arch = basic.architecture || {};
  const commands = basic.cli_commands || [];
  const providers = basic.supported_providers || [];
  const channels = basic.supported_channels || [];
  const stats = basic.stats || {};

  // Stats
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('basic-stat-releases', stats.total_releases || releases.length);
  el('basic-stat-version', stats.latest_version || 'N/A');
  el('basic-stat-providers', stats.supported_providers || providers.length);
  el('basic-stat-channels', stats.supported_channels || channels.length);

  // Naming Evolution
  const namingEl = document.getElementById('basic-naming-evolution');
  if (namingEl) {
    namingEl.innerHTML = naming.map((n, i) => `
      <div class="flex items-center gap-4 p-3 rounded-lg" style="border:1px solid #141c2e;background:${i === naming.length - 1 ? 'rgba(0,230,167,0.05)' : 'transparent'}">
        <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold" style="background:${i === naming.length - 1 ? '#00e6a7' : '#141c2e'};color:${i === naming.length - 1 ? '#0a0e1a' : '#00e6a7'}">${i + 1}</div>
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-1">
            <span class="font-bold text-base">${n.name}</span>
            <span class="text-xs px-2 py-0.5 rounded font-mono" style="background:#141c2e;color:#7a8ba3">${n.versions}</span>
          </div>
          <div class="text-xs text-gray-400">${n.period}</div>
          <div class="text-xs text-gray-500 mt-1">${n.note}</div>
        </div>
      </div>
    `).join('');
  }

  // Workspace Files
  const wsEl = document.getElementById('basic-workspace-files');
  if (wsEl) {
    const catIcon = { config: '⚙️', memory: '🧠', workspace: '📁' };
    wsEl.innerHTML = wsFiles.map(f => `
      <div class="flex items-start gap-3 p-2 rounded-lg" style="border:1px solid #141c2e">
        <span class="text-lg flex-shrink-0">${catIcon[f.category] || '📄'}</span>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <code class="text-sm font-bold" style="color:#00e6a7">${f.file}</code>
            <span class="text-xs px-1.5 py-0.5 rounded" style="background:#141c2e;color:#7a8ba3">${f.category}</span>
          </div>
          <div class="text-xs text-gray-400 mt-1">${f.description}</div>
          ${f.security_note ? `<div class="text-xs mt-1" style="color:#ff8c42">⚠ ${f.security_note}</div>` : ''}
        </div>
      </div>
    `).join('');
  }

  // Memory System
  const memEl = document.getElementById('basic-memory-system');
  if (memEl && memory.layers) {
    const layers = memory.layers || [];
    const search = memory.search || {};
    const flush = memory.flush || {};
    const rules = memory.security_rules || [];
    memEl.innerHTML = `
      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2" style="color:#00e6a7">2-Layer Architecture</h4>
        ${layers.map(l => `
          <div class="flex items-center gap-3 p-2 rounded mb-2" style="border:1px solid #141c2e">
            <div class="w-8 h-8 rounded flex items-center justify-center font-bold text-sm" style="background:#141c2e;color:#00e6a7">L${l.layer}</div>
            <div>
              <div class="text-sm"><code class="font-semibold" style="color:#00d4aa">${l.file}</code> — ${l.scope}</div>
              <div class="text-xs text-gray-400">${l.load_timing} | ${l.content}</div>
            </div>
          </div>
        `).join('')}
      </div>
      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2" style="color:#00e6a7">Hybrid Search</h4>
        <div class="text-xs text-gray-400 mb-2">${(search.engines || []).join(' + ')}</div>
        <div class="flex gap-2 mb-2">
          <span class="text-xs px-2 py-1 rounded" style="background:#141c2e;color:#00e6a7">Vector: ${(search.vector_weight * 100) || 70}%</span>
          <span class="text-xs px-2 py-1 rounded" style="background:#141c2e;color:#ffc312">Text: ${(search.text_weight * 100) || 30}%</span>
        </div>
        <div class="text-xs text-gray-500">Providers: ${(search.embedding_providers || []).join(', ')}</div>
      </div>
      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2" style="color:#00e6a7">Auto Flush</h4>
        <div class="text-xs text-gray-400">${flush.trigger || ''}</div>
        <div class="text-xs text-gray-500 mt-1">${flush.action || ''}</div>
      </div>
      <div>
        <h4 class="text-sm font-semibold mb-2 text-red-400">Security Rules</h4>
        <div class="space-y-1">
          ${rules.map(r => `<div class="text-xs text-gray-400">• ${r}</div>`).join('')}
        </div>
      </div>
    `;
  }

  // Architecture
  const archEl = document.getElementById('basic-architecture');
  if (archEl && arch.components) {
    archEl.innerHTML = (arch.components || []).map(c => `
      <div class="flex items-start gap-3 p-2 rounded-lg" style="border:1px solid #141c2e">
        <div class="w-8 h-8 rounded flex items-center justify-center text-xs font-bold flex-shrink-0" style="background:#141c2e;color:#00e6a7">▶</div>
        <div>
          <div class="text-sm font-semibold">${c.name} <span class="text-xs text-gray-500 font-normal font-mono">${c.introduced}</span></div>
          <div class="text-xs text-gray-400 mt-1">${c.description}</div>
        </div>
      </div>
    `).join('');
  }

  // CLI Commands
  const cliEl = document.getElementById('basic-cli-commands');
  if (cliEl) {
    cliEl.innerHTML = commands.map(c => `
      <div class="flex items-start gap-3 py-1.5" style="border-bottom:1px solid #0f1520">
        <code class="text-xs font-mono flex-shrink-0" style="color:#00e6a7;min-width:260px">${c.command}</code>
        <span class="text-xs text-gray-400">${c.description}</span>
      </div>
    `).join('');
  }

  // Providers & Channels
  const provEl = document.getElementById('basic-providers');
  if (provEl) {
    provEl.innerHTML = providers.map(p => `
      <div class="flex items-center justify-between py-1.5" style="border-bottom:1px solid #0f1520">
        <span class="text-xs font-semibold">${p.name}</span>
        <div class="flex items-center gap-2">
          <span class="text-xs text-gray-400">${p.models}</span>
          <span class="text-xs font-mono text-gray-500">${p.since}</span>
        </div>
      </div>
    `).join('');
  }

  const chanEl = document.getElementById('basic-channels');
  if (chanEl) {
    chanEl.innerHTML = channels.map(c => `
      <div class="py-2" style="border-bottom:1px solid #0f1520">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold">${c.name}</span>
          <span class="text-xs font-mono text-gray-500">${c.since}</span>
        </div>
        <div class="text-xs text-gray-400 mt-0.5">${c.features}</div>
      </div>
    `).join('');
  }

  // Release History
  const relEl = document.getElementById('basic-release-list');
  if (relEl) {
    const catColor = { major: '#00e6a7', security: '#ff4757', feature: '#3b82f6', fix: '#ffc312', initial: '#a855f7' };
    const catLabel = { major: 'Major', security: 'Security', feature: 'Feature', fix: 'Fix', initial: 'Initial' };
    relEl.innerHTML = releases.map(r => `
      <div class="p-3 rounded-lg mb-2" style="border:1px solid #141c2e">
        <div class="flex items-center justify-between mb-2">
          <div class="flex items-center gap-2">
            <span class="text-sm font-bold font-mono" style="color:#00e6a7">v${r.version}</span>
            <span class="text-xs px-1.5 py-0.5 rounded font-semibold" style="background:${catColor[r.category] || '#141c2e'}22;color:${catColor[r.category] || '#94a3b8'};border:1px solid ${catColor[r.category] || '#141c2e'}44">${catLabel[r.category] || r.category}</span>
            <span class="text-xs text-gray-500">${r.name}</span>
          </div>
          <span class="text-xs font-mono text-gray-500">${r.date}</span>
        </div>
        <ul class="space-y-0.5">
          ${r.highlights.map(h => `<li class="text-xs text-gray-400">• ${h}</li>`).join('')}
        </ul>
      </div>
    `).join('');
  }
}
