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

// === State (consolidated global variables) ===
const STATE = {
  selectedResource: null,
  activeFilters: {},
  currentSort: 'risk',
  papers: { type: 'all' },
  eco: { category: 'all', sort: 'stars' },
  skills: { category: 'all', sort: 'downloads' },
  attacks: { category: 'all', phase: 'all' },
  timeline: { year: 'all', scope: 'all' },
  arch: { viewMode: 'structure' }
};

// Legacy aliases for backward compatibility during migration
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
let archViewMode = 'structure';

// === Utilities ===

// 7.1: XSS Prevention — escape HTML entities in user/data strings
function escapeHtml(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// 7.4: Debounce — delay execution until input pauses
function debounce(fn, delay) {
  let timer;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

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
  renderArchitecture();
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
      switchTab(btn.dataset.tab);
    });
  });
}

// === Risk Calculation ===
function calcRiskLevel(repo) {
  // If repo has risk_score.level, use it directly
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

  if (!repo.control_ids || repo.control_ids.length === 0) {
    // No control info (ecosystem repos)
    if (hasCritical) return 'high';
    if (hasHigh) return 'medium';
    return 'low';
  }

  // With control gap analysis
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
  return `<span class="threat-tag"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:${severityColor(threat.severity)}"></span> ${threat.name}</span>`;
}

function renderThreatTags(threatIds) {
  return (threatIds || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean).map(renderThreatTag).join('');
}

var ecoPageSize = 60;
var ecoCurrentPage = 0;

function paginatedRender(containerId, items, renderItemFn, pageSize) {
  pageSize = pageSize || 60;
  var container = document.getElementById(containerId);
  if (!container) return;
  var total = items.length;
  var pages = Math.ceil(total / pageSize);
  var page = Math.min(ecoCurrentPage, pages - 1);
  if (page < 0) page = 0;
  ecoCurrentPage = page;
  var start = page * pageSize;
  var end = Math.min(start + pageSize, total);
  container.innerHTML = items.slice(start, end).map(renderItemFn).join('');
  // Pagination controls
  if (pages > 1) {
    var nav = '<div class="flex items-center justify-center gap-2 mt-4">';
    nav += '<button onclick="ecoCurrentPage=0;renderEcosystem()" class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:pointer" ' + (page === 0 ? 'disabled style="opacity:0.4;background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:default"' : '') + '>«</button>';
    nav += '<button onclick="ecoCurrentPage=Math.max(0,ecoCurrentPage-1);renderEcosystem()" class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:pointer" ' + (page === 0 ? 'disabled style="opacity:0.4;background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:default"' : '') + '>‹</button>';
    nav += '<span class="text-xs text-gray-400">' + (page + 1) + ' / ' + pages + ' (' + total + ' repos)</span>';
    nav += '<button onclick="ecoCurrentPage=Math.min(' + (pages-1) + ',ecoCurrentPage+1);renderEcosystem()" class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:pointer" ' + (page >= pages - 1 ? 'disabled style="opacity:0.4;background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:default"' : '') + '>›</button>';
    nav += '<button onclick="ecoCurrentPage=' + (pages-1) + ';renderEcosystem()" class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:pointer" ' + (page >= pages - 1 ? 'disabled style="opacity:0.4;background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3);cursor:default"' : '') + '>»</button>';
    nav += '</div>';
    container.insertAdjacentHTML('afterend', '<div id="' + containerId + '-pagination">' + nav + '</div>');
    var oldPag = document.getElementById(containerId + '-pagination');
    if (oldPag && oldPag.previousElementSibling !== container) oldPag.remove();
  }
  var existingPag = document.getElementById(containerId + '-pagination');
  if (existingPag && pages <= 1) existingPag.remove();
}

function fuzzySearch(items, query, fields) {
  if (!query || !query.trim()) return items;
  const q = query.toLowerCase().trim();
  return items.filter(item => {
    return fields.some(f => {
      const v = item[f];
      const str = Array.isArray(v) ? v.join(' ') : String(v || '');
      return str.toLowerCase().includes(q);
    });
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

// === Filter Bar Helper (Task 3) ===
function renderFilterBar(containerId, filters, activeFilter, onFilterChange, options) {
  options = options || {};
  const el = document.getElementById(containerId);
  if (!el) return;

  let html = '<div class="filter-bar">';
  filters.forEach(function(f) {
    var id = typeof f === 'string' ? f : f.id;
    var label = typeof f === 'string' ? f : (f.label || f.id);
    var count = typeof f === 'object' ? f.count : null;
    var isActive = id === activeFilter;
    html += '<button class="filter-btn' + (isActive ? ' active' : '') + '" data-filter="' + id + '">';
    html += label;
    if (count !== null && count !== undefined) {
      html += '<span class="filter-count">' + count + '</span>';
    }
    html += '</button>';
  });
  if (options.searchHint) {
    html += '<span class="search-hint">' + options.searchHint + '</span>';
  }
  html += '</div>';
  el.innerHTML = html;

  el.querySelectorAll('[data-filter]').forEach(function(btn) {
    btn.onclick = function() {
      onFilterChange(btn.dataset.filter);
    };
  });
}

// === Overview ===
function renderOverview() {
  var container = document.getElementById('tab-overview');
  if (!container) return;

  var ecoRepos = (DATA.ecosystem.repos || []).length;
  var skillCount = DATA.skills.stats?.total_clawhub || 0;
  var cveCount = (DATA.attacks.cves || []).length;
  var scenarioCount = (DATA.attacks.scenarios || []).length;
  var eventCount = (DATA.timeline.events || DATA.timeline || []).length;
  var malicious = DATA.skills.stats?.flagged_malicious || 0;
  var malPct = DATA.skills.stats?.flagged_percent || 0;
  var controlCount = DATA.controls.length;
  var threatCount = DATA.threats.length;

  // Risk distribution calc
  var riskCounts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
  DATA.repos.forEach(function(r) { riskCounts[calcRiskLevel(r)]++; });
  var total = DATA.repos.length;

  // Top threats
  var threatRanked = DATA.threats.map(function(t) {
    return { threat: t, count: DATA.repos.filter(function(r) { return (r.threat_ids || []).includes(t.id); }).length };
  }).sort(function(a, b) { return b.count - a.count; }).slice(0, 6);

  // Recent events
  var recentEvents = (DATA.timeline.events || DATA.timeline || [])
    .slice().sort(function(a, b) { return (b.date || '').localeCompare(a.date || ''); })
    .slice(0, 7);

  // Top risks from repos
  var topRisks = (DATA.repos || [])
    .filter(function(r) { return r.risk_score; })
    .sort(function(a, b) { return (b.risk_score.total || 0) - (a.risk_score.total || 0); })
    .slice(0, 5);

  // Control coverage
  var totalGaps = DATA.repos.reduce(function(sum, r) { return sum + findControlGaps(r).length; }, 0);
  var coveredRepos = DATA.repos.filter(function(r) { return findControlGaps(r).length === 0; }).length;
  var coveragePct = total > 0 ? Math.round(coveredRepos / total * 100) : 100;

  // Skill safety
  var totalS = skillCount;
  var flaggedS = malicious;
  var safeP = totalS > 0 ? ((totalS - flaggedS) / totalS * 100).toFixed(1) : '100.0';

  // CVE severity breakdown
  var cveCritical = (DATA.attacks.cves || []).filter(function(c) { return c.severity === 'critical'; }).length;
  var cveHigh = (DATA.attacks.cves || []).filter(function(c) { return c.severity === 'high'; }).length;

  // Zone threat count for nav
  var zoneThreatCount = new Set(DATA.repos.flatMap(function(r) { return r.threat_ids || []; })).size;

  // Build HTML
  var html = '';

  // === 1a. Executive Summary Banner ===
  html += '<div class="dash-card" style="border-left: 4px solid var(--risk-critical, #f97316); margin-bottom: 1.5rem;">';
  html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
  html += '<div>';
  html += '<div style="font-size: 1.1rem; font-weight: 700; color: var(--text-primary, #e2e8f0);">';
  html += '&#x26a0;&#xfe0f; OpenClaw Ecosystem Security Status: <span style="color: #f97316;">HIGH RISK</span>';
  html += '</div>';
  html += '<div style="font-size: 0.8rem; color: var(--text-secondary, #94a3b8); margin-top: 0.25rem;">';
  html += 'Last updated: ' + (DATA.moltbook?.stats?.data_as_of || '2026-03-10') + ' &middot; ';
  html += cveCount + ' Active CVEs &middot; ';
  html += scenarioCount + ' Attack Scenarios &middot; ';
  html += eventCount + ' Security Events';
  html += '</div>';
  html += '</div>';
  html += '<div style="text-align: right;">';
  html += '<div style="font-size: 2rem; font-weight: 800; color: #ef4444;">' + cveCount + '</div>';
  html += '<div style="font-size: 0.7rem; color: var(--text-muted, #64748b);">Active CVEs</div>';
  html += '</div>';
  html += '</div>';
  html += '</div>';

  // === Security Alert Banner ===
  html += '<div id="overview-alert" class="mb-6 rounded-xl overflow-hidden" style="background:linear-gradient(135deg, #1a0a12 0%, #2a0a1a 40%, #1a0f20 100%);border:1px solid #4a1525;box-shadow:0 4px 24px rgba(255,50,80,0.08)">';
  html += '<div class="px-5 py-3 flex items-center gap-3" style="background:linear-gradient(90deg, rgba(255,75,100,0.12) 0%, rgba(255,75,100,0.04) 100%);border-bottom:1px solid #3a1020">';
  html += '<span class="flex items-center justify-center w-7 h-7 rounded-lg" style="background:rgba(255,75,100,0.15);color:#ff5a72;font-size:14px">&#x26a0;</span>';
  html += '<span class="font-bold text-sm tracking-wide" style="color:#ff8a9a">Security Alerts</span>';
  html += '<span id="overview-alert-count" class="text-xs font-bold px-2 py-0.5 rounded-full" style="background:rgba(255,75,100,0.2);color:#ff7a8e;margin-left:auto"></span>';
  html += '</div>';
  html += '<div id="overview-alert-content" class="px-5 py-3 space-y-2"></div>';
  html += '</div>';

  // === 1b. Key Metrics Grid ===
  var metrics = [
    { label: 'Ecosystem Repos', value: ecoRepos, color: '#00e6a7', tab: 'ecosystem', trend: ecoRepos + '+ projects' },
    { label: 'ClawHub Skills', value: skillCount.toLocaleString(), color: malicious > 0 ? '#ff8c42' : '#00e6a7', tab: 'skills', trend: malicious > 0 ? '&#x26a0; ' + malicious + ' malicious' : 'All verified' },
    { label: 'Active CVEs', value: cveCount, color: '#ef4444', tab: 'attacks', trend: cveCritical + ' critical, ' + cveHigh + ' high' },
    { label: 'Attack Scenarios', value: scenarioCount, color: '#ff6b7a', tab: 'attacks', trend: scenarioCount + ' documented' },
    { label: 'Security Controls', value: controlCount, color: '#00e6a7', tab: 'security', trend: coveragePct + '% coverage' },
    { label: 'Known Threats', value: threatCount, color: '#ffc312', tab: 'security', trend: riskCounts.critical + ' critical threats' }
  ];

  html += '<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">';
  metrics.forEach(function(m) {
    html += '<div class="dash-card clickable" style="text-align:center;" onclick="navigateToTab(\'' + m.tab + '\')">';
    html += '<div style="font-size:1.8rem;font-weight:700;color:' + m.color + '">' + m.value + '</div>';
    html += '<div class="text-xs text-gray-400" style="margin-top:4px">' + m.label + '</div>';
    html += '<div style="font-size:0.7rem;color:var(--text-secondary,#5a6d84);margin-top:6px">' + m.trend + '</div>';
    html += '</div>';
  });
  html += '</div>';

  // === Risk + Recent Events row ===
  html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">';

  // Risk Distribution
  html += '<div class="dash-card">';
  html += '<h3 class="card-title">Risk Distribution</h3>';
  html += '<div id="risk-distribution" class="space-y-3"></div>';
  html += '</div>';

  // 1c. Recent Activity Feed
  html += '<div class="dash-card">';
  html += '<div class="flex items-center justify-between mb-4">';
  html += '<h3 class="card-title mb-0">Recent Security Events</h3>';
  html += '<a href="#timeline" onclick="navigateToTab(\'timeline\')" class="detail-link text-xs">View All &#x2192;</a>';
  html += '</div>';
  html += '<div class="space-y-3">';
  recentEvents.forEach(function(e) {
    var sevClass = e.severity === 'critical' ? 'critical' : e.severity === 'high' ? 'high' : 'medium';
    html += '<div class="flex items-center gap-3">';
    html += '<span class="risk-dot risk-' + sevClass + '"></span>';
    html += '<span class="text-xs text-gray-500 w-20 flex-shrink-0">' + (e.date || '') + '</span>';
    html += '<span class="text-sm flex-1">' + (e.title || '') + '</span>';
    if (e.severity && e.severity !== 'info') {
      html += '<span class="risk-badge risk-' + e.severity + '" style="font-size:0.65rem;padding:2px 6px">' + e.severity + '</span>';
    }
    html += '</div>';
  });
  html += '</div>';
  html += '</div>';

  html += '</div>'; // end grid

  // === Threats + Attack Distribution row ===
  html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">';

  html += '<div class="dash-card">';
  html += '<h3 class="card-title">Top Threats by Affected Items</h3>';
  html += '<div id="top-threats" class="space-y-3"></div>';
  html += '</div>';

  html += '<div class="dash-card">';
  html += '<div class="flex items-center justify-between mb-4">';
  html += '<h3 class="card-title mb-0">Attack Distribution</h3>';
  html += '<a href="#attacks" onclick="navigateToTab(\'attacks\')" class="detail-link text-xs">Full Analysis &#x2192;</a>';
  html += '</div>';
  html += '<div id="overview-attack-dist" class="space-y-3"></div>';
  html += '</div>';

  html += '</div>';

  // === 1e. Top Risks Summary ===
  if (topRisks.length > 0) {
    html += '<div class="dash-card mb-6">';
    html += '<h3 class="card-title">Top Risk Modules</h3>';
    html += '<div class="space-y-3">';
    topRisks.forEach(function(r) {
      var score = r.risk_score.total || 0;
      var barColor = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
      html += '<div class="flex items-center gap-3">';
      html += '<span class="text-sm flex-1">' + r.name + '</span>';
      html += '<div class="w-32 progress-bar">';
      html += '<div class="progress-fill" style="width:' + score + '%;background:' + barColor + '"></div>';
      html += '</div>';
      html += '<span class="text-xs font-bold" style="color:' + barColor + ';width:40px;text-align:right">' + score + '/100</span>';
      html += r.risk_score.policy ? policyBadgeHtml(r.risk_score.policy) : '';
      html += '</div>';
    });
    html += '</div>';
    html += '</div>';
  }

  // === Architecture Layers ===
  html += '<div class="dash-card mb-6">';
  html += '<h3 class="card-title">Architecture Layers</h3>';
  html += '<div id="layer-overview" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"></div>';
  html += '</div>';

  // === 1d. Quick Navigation Cards ===
  var navCards = [
    { tab: 'architecture', icon: '&#x1f3d7;', title: 'Architecture', preview: (DATA.components?.length || 8) + ' Components &middot; ' + zoneThreatCount + ' Threats' },
    { tab: 'ecosystem', icon: '&#x1f310;', title: 'Ecosystem', preview: ecoRepos + '+ Repos' },
    { tab: 'skills', icon: '&#x1f9e9;', title: 'Skills', preview: skillCount.toLocaleString() + ' Skills &middot; ' + malicious + ' Flagged' },
    { tab: 'attacks', icon: '&#x1f4a5;', title: 'Attacks', preview: cveCount + ' CVEs &middot; ' + scenarioCount + ' Scenarios' },
    { tab: 'timeline', icon: '&#x1f4c5;', title: 'Timeline', preview: eventCount + ' Events' },
    { tab: 'security', icon: '&#x1f6e1;', title: 'Security', preview: threatCount + ' Threats &middot; ' + controlCount + ' Controls' },
    { tab: 'research', icon: '&#x1f4c4;', title: 'Research', preview: DATA.papers.length + ' Papers' },
    { tab: 'moltbook', icon: '&#x1f4f1;', title: 'MoltBook', preview: 'Social Platform Analysis' }
  ];

  html += '<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">';
  navCards.forEach(function(nc) {
    html += '<div class="dash-card clickable" onclick="navigateToTab(\'' + nc.tab + '\')">';
    html += '<div class="flex items-center gap-2 mb-2">';
    html += '<span style="font-size:1.2rem">' + nc.icon + '</span>';
    html += '<span class="font-semibold text-sm">' + nc.title + '</span>';
    html += '</div>';
    html += '<div class="text-xs text-gray-500">' + nc.preview + '</div>';
    html += '</div>';
  });
  html += '</div>';

  // === Ecosystem Health row ===
  html += '<div class="grid grid-cols-1 md:grid-cols-3 gap-6">';

  html += '<div class="dash-card">';
  html += '<h3 class="card-title">Dependency Network</h3>';
  html += '<div id="overview-dep-network"></div>';
  html += '<a href="#ecosystem" onclick="navigateToTab(\'ecosystem\')" class="detail-link text-xs mt-3 inline-block">Details &#x2192;</a>';
  html += '</div>';

  html += '<div class="dash-card">';
  html += '<h3 class="card-title">Skill Security Status</h3>';
  html += '<div id="overview-skill-security"></div>';
  html += '<a href="#skills" onclick="navigateToTab(\'skills\')" class="detail-link text-xs mt-3 inline-block">Details &#x2192;</a>';
  html += '</div>';

  html += '<div class="dash-card">';
  html += '<h3 class="card-title">Control Coverage</h3>';
  html += '<div id="overview-control-coverage"></div>';
  html += '<a href="#security" onclick="navigateToTab(\'security\')" class="detail-link text-xs mt-3 inline-block">Details &#x2192;</a>';
  html += '</div>';

  html += '</div>';

  // Inject the rebuilt overview
  container.innerHTML = html;

  // Now populate dynamic sub-sections that need DOM elements

  // Risk distribution
  var distEl = document.getElementById('risk-distribution');
  if (distEl) {
    distEl.innerHTML = Object.entries(riskCounts).map(function(entry) {
      var level = entry[0], count = entry[1];
      return '<div class="flex items-center gap-3">' +
        '<span class="risk-badge risk-' + level + '" style="width:70px; justify-content:center">' + level + '</span>' +
        '<div class="flex-1 progress-bar">' +
        '<div class="progress-fill" style="width:' + (count/total*100) + '%; background:' + severityColor(level) + '"></div>' +
        '</div>' +
        '<span class="text-sm text-gray-400" style="width:30px; text-align:right">' + count + '</span>' +
        '</div>';
    }).join('');
  }

  // Top threats
  var topThreatsEl = document.getElementById('top-threats');
  if (topThreatsEl) {
    topThreatsEl.innerHTML = threatRanked.map(function(item) {
      return '<div class="flex items-center gap-3">' +
        '<span class="severity-indicator" style="width:8px;height:8px;border-radius:50%;background:' + severityColor(item.threat.severity) + ';flex-shrink:0"></span>' +
        '<span class="text-sm flex-1">' + item.threat.name + '</span>' +
        '<span class="text-sm text-gray-400">' + item.count + ' items</span>' +
        '</div>';
    }).join('');
  }

  // Layer overview
  var layerEl = document.getElementById('layer-overview');
  if (layerEl) {
    layerEl.innerHTML = DATA.components.map(function(comp) {
      var layerRepos = DATA.repos.filter(function(r) { return r.layer === comp.id; });
      var maxRisk = layerRepos.reduce(function(max, r) {
        var rl = calcRiskLevel(r);
        return riskOrder(rl) < riskOrder(max) ? rl : max;
      }, 'none');
      return '<div class="dash-card clickable" onclick="navigateToLayer(\'' + comp.id + '\')">' +
        '<div class="flex items-center justify-between mb-2">' +
        '<span class="text-xs font-bold text-gray-500">' + comp.code + '</span>' +
        '<span class="risk-badge risk-' + maxRisk + '">' + maxRisk + '</span>' +
        '</div>' +
        '<div class="font-semibold text-sm mb-1">' + comp.name + '</div>' +
        '<div class="text-xs text-gray-500">' + layerRepos.length + ' items</div>' +
        '</div>';
    }).join('');
  }

  // Alert banner
  var alertEl = document.getElementById('overview-alert-content');
  if (alertEl) {
    var alerts = [];
    var sevStyle = {
      critical: { bg: 'rgba(255,60,80,0.1)', border: '#5a1525', dot: '#ff4d6a', text: '#ffa0b0' },
      high:     { bg: 'rgba(255,140,66,0.08)', border: '#4a2a10', dot: '#ff8c42', text: '#ffc494' },
      medium:   { bg: 'rgba(255,195,18,0.06)', border: '#3a3010', dot: '#ffc312', text: '#ffe08a' }
    };
    (DATA.attacks.cves || []).forEach(function(c) {
      var s = c.severity === 'critical' ? 'critical' : 'high';
      var nvdUrl = 'https://nvd.nist.gov/vuln/detail/' + c.id;
      alerts.push({ severity: s, html: '<a href="' + nvdUrl + '" target="_blank" rel="noopener" style="color:' + sevStyle[s].dot + ';font-weight:700;text-decoration:none">' + c.id + '</a> <span style="color:' + sevStyle[s].text + '">' + c.title + '</span> <span class="risk-badge risk-' + c.severity + '" style="font-size:10px;padding:1px 6px">' + c.severity + '</span>' });
    });
    if (malPct > 5) alerts.push({ severity: 'high', html: '<span style="color:#ff8c42;font-weight:700">Malicious Skills</span> <span style="color:#ffc494">' + malPct + '% flagged malicious</span>' });
    var recentCritical = (DATA.timeline.events || []).filter(function(e) { return e.severity === 'critical' && e.year >= 2026; }).slice(0, 3);
    recentCritical.forEach(function(e) { alerts.push({ severity: 'critical', html: '<span style="color:#ff4d6a;font-weight:700">' + e.date + '</span> <span style="color:#ffa0b0">' + e.title + '</span>' }); });
    alertEl.innerHTML = alerts.map(function(a) {
      var s = sevStyle[a.severity] || sevStyle.medium;
      return '<div class="flex items-center gap-2 px-3 py-1.5 rounded-lg" style="background:' + s.bg + ';border:1px solid ' + s.border + '">' +
        '<span class="w-1.5 h-1.5 rounded-full flex-shrink-0" style="background:' + s.dot + ';box-shadow:0 0 6px ' + s.dot + '40"></span>' +
        '<span class="text-xs">' + a.html + '</span>' +
        '</div>';
    }).join('');
    alertEl.style.maxHeight = '120px';
    alertEl.style.overflowY = 'auto';
    var countEl = document.getElementById('overview-alert-count');
    if (countEl) countEl.textContent = alerts.length + ' alerts';
    var alertBox = document.getElementById('overview-alert');
    if (alertBox) alertBox.classList.toggle('hidden', alerts.length === 0);
  }

  // Attack Distribution
  var atkDistEl = document.getElementById('overview-attack-dist');
  if (atkDistEl) {
    var dist = DATA.attacks.distribution || [];
    var maxPct = Math.max.apply(null, dist.map(function(d) { return d.percent || 0; }).concat([1]));
    atkDistEl.innerHTML = dist.map(function(d) {
      return '<div class="flex items-center gap-3">' +
        '<span class="text-sm flex-1">' + d.category + '</span>' +
        '<div class="w-32 progress-bar">' +
        '<div class="progress-fill" style="width:' + ((d.percent||0)/maxPct*100) + '%;background:' + (d.color || '#ff6b7a') + '"></div>' +
        '</div>' +
        '<span class="text-sm text-gray-400 w-10 text-right">' + d.percent + '%</span>' +
        '</div>';
    }).join('');
  }

  // Dependency Network
  var depNetEl = document.getElementById('overview-dep-network');
  if (depNetEl) {
    var net = DATA.ecosystem.dependency_network || {};
    depNetEl.innerHTML = '<div class="text-xs text-gray-400 space-y-2">' +
      '<div>Topology: <span class="text-sm font-semibold text-gray-300">' + (net.network_characteristics?.topology || 'Hub-and-Spoke') + '</span></div>' +
      '<div>Dependency types: ' + (net.dependency_types || []).length + '</div>' +
      '<div>Supply chain stages: ' + (net.supply_chain ? net.supply_chain.flow.length : 0) + '</div>' +
      '</div>';
  }

  // Skill Security
  var skillSecEl = document.getElementById('overview-skill-security');
  if (skillSecEl) {
    skillSecEl.innerHTML = '<div class="text-2xl font-bold mb-2" style="color:' + (safeP > 95 ? '#00e6a7' : safeP > 90 ? '#ffc312' : '#ff4757') + '">' + safeP + '%</div>' +
      '<div class="text-xs text-gray-400">Safe skills (' + (totalS - flaggedS).toLocaleString() + ' / ' + totalS.toLocaleString() + ')</div>' +
      '<div class="progress-bar mt-3"><div class="progress-fill" style="width:' + safeP + '%;background:#00e6a7"></div></div>';
  }

  // Control Coverage
  var ctrlCovEl = document.getElementById('overview-control-coverage');
  if (ctrlCovEl) {
    ctrlCovEl.innerHTML = '<div class="text-2xl font-bold mb-2" style="color:' + (totalGaps === 0 ? '#00e6a7' : '#ff8c42') + '">' + coveredRepos + '/' + total + '</div>' +
      '<div class="text-xs text-gray-400">Fully covered components</div>' +
      (totalGaps > 0 ? '<div class="text-xs mt-2 font-semibold" style="color:#ff8c42">&#x26a0; ' + totalGaps + ' control gaps unresolved</div>' : '');
  }

  // Charts (deferred to allow DOM updates)
  setTimeout(function() {
    renderAttackDonutChart();
    renderTimelineChart();
  }, 0);
}

function navigateToLayer(layerId) {
  // Switch to directory tab and filter by layer
  switchTab('directory');

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
        <span class="px-2 py-0.5 rounded text-xs" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${r.type}</span>
        <span class="px-2 py-0.5 rounded text-xs" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${r.language}</span>
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
      <div class="dash-card">
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
            let href = '';
            if (id.startsWith('ATLAS-AML.')) href = 'https://atlas.mitre.org/techniques/' + id.replace('ATLAS-', '');
            else if (id.startsWith('ATTACK-')) href = 'https://attack.mitre.org/techniques/' + id.replace('ATTACK-', '').replace(/\./g, '/');
            return href ? `<a href="${href}" target="_blank" rel="noopener" class="mitre-badge ${cls}" style="text-decoration:none;cursor:pointer">${id}</a>` : `<span class="mitre-badge ${cls}">${id}</span>`;
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
      <div class="dash-card">
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

  // Kill Chain SVG chart
  setTimeout(function() { renderKillChainChart(); }, 0);
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
    <div class="dash-card">
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
  // Paper type filters using unified filter bar
  const typeSet = new Set(DATA.papers.map(p => p.type));
  const types = ['all', ...typeSet, 'moltbook', 'openclaw'];
  const filterItems = types.map(t => {
    const label = t === 'moltbook' ? 'Moltbook' : t === 'openclaw' ? 'OpenClaw' : t;
    const count = t === 'all' ? DATA.papers.length
      : (t === 'moltbook' || t === 'openclaw')
        ? DATA.papers.filter(p => (p.topic_tags || []).includes(t)).length
        : DATA.papers.filter(p => p.type === t).length;
    return { id: t, label: label, count: count };
  });
  renderFilterBar('paper-type-filters', filterItems, activePaperType, function(val) {
    activePaperType = val;
    renderResearch();
  }, { searchHint: DATA.papers.length + ' papers total' });

  // Paper list (moltbook/openclaw filter by topic_tags, others by type)
  const filtered = activePaperType === 'all' ? DATA.papers
    : (activePaperType === 'moltbook' || activePaperType === 'openclaw')
      ? DATA.papers.filter(p => (p.topic_tags || []).includes(activePaperType))
      : DATA.papers.filter(p => p.type === activePaperType);
  document.getElementById('paper-list').innerHTML = filtered.map(p => {
    const mappedThreats = (p.mapped_threats || []).map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
    const mappedComps = [...new Set(p.mapped_components || [])].map(cid => DATA.components.find(c => c.id === cid)).filter(Boolean);

    return `
      <div class="paper-card">
        <div class="flex items-center gap-2 mb-2">
          <span class="paper-type-badge paper-type-${p.type}">${p.type}</span>
          <span class="text-xs text-gray-500">${p.year}</span>
        </div>
        <div class="font-semibold text-sm mb-2">${p.arxiv_url ? `<a href="${p.arxiv_url}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none" onmouseover="this.style.color='#00e6a7'" onmouseout="this.style.color='inherit'">${p.title}</a>` : p.title}${p.arxiv_url ? ` <a href="${p.arxiv_url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none;font-weight:normal">arXiv</a>` : ''}</div>
        <div class="flex flex-wrap gap-1 mb-2">
          ${(p.topic_tags || []).map(tag => `<span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${tag}</span>`).join('')}
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
      <div class="dash-card" style="padding:8px">
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
              <div class="text-xs text-gray-500 truncate" style="max-width:400px">${escapeHtml(r.sub)}</div>
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
  const safe = escapeHtml(text);
  const safeQuery = escapeHtml(query);
  const idx = safe.toLowerCase().indexOf(safeQuery.toLowerCase());
  if (idx === -1) return safe;
  return safe.slice(0, idx) + '<mark style="background:#fbbf24;color:#000;border-radius:2px;padding:0 1px">' + safe.slice(idx, idx + safeQuery.length) + '</mark>' + safe.slice(idx + safeQuery.length);
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
  const btn = document.querySelector(`[data-tab="${tabName}"]`);
  if (!btn) return;
  btn.click();

  if (options.highlightId) {
    setTimeout(() => {
      const el = document.getElementById(options.highlightId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el.style.outline = '2px solid #00e6a7';
        setTimeout(() => { el.style.outline = ''; }, 2000);
      }
    }, 200);
  }

  if (options.filter) {
    setTimeout(() => {
      const searchInput = document.querySelector(`#tab-${tabName} input[type="text"]`);
      if (searchInput) {
        searchInput.value = options.filter;
        searchInput.dispatchEvent(new Event('input'));
      }
    }, 200);
  }
}

function initHashRouting() {
  // Read hash on load
  const hash = window.location.hash.slice(1);
  if (hash) {
    const btn = document.querySelector(`[data-tab="${hash}"]`);
    if (btn) setTimeout(() => btn.click(), 100);
  }

  // Update hash on tab change
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab || btn.getAttribute('data-tab');
      if (tab) history.replaceState(null, '', '#' + tab);
    });
  });

  // Handle back/forward
  window.addEventListener('hashchange', () => {
    const h = window.location.hash.slice(1);
    if (h) {
      const btn = document.querySelector(`[data-tab="${h}"]`);
      if (btn) btn.click();
    }
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
  document.getElementById('eco-search').addEventListener('input', debounce(() => renderEcosystem(), 300));
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
            <div class="dash-card text-center">
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
            <span class="text-xs px-3 py-1.5 rounded-lg font-semibold" style="background:var(--bg-card,#141c2e);color:#ffc312">${step}</span>
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
    btn.onclick = () => {
      activeEcoCategory = btn.dataset.ecocat;
      renderEcosystem();
    };
  });

  // Filter + search
  const query = document.getElementById('eco-search').value;
  let filtered = repos;
  if (activeEcoCategory !== 'all') {
    filtered = filtered.filter(r => r.category === activeEcoCategory);
  }
  filtered = fuzzySearch(filtered, query, ['name', 'description', 'language', 'tags', 'note']);

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
  const ecoRenderItem = (r) => {
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
          ${(r.tags || []).slice(0, 4).map(tag => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-secondary,#5a6d84)">${tag}</span>`).join('')}
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
  };
  // Remove old pagination if exists
  var oldPag = document.getElementById('eco-repo-list-pagination');
  if (oldPag) oldPag.remove();
  if (filtered.length >= 60) {
    paginatedRender('eco-repo-list', filtered, ecoRenderItem, ecoPageSize);
  } else {
    document.getElementById('eco-repo-list').innerHTML = filtered.map(ecoRenderItem).join('');
  }
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
  document.getElementById('skill-search').addEventListener('input', debounce(() => renderSkills(), 300));
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
    el.onclick = () => {
      activeSkillCategory = el.dataset.skillcat;
      renderSkills();
    };
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
  const query = document.getElementById('skill-search').value;
  let filtered = topSkills;
  if (activeSkillCategory !== 'all') {
    filtered = filtered.filter(s => s.category === activeSkillCategory);
  }
  filtered = fuzzySearch(filtered, query, ['name', 'description', 'category']);

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
            ${catInfo ? `<span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${catInfo.icon} ${catInfo.name}</span>` : ''}
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
  document.getElementById('attack-search').addEventListener('input', debounce(() => renderAttacks(), 300));
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
          ${phaseScenarios.slice(0, 5).map(s => renderThreatTag(s)).join('')}
          ${phaseScenarios.length > 5 ? `<span class="text-xs text-gray-500">+${phaseScenarios.length - 5} more</span>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // CVEs
  document.getElementById('atk-cve-list').innerHTML = cves.map(c => {
    const nvdUrl = `https://nvd.nist.gov/vuln/detail/${c.id}`;
    const mitreUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c.id}`;
    return `
    <div class="dash-card" style="border-color:#450a0a;background:rgba(239,68,68,0.05)">
      <div class="flex items-center justify-between mb-1">
        <span class="font-mono text-sm font-bold" style="color:#fca5a5">${c.id}</span>
        <div class="flex items-center gap-2">
          <a href="${nvdUrl}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="background:rgba(239,68,68,0.1);color:#fca5a5;border:1px solid #450a0a;text-decoration:none">NVD</a>
          <a href="${mitreUrl}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="background:rgba(239,68,68,0.1);color:#fca5a5;border:1px solid #450a0a;text-decoration:none">MITRE</a>
          <span class="risk-badge risk-${c.severity}">${c.severity}</span>
        </div>
      </div>
      <div class="text-sm font-semibold mb-1">${c.title}</div>
      <div class="text-xs text-gray-400 mb-1">${c.description}</div>
      <div class="text-xs text-gray-500">Source: ${c.reference}</div>
    </div>
  `;
  }).join('');

  // Attack Surfaces (7-layer)
  document.getElementById('atk-surfaces').innerHTML = surfaces.map(layer => {
    const critCount = layer.surfaces.filter(s => s.severity === 'critical').length;
    const highCount = layer.surfaces.filter(s => s.severity === 'high').length;
    return `
      <div class="dash-card">
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

  // Phase + Category filter buttons using unified filter bar
  const categories = ['all', ...new Set(scenarios.map(s => s.category))];
  const phases = ['all', ...new Set(scenarios.map(s => s.phase))];

  const catFilters = categories.map(c => ({
    id: c,
    label: c.replace(/-/g, ' '),
    count: c === 'all' ? scenarios.length : scenarios.filter(s => s.category === c).length
  }));
  renderFilterBar('atk-category-filters', catFilters, activeAttackCategory, function(val) {
    activeAttackCategory = val;
    renderAttacks();
  });

  const phaseFilters = phases.map(p => ({
    id: p,
    label: p.replace(/_/g, ' '),
    count: p === 'all' ? scenarios.length : scenarios.filter(s => s.phase === p).length
  }));
  renderFilterBar('atk-phase-filters', phaseFilters, activeAttackPhase, function(val) {
    activeAttackPhase = val;
    renderAttacks();
  });

  // Filter scenarios
  const query = document.getElementById('attack-search').value;
  let filtered = scenarios;
  if (activeAttackCategory !== 'all') filtered = filtered.filter(s => s.category === activeAttackCategory);
  if (activeAttackPhase !== 'all') filtered = filtered.filter(s => s.phase === activeAttackPhase);
  filtered = fuzzySearch(filtered, query, ['name', 'description', 'category', 'tags']);

  document.getElementById('atk-scenario-count').textContent = `${filtered.length} scenarios`;

  // Render scenario list
  document.getElementById('atk-scenario-list').innerHTML = filtered.map(s => `
    <div class="dash-card">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">#${s.id}</span>
          <span class="text-sm font-semibold">${s.name}</span>
        </div>
        <span class="risk-badge risk-${s.severity}">${s.severity}</span>
      </div>
      <p class="text-xs text-gray-400 mb-2 leading-relaxed">${s.description}</p>
      <div class="flex items-center gap-2 flex-wrap">
        <span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${s.category.replace(/-/g, ' ')}</span>
        <span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${s.phase.replace(/_/g, ' ')}</span>
        ${s.reference ? `<span class="text-xs text-gray-500">&#x1f4ce; ${s.reference}</span>` : ''}
      </div>
      <div class="flex flex-wrap gap-1 mt-2">
        ${(s.tags || []).map(t => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:#0a0e1a;color:var(--text-secondary,#5a6d84)">${t}</span>`).join('')}
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
  document.getElementById('timeline-search').addEventListener('input', debounce(() => renderTimeline(), 300));
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

  // Year + scope filter buttons using unified filter bar
  const years = ['all', ...new Set(events.map(e => String(e.year)))];
  const scopes = ['all', ...new Set(events.map(e => e.scope))];

  const yearFilters = years.map(y => ({
    id: y,
    label: y,
    count: y === 'all' ? events.length : events.filter(e => String(e.year) === y).length
  }));
  renderFilterBar('tl-year-filters', yearFilters, activeTimelineYear, function(val) {
    activeTimelineYear = val;
    renderTimeline();
  });

  const scopeFilters = scopes.map(s => ({
    id: s,
    label: s.replace(/-/g, ' '),
    count: s === 'all' ? events.length : events.filter(e => e.scope === s).length
  }));
  renderFilterBar('tl-scope-filters', scopeFilters, activeTimelineScope, function(val) {
    activeTimelineScope = val;
    renderTimeline();
  });

  // Filter events
  const query = document.getElementById('timeline-search').value;
  let filtered = events;
  if (activeTimelineYear !== 'all') filtered = filtered.filter(e => String(e.year) === activeTimelineYear);
  if (activeTimelineScope !== 'all') filtered = filtered.filter(e => e.scope === activeTimelineScope);
  filtered = fuzzySearch(filtered, query, ['title', 'description', 'category', 'issues', 'reference']);

  document.getElementById('tl-event-count').textContent = `${filtered.length} events`;

  // Year-grouped timeline
  const grouped = {};
  filtered.forEach(e => {
    if (!grouped[e.year]) grouped[e.year] = [];
    grouped[e.year].push(e);
  });

  const sortedYears = Object.keys(grouped).sort((a, b) => b - a);
  document.getElementById('tl-event-list').innerHTML = sortedYears.map(year => {
    const phase = phases.find(p => p.year === year);
    const yearEvents = grouped[year].sort((a, b) => b.date.localeCompare(a.date));
    return `
      <div class="mb-6">
        <div class="flex items-center gap-3 mb-3">
          <div class="text-xl font-bold" style="color:${phase ? phase.color : '#00e6a7'}">${year}</div>
          ${phase ? `<span class="text-xs px-3 py-1 rounded-full font-semibold" style="background:${phase.color}22;color:${phase.color};border:1px solid ${phase.color}44">${phase.name}</span>` : ''}
          <span class="text-xs text-gray-500">${yearEvents.length} events</span>
        </div>
        <div class="space-y-2 pl-4" style="border-left:2px solid ${phase ? phase.color : '#374151'}">
          ${yearEvents.map(e => `
            <div class="dash-card relative">
              <div class="absolute -left-6 top-3 w-3 h-3 rounded-full" style="background:${timelineSeverityColor(e.severity)};border:2px solid #0a0e1a"></div>
              <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-mono text-gray-500">${e.date}</span>
                  <span>${timelineCategoryIcon(e.category)}</span>
                  <span class="text-sm font-semibold">${e.title}</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${e.scope.replace(/-/g, ' ')}</span>
                  ${e.severity !== 'info' ? `<span class="risk-badge risk-${e.severity}">${e.severity}</span>` : ''}
                </div>
              </div>
              <p class="text-xs text-gray-400 mb-2 leading-relaxed">${e.description}</p>
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs px-2 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${e.category}</span>
                ${(e.issues || []).map(t => `<span class="text-xs px-1.5 py-0.5 rounded" style="background:#0a0e1a;color:var(--text-secondary,#5a6d84)">${t}</span>`).join('')}
                ${e.cvss ? `<span class="text-xs font-bold" style="color:#fca5a5">CVSS ${e.cvss}</span>` : ''}
                ${e.reference ? (() => {
                  const ref = e.reference;
                  let href = '';
                  if (ref.startsWith('arXiv ')) href = 'https://arxiv.org/abs/' + ref.replace('arXiv ', '');
                  else if (ref.includes('CVE-')) href = 'https://nvd.nist.gov/vuln/detail/' + ref;
                  else if (ref === 'OpenClaw GitHub') href = 'https://github.com/openclaw/openclaw';
                  else href = 'https://www.google.com/search?q=' + encodeURIComponent(ref + ' openclaw security');
                  return `<a href="${href}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="color:var(--text-muted,#7a8ba3);background:var(--bg-card,#141c2e);text-decoration:none;border:1px solid var(--border-primary,#1e293b)">&#x1f4ce; ${ref}</a>`;
                })() : ''}
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
// === SVG Chart Visualizations ===

function renderKillChainChart() {
  var phases = DATA.attacks.kill_chain || [];
  if (phases.length === 0) return;
  var el = document.getElementById('kill-chain');
  if (!el) return;
  var w = 900, h = 100, padding = 20;
  var stepW = (w - padding * 2) / phases.length;
  var colors = ['#22c55e','#84cc16','#eab308','#f97316','#ef4444','#dc2626','#991b1b'];
  var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;max-width:' + w + 'px;height:auto">';
  phases.forEach(function(p, i) {
    var x = padding + i * stepW;
    var c = colors[Math.min(i, colors.length - 1)];
    var phaseThreats = DATA.threats.filter(function(t) { return t.kill_chain_phase === p.phase; });
    var arrowW = stepW - 4;
    var points = i === 0
      ? x + ',20 ' + (x + arrowW - 15) + ',20 ' + (x + arrowW) + ',50 ' + (x + arrowW - 15) + ',80 ' + x + ',80'
      : x + ',20 ' + (x + arrowW - 15) + ',20 ' + (x + arrowW) + ',50 ' + (x + arrowW - 15) + ',80 ' + x + ',80 ' + (x + 15) + ',50';
    svg += '<polygon points="' + points + '" fill="' + c + '22" stroke="' + c + '" stroke-width="1.5"/>';
    svg += '<text x="' + (x + arrowW / 2) + '" y="45" text-anchor="middle" fill="' + c + '" font-size="10" font-weight="700">' + p.name + '</text>';
    svg += '<text x="' + (x + arrowW / 2) + '" y="62" text-anchor="middle" fill="#7a8ba3" font-size="8">' + phaseThreats.length + ' threats</text>';
  });
  svg += '</svg>';
  var existingHtml = el.innerHTML;
  el.innerHTML = '<div class="mb-4">' + svg + '</div>' + existingHtml;
}

function renderAttackDonutChart() {
  var distEl = document.getElementById('overview-attack-dist');
  if (!distEl) return;
  var dist = DATA.attacks.distribution || [];
  if (dist.length === 0) return;
  var size = 160, cx = size / 2, cy = size / 2, r = 55, innerR = 35;
  var svg = '<svg viewBox="0 0 ' + size + ' ' + size + '" style="width:' + size + 'px;height:' + size + 'px;display:block;margin:0 auto 16px">';
  var cumAngle = -90;
  dist.forEach(function(d) {
    var angle = (d.percent || 0) / 100 * 360;
    var startRad = cumAngle * Math.PI / 180;
    var endRad = (cumAngle + angle) * Math.PI / 180;
    var largeArc = angle > 180 ? 1 : 0;
    var x1 = cx + r * Math.cos(startRad), y1 = cy + r * Math.sin(startRad);
    var x2 = cx + r * Math.cos(endRad), y2 = cy + r * Math.sin(endRad);
    var ix1 = cx + innerR * Math.cos(endRad), iy1 = cy + innerR * Math.sin(endRad);
    var ix2 = cx + innerR * Math.cos(startRad), iy2 = cy + innerR * Math.sin(startRad);
    svg += '<path d="M' + x1 + ',' + y1 + ' A' + r + ',' + r + ' 0 ' + largeArc + ',1 ' + x2 + ',' + y2 + ' L' + ix1 + ',' + iy1 + ' A' + innerR + ',' + innerR + ' 0 ' + largeArc + ',0 ' + ix2 + ',' + iy2 + ' Z" fill="' + (d.color || '#64748b') + '" opacity="0.85"/>';
    cumAngle += angle;
  });
  var totalScenarios = (DATA.attacks.scenarios || []).length;
  svg += '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" fill="var(--text-primary, #e2e8f0)" font-size="18" font-weight="700">' + totalScenarios + '</text>';
  svg += '<text x="' + cx + '" y="' + (cy + 12) + '" text-anchor="middle" fill="var(--text-muted, #64748b)" font-size="8">scenarios</text>';
  svg += '</svg>';
  var existingHtml = distEl.innerHTML;
  distEl.innerHTML = svg + existingHtml;
}

function renderTimelineChart() {
  var events = DATA.timeline.events || [];
  if (events.length === 0) return;
  var years = {};
  events.forEach(function(e) { years[e.year] = (years[e.year] || 0) + 1; });
  var sortedYears = Object.keys(years).sort();
  var maxCount = Math.max.apply(null, Object.values(years));
  var w = 200, h = 60, padding = 5;
  var barW = Math.min(30, (w - padding * 2) / sortedYears.length - 4);
  var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;max-width:' + w + 'px;height:' + h + 'px">';
  sortedYears.forEach(function(yr, i) {
    var count = years[yr];
    var barH = (count / maxCount) * (h - 20);
    var x = padding + i * (barW + 4);
    var y = h - barH - 14;
    var color = yr === '2026' ? '#ef4444' : yr === '2025' ? '#f97316' : '#00e6a7';
    svg += '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + barH + '" fill="' + color + '" rx="2" opacity="0.7"/>';
    svg += '<text x="' + (x + barW / 2) + '" y="' + (y - 2) + '" text-anchor="middle" fill="' + color + '" font-size="7" font-weight="600">' + count + '</text>';
    svg += '<text x="' + (x + barW / 2) + '" y="' + (h - 2) + '" text-anchor="middle" fill="#5a6d84" font-size="7">' + yr + '</text>';
  });
  svg += '</svg>';
  var distEl = document.getElementById('overview-attack-dist');
  if (distEl && distEl.parentElement) {
    var chartDiv = document.createElement('div');
    chartDiv.className = 'mb-3 text-center';
    chartDiv.innerHTML = '<div class="text-xs text-gray-500 mb-1">Events by Year</div>' + svg;
    var parentCard = distEl.closest('.dash-card');
    if (parentCard) {
      var prevCard = parentCard.previousElementSibling;
      if (prevCard) {
        var eventsContainer = prevCard.querySelector('.space-y-3');
        if (eventsContainer) {
          prevCard.insertBefore(chartDiv, eventsContainer);
        }
      }
    }
  }
}

// === Data Export ===
// =====================================================

function exportData(format, tabName) {
  const dataMap = {
    'directory': () => DATA.repos,
    'ecosystem': () => DATA.ecosystem.repositories || DATA.ecosystem.repos || [],
    'attacks': () => DATA.attacks.scenarios,
    'timeline': () => DATA.timeline.events || DATA.timeline,
    'skills': () => DATA.skills.top_skills,
    'security': () => ({ threats: DATA.threats, controls: DATA.controls }),
    'research': () => DATA.papers,
  };

  const getData = dataMap[tabName];
  if (!getData) return;
  const data = getData();

  if (format === 'json') {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `openclaw-${tabName}-${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(url);
  } else if (format === 'csv') {
    if (!Array.isArray(data) || data.length === 0) return;
    const headers = Object.keys(data[0]);
    const csv = [headers.join(','), ...data.map(row =>
      headers.map(h => {
        const v = row[h];
        const str = typeof v === 'object' ? JSON.stringify(v) : String(v || '');
        return '"' + str.replace(/"/g, '""') + '"';
      }).join(',')
    )].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `openclaw-${tabName}-${new Date().toISOString().slice(0,10)}.csv`;
    a.click(); URL.revokeObjectURL(url);
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

  // Reference URL helper
  const refUrl = (ref) => {
    if (ref.startsWith('arXiv ')) return 'https://arxiv.org/abs/' + ref.replace('arXiv ', '');
    if (ref === 'Wiz Blog' || ref === 'Wiz') return 'https://www.wiz.io/blog/hacking-moltbook';
    return 'https://www.google.com/search?q=' + encodeURIComponent(ref + ' moltbook');
  };
  const refLink = (ref) => `<a href="${refUrl(ref)}" target="_blank" class="detail-link text-xs">${ref}</a>`;

  // Stats
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('mb-stat-agents', stats.claimed_agents ? stats.claimed_agents.toLocaleString() : '-');
  el('mb-stat-humans', stats.actual_humans ? stats.actual_humans.toLocaleString() : '-');
  el('mb-stat-posts', stats.total_posts ? stats.total_posts.toLocaleString() : '-');
  el('mb-stat-incidents', incidents.length);
  el('mb-stat-submolts', stats.submolts ? stats.submolts.toLocaleString() : '-');
  el('mb-stat-leaked-keys', stats.exposed_api_keys ? stats.exposed_api_keys.toLocaleString() : '-');

  // Stats date
  const statsGrid = document.querySelector('#tab-moltbook .grid.grid-cols-3');
  if (statsGrid && stats.data_as_of) {
    let dateEl = document.getElementById('mb-stats-date');
    if (!dateEl) {
      dateEl = document.createElement('div');
      dateEl.id = 'mb-stats-date';
      dateEl.className = 'text-xs text-gray-500 text-right mt-1 mb-3';
      statsGrid.parentNode.insertBefore(dateEl, statsGrid.nextSibling);
    }
    dateEl.textContent = 'Data as of ' + stats.data_as_of;
  }

  // Overview
  const overviewEl = document.getElementById('mb-overview');
  if (overviewEl) {
    overviewEl.innerHTML = `
      <p class="text-sm text-gray-300 mb-3">${overview.description || ''}</p>
      <p class="text-xs text-gray-400 italic mb-3">"${overview.tagline || ''}"</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div class="dash-card" style="padding:8px">
          <div class="text-xs font-semibold mb-1" style="color:#00e6a7">Tech Stack</div>
          <div class="text-xs text-gray-400">${overview.tech_stack || ''}</div>
        </div>
        <div class="dash-card" style="padding:8px">
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
      <div class="dash-card mb-3" style="border-color:${inc.severity === 'critical' ? '#450a0a' : ''};background:${inc.severity === 'critical' ? 'rgba(239,68,68,0.05)' : ''}">
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
        <div class="text-xs mt-1">${(inc.references || []).map(r => refLink(r)).join(' · ')}</div>
      </div>
    `).join('');
  }

  // Controversies
  const contEl = document.getElementById('mb-controversies');
  if (contEl) {
    const sevIcon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    contEl.innerHTML = controversies.map(c => `
      <div class="dash-card mb-3">
        <div class="flex items-center gap-2 mb-2">
          <span>${sevIcon[c.severity] || '⚪'}</span>
          <span class="text-sm font-bold">${c.title}</span>
          <span class="risk-badge risk-${c.severity}">${c.severity}</span>
        </div>
        <p class="text-xs text-gray-400 leading-relaxed">${c.description}</p>
        <div class="text-xs mt-2">${(c.sources || []).map(s => refLink(s)).join(' · ')}</div>
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
      <div class="dash-card flex items-center gap-3" style="padding:8px">
        <div class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style="background:var(--bg-card,#141c2e);color:${roleColor[f.role] || '#00e6a7'}">
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
      <div class="dash-card flex items-center gap-4" style="${i === naming.length - 1 ? 'background:rgba(0,230,167,0.05)' : ''}">
        <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold" style="background:${i === naming.length - 1 ? '#00e6a7' : '#141c2e'};color:${i === naming.length - 1 ? '#0a0e1a' : '#00e6a7'}">${i + 1}</div>
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-1">
            <span class="font-bold text-base">${n.name}</span>
            <span class="text-xs px-2 py-0.5 rounded font-mono" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${n.versions}</span>
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
    wsEl.innerHTML = wsFiles.map((f, idx) => `
      <div class="p-2 rounded-lg" style="border:1px solid #141c2e">
        <div class="flex items-start gap-3">
          <span class="text-lg flex-shrink-0">${catIcon[f.category] || '📄'}</span>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <code class="text-sm font-bold" style="color:#00e6a7">${f.file}</code>
              <span class="text-xs px-1.5 py-0.5 rounded" style="background:var(--bg-card,#141c2e);color:var(--text-muted,#7a8ba3)">${f.category}</span>
              ${f.detail ? `<button class="text-xs px-1.5 py-0.5 rounded cursor-pointer" style="background:var(--bg-card,#141c2e);color:#00d4aa;border:1px solid var(--border-primary,#1e293b)" onclick="this.closest('.p-2').querySelector('.detail-panel').classList.toggle('hidden')">Detail</button>` : ''}
              ${f.url ? `<a href="${f.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}
            </div>
            <div class="text-xs text-gray-400 mt-1">${f.description}</div>
            ${f.security_note ? `<div class="text-xs mt-1" style="color:#ff8c42">⚠ ${f.security_note}</div>` : ''}
          </div>
        </div>
        ${f.detail ? `<div class="detail-panel hidden mt-2 ml-9 p-2 rounded text-xs text-gray-400" style="background:#0a0e1a;border:1px solid var(--border-primary,#1e293b)">
          <div>${f.detail}</div>
          ${f.spec ? `<div class="mt-1" style="color:var(--text-muted,#7a8ba3)"><span style="color:#00d4aa">Spec:</span> ${f.spec}</div>` : ''}
        </div>` : ''}
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
          <div class="p-2 rounded mb-2" style="border:1px solid #141c2e">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded flex items-center justify-center font-bold text-sm flex-shrink-0" style="background:var(--bg-card,#141c2e);color:#00e6a7">L${l.layer}</div>
              <div class="flex-1">
                <div class="text-sm flex items-center gap-2">
                  <code class="font-semibold" style="color:#00d4aa">${l.file}</code> — ${l.scope}
                  ${l.url ? `<a href="${l.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}
                </div>
                <div class="text-xs text-gray-400">${l.load_timing} | ${l.content}</div>
                ${l.detail ? `<div class="text-xs text-gray-500 mt-1">${l.detail}</div>` : ''}
              </div>
            </div>
          </div>
        `).join('')}
      </div>
      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2 flex items-center gap-2" style="color:#00e6a7">Hybrid Search ${search.url ? `<a href="${search.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded font-normal" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}</h4>
        <div class="text-xs text-gray-400 mb-2">${(search.engines || []).join(' + ')}</div>
        <div class="flex gap-2 mb-2">
          <span class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:#00e6a7">Vector: ${(search.vector_weight * 100) || 70}%</span>
          <span class="text-xs px-2 py-1 rounded" style="background:var(--bg-card,#141c2e);color:#ffc312">Text: ${(search.text_weight * 100) || 30}%</span>
        </div>
        <div class="text-xs text-gray-500">Providers: ${(search.embedding_providers || []).join(', ')}</div>
        ${search.detail ? `<div class="text-xs text-gray-500 mt-2">${search.detail}</div>` : ''}
      </div>
      <div class="mb-4">
        <h4 class="text-sm font-semibold mb-2 flex items-center gap-2" style="color:#00e6a7">Auto Flush ${flush.url ? `<a href="${flush.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded font-normal" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}</h4>
        <div class="text-xs text-gray-400">${flush.trigger || ''}</div>
        <div class="text-xs text-gray-500 mt-1">${flush.action || ''}</div>
        ${flush.detail ? `<div class="text-xs text-gray-500 mt-1">${flush.detail}</div>` : ''}
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
      <div class="p-2 rounded-lg" style="border:1px solid #141c2e">
        <div class="flex items-start gap-3">
          <div class="w-8 h-8 rounded flex items-center justify-center text-xs font-bold flex-shrink-0" style="background:var(--bg-card,#141c2e);color:#00e6a7">▶</div>
          <div class="flex-1">
            <div class="text-sm font-semibold flex items-center gap-2">${c.name} <span class="text-xs text-gray-500 font-normal font-mono">${c.introduced}</span>
              ${c.detail ? `<button class="text-xs px-1.5 py-0.5 rounded cursor-pointer font-normal" style="background:var(--bg-card,#141c2e);color:#00d4aa;border:1px solid var(--border-primary,#1e293b)" onclick="this.closest('.p-2').querySelector('.detail-panel').classList.toggle('hidden')">Detail</button>` : ''}
              ${c.url ? `<a href="${c.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded font-normal" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}
            </div>
            <div class="text-xs text-gray-400 mt-1">${c.description}</div>
          </div>
        </div>
        ${c.detail ? `<div class="detail-panel hidden mt-2 ml-11 p-2 rounded text-xs text-gray-400" style="background:#0a0e1a;border:1px solid var(--border-primary,#1e293b)">
          <div>${c.detail}</div>
          ${c.spec ? `<div class="mt-1" style="color:var(--text-muted,#7a8ba3)"><span style="color:#00d4aa">Spec:</span> ${c.spec}</div>` : ''}
        </div>` : ''}
      </div>
    `).join('');
  }

  // CLI Commands
  const cliEl = document.getElementById('basic-cli-commands');
  if (cliEl) {
    cliEl.innerHTML = commands.map(c => `
      <div class="py-1.5" style="border-bottom:1px solid #0f1520">
        <div class="flex items-start gap-3">
          <code class="text-xs font-mono flex-shrink-0" style="color:#00e6a7;min-width:260px">${c.command}</code>
          <span class="text-xs text-gray-400 flex-1">${c.description}</span>
          ${c.url ? `<a href="${c.url}" target="_blank" rel="noopener" class="text-xs px-1.5 py-0.5 rounded flex-shrink-0" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none">Docs</a>` : ''}
        </div>
        ${c.detail ? `<div class="text-xs text-gray-500 mt-1 ml-0" style="padding-left:268px">${c.detail}</div>` : ''}
      </div>
    `).join('');
  }

  // Providers & Channels
  const provEl = document.getElementById('basic-providers');
  if (provEl) {
    provEl.innerHTML = providers.map(p => `
      <div class="py-1.5" style="border-bottom:1px solid #0f1520">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold flex items-center gap-2">${p.name}
            ${p.url ? `<a href="${p.url}" target="_blank" rel="noopener" class="px-1 py-0.5 rounded font-normal" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none;font-size:10px">API</a>` : ''}
          </span>
          <div class="flex items-center gap-2">
            <span class="text-xs text-gray-400">${p.models}</span>
            <span class="text-xs font-mono text-gray-500">${p.since}</span>
          </div>
        </div>
        ${p.detail ? `<div class="text-xs text-gray-500 mt-0.5">${p.detail}</div>` : ''}
      </div>
    `).join('');
  }

  const chanEl = document.getElementById('basic-channels');
  if (chanEl) {
    chanEl.innerHTML = channels.map(c => `
      <div class="py-2" style="border-bottom:1px solid #0f1520">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold flex items-center gap-2">${c.name}
            ${c.url ? `<a href="${c.url}" target="_blank" rel="noopener" class="px-1 py-0.5 rounded font-normal" style="background:rgba(0,230,167,0.08);color:#00e6a7;border:1px solid #00e6a720;text-decoration:none;font-size:10px">Docs</a>` : ''}
          </span>
          <span class="text-xs font-mono text-gray-500">${c.since}</span>
        </div>
        <div class="text-xs text-gray-400 mt-0.5">${c.features}</div>
        ${c.detail ? `<div class="text-xs text-gray-500 mt-0.5">${c.detail}</div>` : ''}
      </div>
    `).join('');
  }

  // Release History
  const relEl = document.getElementById('basic-release-list');
  if (relEl) {
    const catColor = { major: '#00e6a7', security: '#ff4757', feature: '#3b82f6', fix: '#ffc312', initial: '#a855f7' };
    const catLabel = { major: 'Major', security: 'Security', feature: 'Feature', fix: 'Fix', initial: 'Initial' };
    relEl.innerHTML = releases.map(r => `
      <div class="dash-card mb-2">
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

// === Architecture Tab ===
let archScale = 1;
function archZoom(delta) {
  archScale = Math.max(0.4, Math.min(3, archScale + delta));
  const el = document.getElementById('arch-diagram');
  if (el) el.style.transform = `scale(${archScale})`;
  const lbl = document.getElementById('arch-zoom-label');
  if (lbl) lbl.textContent = Math.round(archScale * 100) + '%';
}
function archZoomReset() {
  archScale = 1;
  const el = document.getElementById('arch-diagram');
  if (el) el.style.transform = 'scale(1)';
  const lbl = document.getElementById('arch-zoom-label');
  if (lbl) lbl.textContent = '100%';
}
function initArchZoom() {
  const wrapper = document.getElementById('arch-diagram-wrapper');
  if (!wrapper) return;
  wrapper.addEventListener('wheel', (e) => {
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      archZoom(e.deltaY < 0 ? 0.1 : -0.1);
    }
  }, { passive: false });
  // Drag to pan
  let dragging = false, startX, startY, scrollL, scrollT;
  wrapper.addEventListener('mousedown', (e) => {
    if (e.target.closest('[onclick]')) return;
    dragging = true; wrapper.style.cursor = 'grabbing';
    startX = e.pageX - wrapper.offsetLeft; startY = e.pageY - wrapper.offsetTop;
    scrollL = wrapper.scrollLeft; scrollT = wrapper.scrollTop;
  });
  wrapper.addEventListener('mousemove', (e) => {
    if (!dragging) return; e.preventDefault();
    wrapper.scrollLeft = scrollL - (e.pageX - wrapper.offsetLeft - startX);
    wrapper.scrollTop = scrollT - (e.pageY - wrapper.offsetTop - startY);
  });
  wrapper.addEventListener('mouseup', () => { dragging = false; wrapper.style.cursor = 'grab'; });
  wrapper.addEventListener('mouseleave', () => { dragging = false; wrapper.style.cursor = 'grab'; });
}

function navigateToBasicSection(sectionId) {
  navigateToTab('basic');
  setTimeout(() => {
    const target = document.getElementById(sectionId);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target.style.transition = 'box-shadow 0.3s ease';
      target.style.boxShadow = '0 0 0 2px #00e6a7, 0 0 20px rgba(0,228,167,0.15)';
      setTimeout(() => { target.style.boxShadow = ''; }, 2500);
    }
  }, 150);
}

function renderArchitecture() {
  renderArchDiagram();
  initArchZoom();
  renderArchDataflow();
  renderArchDeps();
  renderArchThreatLayer();
  renderArchLayerSecurity();
}

function renderArchDiagram() {
  const el = document.getElementById('arch-diagram');
  if (!el) return;

  // Pull real data from basic.json
  const providers = (DATA.basic.supported_providers || []).slice(0, 6).map(p => p.name);
  const channelList = (DATA.basic.supported_channels || []).slice(0, 6).map(c => c.name);
  const archComps = DATA.basic.architecture?.components || [];
  const gwComp = archComps.find(c => c.name === 'Gateway') || {};
  const rtComp = archComps.find(c => c.name === 'Agent Runtime') || {};
  const memComp = archComps.find(c => c.name === 'Memory Engine') || {};
  const sandComp = archComps.find(c => c.name === 'Sandbox') || {};
  const plugComp = archComps.find(c => c.name === 'Plugin System') || {};
  const chComp = archComps.find(c => c.name === 'Channel Adapters') || {};

  const W = 960, H = 820;
  const cx = W / 2, cy = H / 2 - 10;

  // Helper: rounded rect with text
  function box(x, y, w, h, fill, stroke, rx) {
    return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${rx||8}" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`;
  }
  function arrow(x1, y1, x2, y2, color, dash) {
    return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="1.5" marker-end="url(#a${color.replace('#','')})" ${dash ? 'stroke-dasharray="5,3"' : ''}/>`;
  }

  let svg = `<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" style="width:100%;display:block;font-family:Pretendard,system-ui,sans-serif">`;

  // Defs: arrow markers
  const mColors = {'00e6a7':1,'3b82f6':1,'f59e0b':1,'a78bfa':1,'ef4444':1,'64748b':1};
  svg += `<defs>`;
  Object.keys(mColors).forEach(c => {
    svg += `<marker id="a${c}" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="7" markerHeight="5" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="#${c}"/></marker>`;
  });
  svg += `<filter id="glo"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>`;
  svg += `</defs>`;

  // Background
  svg += `<rect width="${W}" height="${H}" rx="12" fill="#0a0e1a"/>`;

  // ─── Title ───
  svg += `<text x="${cx}" y="24" text-anchor="middle" fill="#e2e8f0" font-size="15" font-weight="700">OPENCLAW LOCAL SYSTEM</text>`;
  svg += `<text x="${cx}" y="40" text-anchor="middle" fill="#64748b" font-size="10">(Self-Hosted · ${DATA.basic.supported_providers?.length || 15} Providers · ${DATA.basic.supported_channels?.length || 12} Channels)</text>`;

  // ─── Central system boundary ───
  svg += `<rect x="175" y="50" width="625" height="530" rx="10" fill="none" stroke="#1e3a5f" stroke-width="1.5" stroke-dasharray="6,3"/>`;
  svg += `<text x="488" y="68" text-anchor="middle" fill="#1e3a5f" font-size="9" font-weight="600">OPENCLAW LOCAL SYSTEM (Self-Hosted)</text>`;

  // ════════════════════════════════════════
  // LEFT ZONE: USER INTERACTION → Basic Channels
  // ════════════════════════════════════════
  const ux = 10, uy = 70, uw = 150, uh = 490;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-channels')">`;
  svg += box(ux, uy, uw, uh, 'rgba(59,130,246,0.06)', '#1e3a5f80', 10);
  svg += `<text x="${ux+uw/2}" y="${uy+22}" text-anchor="middle" fill="#60a5fa" font-size="11" font-weight="700">USER INTERACTION</text>`;
  const chIcons = {'WhatsApp':'💬','Telegram':'📨','Discord':'🎮','Slack':'💼','Signal':'🔒','iMessage':'📱','CLI':'⌨️','Web UI':'🌐','Matrix':'🔷','Teams':'🟦','LINE':'🟢'};
  channelList.forEach((ch, i) => {
    const icon = chIcons[ch] || '📡';
    svg += `<text x="${ux+uw/2}" y="${uy+50+i*26}" text-anchor="middle" fill="#94a3b8" font-size="10">${icon} ${ch}</text>`;
  });
  svg += `<text x="${ux+uw-4}" y="${uy+uh/2-30}" text-anchor="end" fill="#3b82f660" font-size="8">Messages &amp;</text>`;
  svg += `<text x="${ux+uw-4}" y="${uy+uh/2-20}" text-anchor="end" fill="#3b82f660" font-size="8">Commands →</text>`;
  svg += `<text x="${ux+uw-4}" y="${uy+uh/2+24}" text-anchor="end" fill="#3b82f660" font-size="8">← Responses &amp;</text>`;
  svg += `<text x="${ux+uw-4}" y="${uy+uh/2+34}" text-anchor="end" fill="#3b82f660" font-size="8">Proactive Updates</text>`;
  svg += `<text x="${ux+uw/2}" y="${uy+uh-12}" text-anchor="middle" fill="#3b82f640" font-size="7">▸ View Channels</text>`;
  svg += `</g>`;

  // ════════════════════════════════════════
  // RIGHT ZONE: LOCAL MACHINE RESOURCES → Basic Workspace
  // ════════════════════════════════════════
  const rx = 800, ry = 70, rw = 150, rh = 490;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-workspace')">`;
  svg += box(rx, ry, rw, rh, 'rgba(245,158,11,0.05)', '#3a2a1080', 10);
  svg += `<text x="${rx+rw/2}" y="${ry+22}" text-anchor="middle" fill="#f59e0b" font-size="11" font-weight="700">LOCAL MACHINE</text>`;
  svg += `<text x="${rx+rw/2}" y="${ry+36}" text-anchor="middle" fill="#f59e0b" font-size="9" font-weight="700">RESOURCES</text>`;
  const resList = [
    { icon: '📁', name: 'LOCAL FILESYSTEM', desc: 'Files & Directories' },
    { icon: '💻', name: 'SYSTEM TERMINAL', desc: 'Shell Commands' },
    { icon: '🌐', name: 'WEB BROWSER', desc: 'Chromium Automation' },
    { icon: '📱', name: 'LOCAL APPS', desc: 'IDE, Git, Docker' },
    { icon: '☁️', name: 'CLOUD APIs', desc: 'AWS, GCP, Azure' }
  ];
  resList.forEach((r, i) => {
    const iy = ry + 58 + i * 56;
    svg += `<rect x="${rx+10}" y="${iy}" width="${rw-20}" height="42" rx="6" fill="rgba(245,158,11,0.04)" stroke="#f59e0b20" stroke-width="1"/>`;
    svg += `<text x="${rx+rw/2}" y="${iy+17}" text-anchor="middle" fill="#f59e0b" font-size="10">${r.icon} ${r.name}</text>`;
    svg += `<text x="${rx+rw/2}" y="${iy+32}" text-anchor="middle" fill="#94a3b8" font-size="8">${r.desc}</text>`;
  });
  svg += `<text x="${rx+rw/2}" y="${ry+rh-12}" text-anchor="middle" fill="#f59e0b40" font-size="7">▸ View Workspace Files</text>`;
  svg += `</g>`;

  // ════════════════════════════════════════
  // GATEWAY → Basic Architecture
  // ════════════════════════════════════════
  const gx = 195, gy = 130, gw = 100, gh = 130;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-architecture')">`;
  svg += box(gx, gy, gw, gh, 'rgba(168,85,247,0.08)', '#a855f750', 10);
  svg += `<text x="${gx+gw/2}" y="${gy+20}" text-anchor="middle" fill="#a855f7" font-size="20">⇌</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+40}" text-anchor="middle" fill="#c084fc" font-size="11" font-weight="700">GATEWAY</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+56}" text-anchor="middle" fill="#94a3b8" font-size="7.5">Message Router &amp;</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+67}" text-anchor="middle" fill="#94a3b8" font-size="7.5">Session Manager</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+85}" text-anchor="middle" fill="#64748b" font-size="7">WebSocket + REST</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+97}" text-anchor="middle" fill="#64748b" font-size="7">${gwComp.introduced || '2025-12'}</text>`;
  svg += `<text x="${gx+gw/2}" y="${gy+115}" text-anchor="middle" fill="#a855f740" font-size="7">▸ Details</text>`;
  svg += `</g>`;
  // User → Gateway arrows
  svg += arrow(ux+uw, gy+gh/2-8, gx, gy+gh/2-8, '#3b82f6', true);
  svg += arrow(gx, gy+gh/2+8, ux+uw, gy+gh/2+8, '#3b82f6', true);

  // ════════════════════════════════════════
  // EXTERNAL LLM API → Basic Providers
  // ════════════════════════════════════════
  const llmx = 350, llmy = 58, llmw = 260, llmh = 68;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-providers')">`;
  svg += box(llmx, llmy, llmw, llmh, 'rgba(167,139,250,0.06)', '#a78bfa40', 12);
  svg += `<text x="${llmx+llmw/2}" y="${llmy+18}" text-anchor="middle" fill="#a78bfa" font-size="14">☁️</text>`;
  svg += `<text x="${llmx+llmw/2}" y="${llmy+34}" text-anchor="middle" fill="#c4b5fd" font-size="11" font-weight="700">EXTERNAL LLM API</text>`;
  svg += `<text x="${llmx+llmw/2}" y="${llmy+50}" text-anchor="middle" fill="#94a3b8" font-size="8">${providers.join(' · ')}</text>`;
  svg += `<text x="${llmx+llmw/2}" y="${llmy+62}" text-anchor="middle" fill="#64748b" font-size="7">${DATA.basic.supported_providers?.length || 15} providers  ▸ View All</text>`;
  svg += `</g>`;

  // ════════════════════════════════════════
  // AGENT (center) → Workspace Files from basic.json
  // ════════════════════════════════════════
  const wsFiles = (DATA.basic.workspace_files || []).filter(f => f.category === 'config').slice(0, 6);
  const ax = 310, ay = 140, aw = 210, ah = 220;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-workspace')">`;
  svg += box(ax, ay, aw, ah, 'rgba(250,204,21,0.08)', '#fbbf2450', 12);
  // Header
  svg += `<text x="${ax+aw/2}" y="${ay+18}" text-anchor="middle" fill="#fbbf24" font-size="16">🧠</text>`;
  svg += `<text x="${ax+aw/2}" y="${ay+34}" text-anchor="middle" fill="#fde68a" font-size="12" font-weight="700">AGENT</text>`;
  svg += `<text x="${ax+aw/2}" y="${ay+48}" text-anchor="middle" fill="#fde68a" font-size="8">(AI Brain / LLM · ${rtComp.introduced || '2025-11'})</text>`;
  // Workspace files
  svg += `<text x="${ax+12}" y="${ay+66}" fill="#94a3b8" font-size="7.5" font-weight="600">WORKSPACE FILES</text>`;
  wsFiles.forEach((f, i) => {
    const fy = ay + 74 + i * 20;
    svg += `<rect x="${ax+8}" y="${fy}" width="${aw-16}" height="16" rx="3" fill="rgba(0,0,0,0.2)" stroke="#fbbf2415" stroke-width="0.5"/>`;
    svg += `<text x="${ax+14}" y="${fy+12}" fill="#fde68a" font-size="8" font-weight="600">${f.file}</text>`;
    const descShort = f.description.split('—')[0].trim();
    svg += `<text x="${ax+aw-12}" y="${fy+12}" text-anchor="end" fill="#64748b" font-size="6.5">${descShort}</text>`;
  });
  // Footer
  const footY = ay + 74 + wsFiles.length * 20 + 6;
  svg += `<text x="${ax+aw/2}" y="${footY}" text-anchor="middle" fill="#94a3b8" font-size="7">Context Management · Tool Orchestration</text>`;
  svg += `<text x="${ax+aw/2}" y="${footY+13}" text-anchor="middle" fill="#fbbf2440" font-size="7">▸ View Workspace Files</text>`;
  svg += `</g>`;
  // LLM → Agent
  svg += arrow(llmx+llmw/2, llmy+llmh, llmx+llmw/2, ay, '#a78bfa', false);
  // Gateway → Agent
  svg += arrow(gx+gw, gy+gh/2, ax, ay+ah/2, '#a855f7', false);

  // ════════════════════════════════════════
  // SKILLS → Skills Tab (real data from skills.json)
  // ════════════════════════════════════════
  const skillStats = DATA.skills.stats || {};
  const skillCats = (DATA.skills.categories || []).slice(0, 6);
  const totalSkills = skillStats.total_clawhub || 0;
  const flaggedSkills = skillStats.flagged_malicious || 0;
  const flaggedPct = skillStats.flagged_percent || 0;
  const catCount = skillStats.categories_count || 0;

  const sx = 545, sy = 130, sw = 240, sh = 310;
  svg += `<g style="cursor:pointer" onclick="navigateToTab('skills')">`;
  svg += box(sx, sy, sw, sh, 'rgba(16,185,129,0.06)', '#10b98140', 10);
  // Header
  svg += `<text x="${sx+sw/2}" y="${sy+18}" text-anchor="middle" fill="#10b981" font-size="14">🧩</text>`;
  svg += `<text x="${sx+sw/2}" y="${sy+34}" text-anchor="middle" fill="#34d399" font-size="11" font-weight="700">SKILLS</text>`;
  svg += `<text x="${sx+sw/2}" y="${sy+48}" text-anchor="middle" fill="#94a3b8" font-size="8">(Modular Capabilities · ClawHub Registry)</text>`;
  // Stats row
  svg += `<rect x="${sx+10}" y="${sy+56}" width="${sw-20}" height="32" rx="5" fill="rgba(0,0,0,0.2)" stroke="#1e293b" stroke-width="0.5"/>`;
  svg += `<text x="${sx+20}" y="${sy+76}" fill="#00e6a7" font-size="10" font-weight="700">${totalSkills.toLocaleString()}</text>`;
  svg += `<text x="${sx+73}" y="${sy+76}" fill="#64748b" font-size="8">skills</text>`;
  svg += `<text x="${sx+110}" y="${sy+76}" fill="#ef4444" font-size="10" font-weight="700">${flaggedSkills}</text>`;
  svg += `<text x="${sx+140}" y="${sy+76}" fill="#64748b" font-size="8">malicious (${flaggedPct}%)</text>`;
  // Top categories
  svg += `<text x="${sx+14}" y="${sy+103}" fill="#94a3b8" font-size="7.5" font-weight="600">TOP CATEGORIES (${catCount})</text>`;
  const catMaxCount = skillCats.length > 0 ? skillCats[0].count : 1;
  skillCats.forEach((cat, i) => {
    const iy = sy + 110 + i * 26;
    const barW = (cat.count / catMaxCount) * (sw - 90);
    svg += `<text x="${sx+14}" y="${iy+12}" fill="#e2e8f0" font-size="8">${cat.icon} ${cat.name}</text>`;
    svg += `<rect x="${sx+sw-70}" y="${iy+2}" width="${barW > 0 ? barW * 50 / (sw - 90) : 2}" height="10" rx="2" fill="#10b98130"/>`;
    svg += `<text x="${sx+sw-14}" y="${iy+12}" text-anchor="end" fill="#64748b" font-size="8">${cat.count}</text>`;
  });
  // Security warning
  const warnY = sy + 110 + skillCats.length * 26 + 6;
  svg += `<rect x="${sx+10}" y="${warnY}" width="${sw-20}" height="22" rx="4" fill="rgba(239,68,68,0.08)" stroke="#ef444425" stroke-width="0.5"/>`;
  svg += `<text x="${sx+sw/2}" y="${warnY+15}" text-anchor="middle" fill="#f87171" font-size="8">⚠ ${flaggedSkills} flagged malicious (${flaggedPct}%) — ClawHavoc Campaign</text>`;
  // Footer link
  svg += `<text x="${sx+sw/2}" y="${sy+sh-8}" text-anchor="middle" fill="#10b98160" font-size="8">▸ View All Skills &amp; Risk Scores</text>`;
  svg += `</g>`;
  // Agent → Skills
  svg += arrow(ax+aw, ay+ah/2, sx, ay+ah/2, '#10b981', false);
  // Skills → Resources
  svg += arrow(sx+sw, sy+60, rx, ry+rh/2-50, '#f59e0b', true);
  svg += `<text x="${sx+sw+2}" y="${sy+50}" fill="#f59e0b60" font-size="7">Execution</text>`;
  svg += `<text x="${sx+sw+2}" y="${sy+60}" fill="#f59e0b60" font-size="7">Results &amp; Data →</text>`;

  // ════════════════════════════════════════
  // PERSISTENT MEMORY → Basic Memory System (real data)
  // ════════════════════════════════════════
  const memSys = DATA.basic.memory_system || {};
  const memLayers = memSys.layers || [];
  const memSearch = memSys.search || {};
  const memFlush = memSys.flush || {};
  const memRules = (memSys.security_rules || []).slice(0, 2);

  const mx = 270, my = ay + ah + 16, mw = 290, mh = 170;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-memory')">`;
  svg += box(mx, my, mw, mh, 'rgba(6,182,212,0.06)', '#06b6d440', 10);
  // Header
  svg += `<text x="${mx+mw/2}" y="${my+16}" text-anchor="middle" fill="#06b6d4" font-size="13">🗄️</text>`;
  svg += `<text x="${mx+mw/2}" y="${my+30}" text-anchor="middle" fill="#22d3ee" font-size="11" font-weight="700">PERSISTENT MEMORY</text>`;
  svg += `<text x="${mx+mw/2}" y="${my+43}" text-anchor="middle" fill="#94a3b8" font-size="7.5">Context, Preferences, History · Local Files/DB</text>`;
  // Memory layers
  let ly = my + 52;
  memLayers.forEach(l => {
    svg += `<rect x="${mx+10}" y="${ly}" width="${mw-20}" height="18" rx="3" fill="rgba(0,0,0,0.2)" stroke="#06b6d415" stroke-width="0.5"/>`;
    svg += `<text x="${mx+18}" y="${ly+13}" fill="#22d3ee" font-size="8" font-weight="600">L${l.layer}</text>`;
    svg += `<text x="${mx+36}" y="${ly+13}" fill="#e2e8f0" font-size="7.5">${l.file}</text>`;
    svg += `<text x="${mx+mw-14}" y="${ly+13}" text-anchor="end" fill="#64748b" font-size="6.5">${l.scope} · ${l.load_timing}</text>`;
    ly += 22;
  });
  // Hybrid search
  ly += 4;
  svg += `<text x="${mx+12}" y="${ly}" fill="#94a3b8" font-size="7" font-weight="600">HYBRID SEARCH</text>`;
  const vw = memSearch.vector_weight ? (memSearch.vector_weight * 100) : 70;
  const tw = memSearch.text_weight ? (memSearch.text_weight * 100) : 30;
  svg += `<rect x="${mx+90}" y="${ly-8}" width="60" height="10" rx="2" fill="#0d1321" stroke="#1e293b" stroke-width="0.5"/>`;
  svg += `<rect x="${mx+90}" y="${ly-8}" width="${60*vw/100}" height="10" rx="2" fill="#06b6d440"/>`;
  svg += `<text x="${mx+155}" y="${ly}" fill="#64748b" font-size="6.5">Vector ${vw}% / Text ${tw}%</text>`;
  // Flush
  ly += 16;
  svg += `<text x="${mx+12}" y="${ly}" fill="#94a3b8" font-size="7" font-weight="600">AUTO FLUSH</text>`;
  svg += `<text x="${mx+70}" y="${ly}" fill="#64748b" font-size="6.5">${memFlush.trigger || ''}</text>`;
  // Security rules
  ly += 14;
  memRules.forEach(r => {
    svg += `<text x="${mx+12}" y="${ly}" fill="#f8717180" font-size="6.5">⚠ ${r}</text>`;
    ly += 11;
  });
  // Footer
  svg += `<text x="${mx+mw/2}" y="${my+mh-6}" text-anchor="middle" fill="#06b6d440" font-size="7">${memComp.introduced || '2026-01'}  ▸ View Memory System Details</text>`;
  svg += `</g>`;
  // Agent ↔ Memory
  svg += arrow(ax+aw/2, ay+ah, mx+mw/2, my, '#06b6d4', false);

  // ════════════════════════════════════════
  // SANDBOX → Basic Architecture
  // ════════════════════════════════════════
  const sbx = 545, sby = sy + sh + 12, sbw = 240, sbh = 55;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-architecture')">`;
  svg += box(sbx, sby, sbw, sbh, 'rgba(239,68,68,0.05)', '#ef444430', 10);
  svg += `<text x="${sbx+16}" y="${sby+17}" fill="#ef4444" font-size="10">🛡️</text>`;
  svg += `<text x="${sbx+32}" y="${sby+17}" fill="#f87171" font-size="10" font-weight="700">SANDBOX</text>`;
  svg += `<text x="${sbx+16}" y="${sby+33}" fill="#94a3b8" font-size="8">Docker/Podman Container Isolation · Workspace Separation</text>`;
  svg += `<text x="${sbx+16}" y="${sby+47}" fill="#64748b" font-size="7">${sandComp.introduced || '2026-01'}  ▸ Details</text>`;
  svg += `</g>`;
  // Skills → Sandbox
  svg += arrow(sx+sw/2, sy+sh, sbx+sbw/2, sby, '#ef4444', false);

  // ════════════════════════════════════════
  // CONTROL UI / TUI → Basic CLI
  // ════════════════════════════════════════
  const cux = 195, cuy = 380, cuw = 100, cuh = 70;
  svg += `<g style="cursor:pointer" onclick="navigateToBasicSection('basic-section-cli')">`;
  svg += box(cux, cuy, cuw, cuh, 'rgba(99,102,241,0.06)', '#6366f140', 8);
  svg += `<text x="${cux+cuw/2}" y="${cuy+18}" text-anchor="middle" fill="#818cf8" font-size="12">📊</text>`;
  svg += `<text x="${cux+cuw/2}" y="${cuy+34}" text-anchor="middle" fill="#818cf8" font-size="9" font-weight="700">CONTROL UI</text>`;
  svg += `<text x="${cux+cuw/2}" y="${cuy+48}" text-anchor="middle" fill="#94a3b8" font-size="7.5">Web Dashboard</text>`;
  svg += `<text x="${cux+cuw/2}" y="${cuy+60}" text-anchor="middle" fill="#94a3b8" font-size="7.5">TUI / CLI  ▸</text>`;
  svg += `</g>`;
  // Gateway ↔ Control UI
  svg += arrow(gx+gw/2, gy+gh, cux+cuw/2, cuy, '#6366f1', true);

  // ════════════════════════════════════════
  // Agentic Loop label (bottom)
  // ════════════════════════════════════════
  svg += `<rect x="200" y="${H-42}" width="560" height="28" rx="14" fill="rgba(0,228,167,0.06)" stroke="#00e6a720" stroke-width="1"/>`;
  svg += `<text x="${cx}" y="${H-24}" text-anchor="middle" fill="#00e6a7" font-size="10" font-weight="600">↻ Agentic Loop &amp; Proactive Monitoring</text>`;

  // ════════════════════════════════════════
  // Security perimeter
  // ════════════════════════════════════════
  svg += `<rect x="185" y="125" width="610" height="440" rx="12" fill="none" stroke="#ef444425" stroke-width="1.5" stroke-dasharray="4,4"/>`;
  svg += `<text x="190" y="120" fill="#ef444450" font-size="7" font-weight="600">SECURITY PERIMETER (Sandbox + GuardClaw + Policy Enforcement)</text>`;

  // ════════════════════════════════════════
  // ECOSYSTEM EXTENSIONS (bottom row)
  // ════════════════════════════════════════
  const ecoY = 630;
  svg += `<text x="${cx}" y="${ecoY}" text-anchor="middle" fill="#64748b" font-size="11" font-weight="600">─── ECOSYSTEM EXTENSIONS ───</text>`;

  // Collect ecosystem data for counts
  const ecoRepos = DATA.ecosystem.repos || [];
  const hwRepos = ecoRepos.filter(r => r.category === 'hardware');
  const cloudRepos = ecoRepos.filter(r => r.category === 'cloud-hosted');
  const chinaRepos = ecoRepos.filter(r => r.category === 'china-ecosystem');

  // ─── HARDWARE / IoT ───
  const hwx = 10, hwy = ecoY + 14, hww = 290, hwh = 160;
  svg += `<g style="cursor:pointer" onclick="navigateToTab('ecosystem','hardware')">`;
  svg += box(hwx, hwy, hww, hwh, 'rgba(245,158,11,0.06)', '#f59e0b40', 10);
  svg += `<text x="${hwx+hww/2}" y="${hwy+18}" text-anchor="middle" fill="#f59e0b" font-size="13">🔌</text>`;
  svg += `<text x="${hwx+hww/2}" y="${hwy+34}" text-anchor="middle" fill="#fbbf24" font-size="11" font-weight="700">HARDWARE / IoT</text>`;
  svg += `<text x="${hwx+hww/2}" y="${hwy+48}" text-anchor="middle" fill="#94a3b8" font-size="8">${hwRepos.length} repos — Embedded AI Agents</text>`;
  const hwItems = [
    { icon: '📟', name: 'ESP32-Claw / MimiClaw', desc: '$5 MCU agent, WiFi/BLE' },
    { icon: '🤖', name: 'RoboClaw Agent', desc: 'Robot motor control AI' },
    { icon: '🏠', name: 'HomeClaw / SmartClaw', desc: 'Smart home hub agent' },
    { icon: '📡', name: 'IoTClaw / DeviceClaw', desc: 'IoT device management' },
    { icon: '🖥️', name: 'BoardClaw', desc: 'Raspberry Pi / SBC agent' }
  ];
  hwItems.forEach((item, i) => {
    const iy = hwy + 58 + i * 18;
    svg += `<text x="${hwx+14}" y="${iy}" fill="#fde68a" font-size="8">${item.icon} ${item.name}</text>`;
    svg += `<text x="${hwx+hww-10}" y="${iy}" text-anchor="end" fill="#64748b" font-size="7">${item.desc}</text>`;
  });
  svg += `<text x="${hwx+hww/2}" y="${hwy+hwh-8}" text-anchor="middle" fill="#f59e0b40" font-size="7">▸ View Hardware Ecosystem</text>`;
  svg += `</g>`;
  // Arrow: Hardware → Local Machine (via Skills/Sandbox)
  svg += `<line x1="${hwx+hww/2}" y1="${hwy}" x2="${sbx+sbw/2}" y2="${sby+sbh}" stroke="#f59e0b" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#af59e0b)"/>`;

  // ─── CLOUD / HOSTED ───
  const clx = 320, cly = ecoY + 14, clw = 290, clh = 160;
  svg += `<g style="cursor:pointer" onclick="navigateToTab('ecosystem','cloud-hosted')">`;
  svg += box(clx, cly, clw, clh, 'rgba(99,102,241,0.06)', '#6366f140', 10);
  svg += `<text x="${clx+clw/2}" y="${cly+18}" text-anchor="middle" fill="#818cf8" font-size="13">☁️</text>`;
  svg += `<text x="${clx+clw/2}" y="${cly+34}" text-anchor="middle" fill="#a5b4fc" font-size="11" font-weight="700">CLOUD / HOSTED</text>`;
  svg += `<text x="${clx+clw/2}" y="${cly+48}" text-anchor="middle" fill="#94a3b8" font-size="8">${cloudRepos.length} repos — Managed Agent Platforms</text>`;
  const clItems = [
    { icon: '🌩️', name: 'CloudClaw', desc: 'Managed cloud platform' },
    { icon: '⚡', name: 'ServerlessClaw', desc: 'Lambda/Cloud Functions' },
    { icon: '🔧', name: 'Claw API Server', desc: 'REST/GraphQL API' },
    { icon: '💼', name: 'HostedClaw / Claw SaaS', desc: 'Multi-tenant SaaS' },
    { icon: '🔶', name: 'MoltWorker (Cloudflare)', desc: 'Workers serverless' }
  ];
  clItems.forEach((item, i) => {
    const iy = cly + 58 + i * 18;
    svg += `<text x="${clx+14}" y="${iy}" fill="#c4b5fd" font-size="8">${item.icon} ${item.name}</text>`;
    svg += `<text x="${clx+clw-10}" y="${iy}" text-anchor="end" fill="#64748b" font-size="7">${item.desc}</text>`;
  });
  svg += `<text x="${clx+clw/2}" y="${cly+clh-8}" text-anchor="middle" fill="#6366f140" font-size="7">▸ View Cloud Ecosystem</text>`;
  svg += `</g>`;
  // Arrow: Cloud → External LLM API
  svg += `<line x1="${clx+clw/2}" y1="${cly}" x2="${llmx+llmw/2}" y2="${llmy+llmh}" stroke="#6366f1" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" marker-end="url(#a6366f1)"/>`;

  // ─── CHINA ECOSYSTEM ───
  const cnx = 630, cny = ecoY + 14, cnw = 320, cnh = 160;
  svg += `<g style="cursor:pointer" onclick="navigateToTab('ecosystem','china-ecosystem')">`;
  svg += box(cnx, cny, cnw, cnh, 'rgba(239,68,68,0.05)', '#ef444430', 10);
  svg += `<text x="${cnx+cnw/2}" y="${cny+18}" text-anchor="middle" fill="#ef4444" font-size="13">🇨🇳</text>`;
  svg += `<text x="${cnx+cnw/2}" y="${cny+34}" text-anchor="middle" fill="#fca5a5" font-size="11" font-weight="700">CHINA ECOSYSTEM</text>`;
  svg += `<text x="${cnx+cnw/2}" y="${cny+48}" text-anchor="middle" fill="#94a3b8" font-size="8">${chinaRepos.length} repos — Big Tech Forks &amp; Compatible Agents</text>`;
  const cnItems = [
    { icon: '🌙', name: 'MaxClaw (MiniMax)', stars: '8.7K', desc: 'Hailuo multimodal' },
    { icon: '🛒', name: 'CoPaw (Alibaba/Qwen)', stars: '15.2K', desc: 'DingTalk/Taobao' },
    { icon: '🎵', name: 'ArkClaw (ByteDance)', stars: '11.3K', desc: 'Coze/TikTok' },
    { icon: '💬', name: 'WorkBuddy (Tencent)', stars: '9.8K', desc: 'WeChat Work' },
    { icon: '📚', name: 'AutoClaw (Zhipu/GLM)', stars: '7.6K', desc: 'AutoGLM web agent' }
  ];
  cnItems.forEach((item, i) => {
    const iy = cny + 58 + i * 18;
    svg += `<text x="${cnx+14}" y="${iy}" fill="#fca5a5" font-size="8">${item.icon} ${item.name}</text>`;
    svg += `<text x="${cnx+cnw/2+30}" y="${iy}" fill="#f8717180" font-size="7">★${item.stars}</text>`;
    svg += `<text x="${cnx+cnw-10}" y="${iy}" text-anchor="end" fill="#64748b" font-size="7">${item.desc}</text>`;
  });
  svg += `<text x="${cnx+cnw/2}" y="${cny+cnh-8}" text-anchor="middle" fill="#ef444440" font-size="7">▸ View China Ecosystem</text>`;
  svg += `</g>`;
  // Arrow: China → Agent Runtime (compatible forks)
  svg += `<line x1="${cnx}" y1="${cny}" x2="${rx+rw/2}" y2="${ry+rh}" stroke="#ef4444" stroke-width="1" stroke-dasharray="4,3" opacity="0.3" marker-end="url(#aef4444)"/>`;

  svg += `</svg>`;

  // ─── 8-Layer Reference below diagram ───
  const layers = DATA.components || [];
  const colors = ['#a78bfa','#60a5fa','#f59e0b','#10b981','#06b6d4','#6366f1','#8b5cf6','#ef4444'];
  let layerRef = `<div class="mt-4 grid grid-cols-2 md:grid-cols-4 gap-2">`;
  layers.forEach((comp, i) => {
    const repos = DATA.repos.filter(r => r.layer === comp.id);
    const tCount = new Set(repos.flatMap(r => r.threat_ids || [])).size;
    layerRef += `
      <div class="px-3 py-2 rounded-lg cursor-pointer hover:opacity-80" style="background:rgba(255,255,255,0.02);border:1px solid ${colors[i]}30" onclick="showArchLayer('${comp.id}')">
        <div class="flex items-center gap-2 mb-1">
          <span class="w-2 h-2 rounded-full" style="background:${colors[i]}"></span>
          <span class="text-xs font-bold" style="color:${colors[i]}">${comp.code}. ${comp.name}</span>
        </div>
        <div class="text-xs text-gray-500">${comp.description}</div>
        <div class="flex gap-3 mt-1">
          <span class="text-xs text-gray-600">${repos.length} modules</span>
          ${tCount > 0 ? `<span class="text-xs" style="color:#ff6b7a">${tCount} threats</span>` : ''}
        </div>
      </div>
    `;
  });
  layerRef += `</div>`;

  el.innerHTML = renderArchViewToggle() + svg + '<div id="kc-detail-container"></div>' + layerRef;

  // Render initial overlay if mode is not structure
  if (archViewMode !== 'structure') {
    setTimeout(() => { renderArchOverlay(); renderArchDefensePanel(); }, 50);
  }
}

function showArchLayer(layerId) {
  const panel = document.getElementById('arch-layer-detail');
  const titleEl = document.getElementById('arch-layer-title');
  const bodyEl = document.getElementById('arch-layer-body');
  if (!panel || !titleEl || !bodyEl) return;

  const comp = DATA.components.find(c => c.id === layerId);
  if (!comp) return;

  const repos = DATA.repos.filter(r => r.layer === layerId);
  const threatIds = [...new Set(repos.flatMap(r => r.threat_ids || []))];
  const threats = threatIds.map(tid => DATA.threats.find(t => t.id === tid)).filter(Boolean);
  const controlIds = [...new Set(repos.flatMap(r => r.control_ids || []))];
  const controls = controlIds.map(cid => DATA.controls.find(c => c.id === cid)).filter(Boolean);
  const gaps = repos.flatMap(r => findControlGaps(r));
  const missingIds = [...new Set(gaps.flatMap(g => g.missing))];

  titleEl.innerHTML = `${comp.code}. ${comp.name}`;

  bodyEl.innerHTML = `
    <p class="text-sm text-gray-400 mb-4">${comp.description}</p>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
      <div class="p-3 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
        <div class="text-xs text-gray-500 mb-2">Modules (${repos.length})</div>
        <div class="space-y-1" style="max-height:200px;overflow-y:auto">
          ${repos.map(r => `<div class="flex items-center gap-2">
            <span class="risk-badge risk-${calcRiskLevel(r)}" style="font-size:9px;padding:1px 5px">${calcRiskLevel(r)}</span>
            <span class="text-xs">${r.name}</span>
          </div>`).join('')}
        </div>
      </div>
      <div class="p-3 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
        <div class="text-xs text-gray-500 mb-2">Threats (${threats.length})</div>
        <div class="space-y-1" style="max-height:200px;overflow-y:auto">
          ${threats.map(t => `<div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full flex-shrink-0" style="background:${severityColor(t.severity)}"></span>
            <span class="text-xs">${t.name}</span>
          </div>`).join('')}
        </div>
      </div>
      <div class="p-3 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
        <div class="text-xs text-gray-500 mb-2">Controls (${controls.length}) ${missingIds.length > 0 ? `<span style="color:#ff6b7a">/ ${missingIds.length} gaps</span>` : ''}</div>
        <div class="space-y-1" style="max-height:200px;overflow-y:auto">
          ${controls.map(c => `<div class="text-xs flex items-center gap-1">
            <span style="color:#00e6a7">✓</span> ${c.name}
          </div>`).join('')}
          ${missingIds.map(mid => {
            const mc = DATA.controls.find(c => c.id === mid);
            return mc ? `<div class="text-xs flex items-center gap-1"><span style="color:#ff6b7a">✗</span> <span style="color:#ff6b7a80">${mc.name}</span></div>` : '';
          }).join('')}
        </div>
      </div>
    </div>
    <div class="flex gap-2">
      <button class="text-xs px-3 py-1.5 rounded-lg" style="background:rgba(0,228,167,0.1);color:#00e6a7;border:1px solid #00e6a730" onclick="navigateToTab('directory')">View in Risk/Threat →</button>
      <button class="text-xs px-3 py-1.5 rounded-lg" style="background:rgba(99,102,241,0.1);color:#818cf8;border:1px solid #6366f130" onclick="navigateToTab('security')">View Security Review →</button>
    </div>
  `;
  panel.classList.remove('hidden');
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderArchDataflow() {
  const el = document.getElementById('arch-dataflow');
  if (!el) return;

  const supplyChain = DATA.ecosystem.dependency_network?.supply_chain;
  const flow = supplyChain ? supplyChain.flow : ['GitHub Repos', 'ClawHub Registry', 'OpenClaw Agent', 'Local Execution'];
  const archComps = DATA.basic.architecture?.components || [];

  el.innerHTML = `
    <div class="mb-4">
      <div class="text-xs text-gray-500 mb-2 font-semibold">Supply Chain Flow</div>
      <div class="flex items-center flex-wrap gap-1">
        ${flow.map((step, i) => `
          <span class="text-xs px-3 py-1.5 rounded-lg font-semibold" style="background:rgba(0,228,167,${0.06 + i*0.04});border:1px solid #00e6a720;color:#00e6a7">${step}</span>
          ${i < flow.length - 1 ? '<span style="color:#00e6a740">→</span>' : ''}
        `).join('')}
      </div>
      ${supplyChain?.risk ? `<div class="text-xs mt-2" style="color:#ff6b7a">⚠ ${supplyChain.risk}</div>` : ''}
    </div>
    <div>
      <div class="text-xs text-gray-500 mb-2 font-semibold">Core Components</div>
      <div class="space-y-2" style="max-height:320px;overflow-y:auto">
        ${archComps.map(c => `
          <div class="flex items-start gap-3 px-3 py-2 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
            <span class="text-xs font-bold whitespace-nowrap" style="color:#00d4aa;min-width:90px">${c.name}</span>
            <span class="text-xs text-gray-400 flex-1">${c.description}</span>
            <span class="text-xs text-gray-600 whitespace-nowrap">${c.introduced || ''}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderArchDeps() {
  const el = document.getElementById('arch-deps');
  if (!el) return;

  const net = DATA.ecosystem.dependency_network || {};
  const depTypes = net.dependency_types || [];
  const chars = net.network_characteristics || {};

  el.innerHTML = `
    <div class="mb-3 px-3 py-2 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
      <div class="flex items-center gap-2 mb-1">
        <span class="text-xs font-bold" style="color:#00d4aa">Topology:</span>
        <span class="text-sm font-semibold text-gray-300">${chars.topology || 'Hub-and-Spoke'}</span>
        <span class="text-xs text-gray-500">|</span>
        <span class="text-xs text-gray-400">${chars.properties || 'Scale-Free Network'}</span>
      </div>
      ${chars.vulnerability ? `<div class="text-xs" style="color:#ff6b7a80">⚠ ${chars.vulnerability}</div>` : ''}
    </div>
    <div class="space-y-2" style="max-height:360px;overflow-y:auto">
      ${depTypes.map(d => `
        <div class="px-3 py-2 rounded-lg" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e">
          <div class="flex items-center gap-2 mb-1">
            <span>${d.icon || ''}</span>
            <span class="text-xs font-bold text-gray-300">${d.name}</span>
          </div>
          <div class="text-xs text-gray-500 mb-1">${d.description}</div>
          <div class="text-xs font-mono" style="color:#00e6a780">${d.flow}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderArchThreatLayer() {
  const el = document.getElementById('arch-threat-layer');
  if (!el) return;

  const layerIds = DATA.components.map(c => c.id);
  const layerCodes = DATA.components.map(c => c.code);
  const threats = DATA.threats.filter(t => t.severity === 'critical' || t.severity === 'high');
  const colors = ['#a78bfa','#60a5fa','#f59e0b','#10b981','#06b6d4','#6366f1','#8b5cf6','#ef4444'];

  let html = `<table style="width:100%;border-collapse:collapse;font-size:11px">
    <thead><tr>
      <th class="text-left p-2" style="border-bottom:1px solid #1e293b;color:#94a3b8;min-width:140px">Threat</th>
      ${layerCodes.map((code, i) => `<th class="text-center p-2" style="border-bottom:1px solid #1e293b;color:${colors[i]};width:40px" title="${DATA.components[i].name}">${code}</th>`).join('')}
    </tr></thead><tbody>`;

  threats.forEach(t => {
    const affected = t.affected_layers || [];
    html += `<tr>
      <td class="p-2" style="border-bottom:1px solid #0d1321">
        <span class="w-2 h-2 rounded-full inline-block mr-1" style="background:${severityColor(t.severity)}"></span>
        ${t.name}
      </td>
      ${layerIds.map(lid => {
        const hit = affected.includes(lid);
        return `<td class="text-center p-2" style="border-bottom:1px solid #0d1321">${hit ? '<span style="color:#ff6b7a">●</span>' : '<span style="color:#1e293b">·</span>'}</td>`;
      }).join('')}
    </tr>`;
  });

  html += `</tbody></table>`;
  el.innerHTML = html;
}

function renderArchLayerSecurity() {
  const el = document.getElementById('arch-layer-security');
  if (!el) return;

  const colors = ['#a78bfa','#60a5fa','#f59e0b','#10b981','#06b6d4','#6366f1','#8b5cf6','#ef4444'];

  el.innerHTML = DATA.components.map((comp, i) => {
    const repos = DATA.repos.filter(r => r.layer === comp.id);
    const totalThreats = new Set(repos.flatMap(r => r.threat_ids || [])).size;
    const totalControls = new Set(repos.flatMap(r => r.control_ids || [])).size;
    const totalGaps = repos.reduce((s, r) => s + findControlGaps(r).length, 0);
    const coverage = totalThreats > 0 ? Math.round(totalControls / (totalControls + totalGaps) * 100) : 100;
    const barColor = coverage >= 80 ? '#00e6a7' : coverage >= 50 ? '#ffc312' : '#ff4757';

    return `
      <div class="flex items-center gap-3 cursor-pointer hover:opacity-80" onclick="showArchLayer('${comp.id}')">
        <span class="text-xs font-bold w-5 text-center" style="color:${colors[i]}">${comp.code}</span>
        <span class="text-xs flex-1 truncate" title="${comp.name}">${comp.name}</span>
        <span class="text-xs text-gray-500 w-16 text-right">${repos.length} mod</span>
        <div class="w-24 progress-bar">
          <div class="progress-fill" style="width:${coverage}%;background:${barColor}"></div>
        </div>
        <span class="text-xs w-10 text-right" style="color:${barColor}">${coverage}%</span>
      </div>
    `;
  }).join('');
}


// Architecture view modes
const archViewModes = [
  { id: 'structure', label: '📐 Structure', title: 'Default architecture view' },
  { id: 'usecase', label: '🔄 Use Cases', title: 'Normal use case flow visualization' },
  { id: 'heatmap', label: '🔥 Heatmap', title: 'Threat density heatmap' },
  { id: 'cve', label: '🛡 CVE Map', title: 'CVE indicators per zone' },
  { id: 'attack', label: '⚔️ Attack Flow', title: 'Attack scenario animation' },
  { id: 'threat', label: '⚠️ Threats', title: 'Threat type mapping per zone' },
  { id: 'defense', label: '🏰 Defense', title: 'Defense coverage matrix' },
  { id: 'risk', label: '📊 Risk Score', title: 'Risk score overlay' },
  { id: 'killchain', label: '🔗 Kill Chain', title: 'Kill chain flow visualization' }
];

// Normal use case flows for architecture visualization
const archUseCases = [
  { id: 'chat', name: '💬 채팅 대화', description: '사용자가 메시지를 보내고 AI 응답을 받는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자가 Slack/Discord/Web으로 메시지 전송', phase: 'input' },
      { zone: 'Gateway', label: '게이트웨이가 인증 및 요청 라우팅', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 메시지 처리 및 액션 결정', phase: 'processing' },
      { zone: 'Memory Engine', label: '대화 컨텍스트 및 지식 검색', phase: 'memory' },
      { zone: 'Agent Runtime', label: '컨텍스트 기반 응답 생성', phase: 'processing' },
      { zone: 'Gateway', label: '응답 포맷팅 및 전달', phase: 'routing' },
      { zone: 'Channel Adapters', label: '사용자가 응답 수신', phase: 'output' }
    ]},
  { id: 'skill', name: '🔧 스킬 실행', description: '에이전트가 스킬/도구를 호출하여 작업을 완료하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자가 파일 작업 요청', phase: 'input' },
      { zone: 'Gateway', label: '요청 인증 완료', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 도구 사용 계획 수립', phase: 'processing' },
      { zone: 'Plugin System', label: '스킬 로드 및 검증', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스에서 스킬 실행', phase: 'execution' },
      { zone: 'Plugin System', label: '결과 캡처', phase: 'skill' },
      { zone: 'Agent Runtime', label: '결과 해석 및 응답 구성', phase: 'processing' },
      { zone: 'Channel Adapters', label: '사용자에게 결과 전달', phase: 'output' }
    ]},
  { id: 'memory', name: '🧠 메모리 및 학습', description: '에이전트가 학습한 지식을 저장하고 검색하는 흐름',
    steps: [
      { zone: 'Agent Runtime', label: '대화 중 새로운 정보 식별', phase: 'processing' },
      { zone: 'Memory Engine', label: '벡터 임베딩 생성', phase: 'memory' },
      { zone: 'Memory Engine', label: '영구 메모리에 저장 (Vector + BM25)', phase: 'memory' },
      { zone: 'Agent Runtime', label: '이후: 새로운 쿼리 도착', phase: 'processing' },
      { zone: 'Memory Engine', label: '하이브리드 검색으로 관련 메모리 검색', phase: 'memory' },
      { zone: 'Agent Runtime', label: '컨텍스트 강화 응답 생성', phase: 'processing' }
    ]},
  { id: 'multi-channel', name: '📡 멀티 채널 라우팅', description: '동일한 에이전트가 여러 채널을 동시에 지원하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: 'Slack, Discord, Web에서 메시지 도착', phase: 'input' },
      { zone: 'Gateway', label: '채널별 인증 및 정규화', phase: 'routing' },
      { zone: 'Agent Runtime', label: '채널에 관계없이 통합 처리', phase: 'processing' },
      { zone: 'Memory Engine', label: '채널 간 공유 메모리', phase: 'memory' },
      { zone: 'Agent Runtime', label: '채널에 적합한 응답 포맷팅', phase: 'processing' },
      { zone: 'Gateway', label: '올바른 채널 어댑터로 라우팅', phase: 'routing' },
      { zone: 'Channel Adapters', label: '해당 채널을 통해 전달', phase: 'output' }
    ]},
  { id: 'admin', name: '⚙️ 관리 및 모니터링', description: '관리자가 에이전트를 모니터링하고 제어하는 흐름',
    steps: [
      { zone: 'Control UI', label: '관리자가 대시보드 열기', phase: 'admin' },
      { zone: 'Agent Runtime', label: '에이전트 상태 및 메트릭 조회', phase: 'processing' },
      { zone: 'Memory Engine', label: '사용 로그 및 메모리 통계 조회', phase: 'memory' },
      { zone: 'Plugin System', label: '설치된 스킬 및 권한 목록 조회', phase: 'skill' },
      { zone: 'Control UI', label: '관리자가 권한/정책 조정', phase: 'admin' },
      { zone: 'Gateway', label: '업데이트된 정책 전파', phase: 'routing' }
    ]},
  { id: 'file-ops', name: '📁 로컬 파일 작업', description: '에이전트가 스킬을 통해 로컬 머신의 파일을 읽기/쓰기하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자 요청: "config.yaml을 읽고 요약해줘"', phase: 'input' },
      { zone: 'Gateway', label: '요청 인증 및 전달', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 파일시스템 스킬 사용 결정', phase: 'processing' },
      { zone: 'Plugin System', label: 'skill-filesystem 로드, 경로 검증', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스 환경에서 파일 읽기 실행', phase: 'execution' },
      { zone: 'Local Machine', label: '로컬 파일시스템에서 config.yaml 읽기', phase: 'local' },
      { zone: 'Sandbox', label: '파일 내용이 샌드박스로 반환', phase: 'execution' },
      { zone: 'Plugin System', label: '결과가 에이전트로 전달', phase: 'skill' },
      { zone: 'Agent Runtime', label: '에이전트가 파일 내용 요약', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 요약 응답 생성', phase: 'llm' },
      { zone: 'Agent Runtime', label: '응답 조합', phase: 'processing' },
      { zone: 'Channel Adapters', label: '사용자에게 요약 전달', phase: 'output' }
    ]},
  { id: 'web-browse', name: '🌐 웹 브라우징 및 스크래핑', description: '에이전트가 웹 페이지를 탐색하고 정보를 추출하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자 요청: "AI 보안 최신 뉴스 확인해줘"', phase: 'input' },
      { zone: 'Gateway', label: '에이전트로 요청 라우팅', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 브라우저 스킬 사용 계획', phase: 'processing' },
      { zone: 'Plugin System', label: 'URL 대상으로 skill-browser 로드', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스에서 Chromium 실행', phase: 'execution' },
      { zone: 'Local Machine', label: '브라우저가 대상 웹사이트로 이동', phase: 'local' },
      { zone: 'Sandbox', label: '페이지 콘텐츠 추출 및 정제', phase: 'execution' },
      { zone: 'Plugin System', label: '추출된 콘텐츠 반환', phase: 'skill' },
      { zone: 'Agent Runtime', label: '에이전트가 웹 콘텐츠 처리', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 콘텐츠 분석 및 요약', phase: 'llm' },
      { zone: 'Memory Engine', label: '향후 참조를 위해 주요 발견사항 저장', phase: 'memory' },
      { zone: 'Agent Runtime', label: '발견사항 포함 응답 구성', phase: 'processing' },
      { zone: 'Channel Adapters', label: '사용자에게 분석 결과 전달', phase: 'output' }
    ]},
  { id: 'llm-reasoning', name: '🤖 LLM 기반 추론', description: '에이전트가 복잡한 추론 작업을 위해 외부 LLM을 사용하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자 질문: "이 코드의 취약점을 분석해줘"', phase: 'input' },
      { zone: 'Gateway', label: '요청 인증, 토큰 카운트', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 컨텍스트 포함 프롬프트 준비', phase: 'processing' },
      { zone: 'Memory Engine', label: '과거 분석 및 패턴 검색', phase: 'memory' },
      { zone: 'Agent Runtime', label: 'LLM용 강화 프롬프트 구성', phase: 'processing' },
      { zone: 'External LLM API', label: '심층 분석을 위해 Claude/GPT API 호출', phase: 'llm' },
      { zone: 'External LLM API', label: 'LLM이 취약점 평가 반환', phase: 'llm' },
      { zone: 'Agent Runtime', label: '에이전트가 LLM 응답 검증 및 포맷팅', phase: 'processing' },
      { zone: 'Memory Engine', label: '향후 사용을 위해 분석 결과 캐시', phase: 'memory' },
      { zone: 'Channel Adapters', label: '사용자에게 취약점 보고서 전달', phase: 'output' }
    ]},
  { id: 'code-execute', name: '💻 코드 실행', description: '에이전트가 로컬 머신에서 코드를 작성하고 실행하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자 요청: "데이터 처리용 Python 스크립트 실행해줘"', phase: 'input' },
      { zone: 'Gateway', label: '실행 권한 확인과 함께 요청 라우팅', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 Python 코드 생성', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 코드 생성/검토', phase: 'llm' },
      { zone: 'Plugin System', label: '코드 페이로드로 skill-python 로드', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스에서 Python 인터프리터 실행', phase: 'execution' },
      { zone: 'Local Machine', label: '스크립트가 입력 파일 읽기 및 데이터 처리', phase: 'local' },
      { zone: 'Local Machine', label: '출력 파일이 로컬 파일시스템에 기록', phase: 'local' },
      { zone: 'Sandbox', label: '실행 결과 및 출력 캡처', phase: 'execution' },
      { zone: 'Plugin System', label: '에이전트로 결과 반환', phase: 'skill' },
      { zone: 'Agent Runtime', label: '에이전트가 실행 결과 해석', phase: 'processing' },
      { zone: 'Channel Adapters', label: '사용자에게 결과 및 출력 전달', phase: 'output' }
    ]},
  { id: 'multi-agent', name: '🤝 멀티 에이전트 오케스트레이션', description: '주 에이전트가 전문 에이전트에게 하위 작업을 위임하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: '사용자 요청: "AI 보안 트렌드를 조사하고 보고서 작성해줘"', phase: 'input' },
      { zone: 'Gateway', label: '주 오케스트레이터 에이전트로 요청 라우팅', phase: 'routing' },
      { zone: 'Agent Runtime', label: '오케스트레이터가 작업을 하위 작업으로 분해', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 작업 분해 전략 계획', phase: 'llm' },
      { zone: 'Agent Runtime', label: '리서치 에이전트 생성 → 웹 검색 하위 작업', phase: 'processing' },
      { zone: 'Plugin System', label: '리서치 에이전트가 skill-browser 사용', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스에서 웹 스크래핑 실행', phase: 'execution' },
      { zone: 'Local Machine', label: '브라우저가 여러 웹 소스 가져오기', phase: 'local' },
      { zone: 'Agent Runtime', label: '작성 에이전트 생성 → 보고서 하위 작업', phase: 'processing' },
      { zone: 'External LLM API', label: '작성 에이전트가 콘텐츠 생성을 위해 LLM 호출', phase: 'llm' },
      { zone: 'Memory Engine', label: '두 에이전트가 메모리를 통해 컨텍스트 공유', phase: 'memory' },
      { zone: 'Agent Runtime', label: '오케스트레이터가 하위 에이전트 결과 병합', phase: 'processing' },
      { zone: 'Plugin System', label: 'skill-filesystem이 최종 보고서 작성', phase: 'skill' },
      { zone: 'Local Machine', label: '보고서가 report.md로 저장', phase: 'local' },
      { zone: 'Channel Adapters', label: '사용자에게 요약과 함께 보고서 전달', phase: 'output' }
    ]},
  { id: 'voice-call', name: '📞 사용자 음성 통화', description: '에이전트가 음성 채널을 사용하여 아웃바운드 전화를 거는 흐름',
    steps: [
      { zone: 'Agent Runtime', label: '예약된 알림 트리거: 중요 보안 이벤트', phase: 'processing' },
      { zone: 'Memory Engine', label: '사용자 연락처 설정 및 전화번호 검색', phase: 'memory' },
      { zone: 'Agent Runtime', label: '음성 메시지 내용 준비', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 자연스러운 음성 스크립트 생성', phase: 'llm' },
      { zone: 'Plugin System', label: 'TTS 페이로드로 skill-voice-call 로드', phase: 'skill' },
      { zone: 'Gateway', label: '정책 엔진을 통해 아웃바운드 통화 승인', phase: 'routing' },
      { zone: 'Channel Adapters', label: '음성 채널이 Twilio/VAPI를 통해 전화 발신', phase: 'output' },
      { zone: 'Channel Adapters', label: '사용자 응답 — TTS가 보안 알림 재생', phase: 'output' },
      { zone: 'Channel Adapters', label: '사용자가 음성 명령으로 응답', phase: 'input' },
      { zone: 'Gateway', label: 'STT가 사용자 응답 텍스트 변환', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 사용자 지시 처리', phase: 'processing' },
      { zone: 'Memory Engine', label: '감사 추적을 위해 상호작용 기록', phase: 'memory' },
      { zone: 'Channel Adapters', label: 'SMS를 통해 확인 메시지 전송', phase: 'output' }
    ]},
  { id: 'coding-assist', name: '👨‍💻 인터랙티브 코딩 어시스턴트', description: '에이전트가 IDE에서 사용자의 코드 작성, 디버깅, 테스트를 지원하는 흐름',
    steps: [
      { zone: 'Channel Adapters', label: 'VS Code에서 사용자: "auth.py 42번 줄의 버그 수정해줘"', phase: 'input' },
      { zone: 'Gateway', label: 'IDE 확장이 에이전트로 요청 라우팅', phase: 'routing' },
      { zone: 'Agent Runtime', label: '에이전트가 코딩 요청 분석', phase: 'processing' },
      { zone: 'Plugin System', label: 'skill-filesystem이 auth.py 소스 코드 읽기', phase: 'skill' },
      { zone: 'Local Machine', label: '프로젝트 디렉토리에서 파일 내용 읽기', phase: 'local' },
      { zone: 'Memory Engine', label: '프로젝트 컨텍스트 및 과거 수정 이력 검색', phase: 'memory' },
      { zone: 'External LLM API', label: 'LLM이 코드 분석, 버그 식별, 수정 생성', phase: 'llm' },
      { zone: 'Agent Runtime', label: '에이전트가 제안된 수정 검증', phase: 'processing' },
      { zone: 'Plugin System', label: 'skill-filesystem이 패치된 auth.py 기록', phase: 'skill' },
      { zone: 'Local Machine', label: '수정된 파일 디스크에 저장', phase: 'local' },
      { zone: 'Plugin System', label: 'skill-shell이 테스트 스위트 실행', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스 환경에서 pytest 실행', phase: 'execution' },
      { zone: 'Local Machine', label: '로컬 코드베이스에 대해 테스트 실행', phase: 'local' },
      { zone: 'Agent Runtime', label: '에이전트가 테스트 결과 검토 — 모두 통과', phase: 'processing' },
      { zone: 'Channel Adapters', label: '수정 적용, IDE에 diff 및 테스트 결과 표시', phase: 'output' }
    ]},
  { id: 'scheduled-digest', name: '⏰ 예약 일일 다이제스트', description: '에이전트가 캘린더, 뉴스, 소셜 미디어의 예약 요약을 전송하는 흐름',
    steps: [
      { zone: 'Agent Runtime', label: '매일 오전 7시에 크론 트리거 실행', phase: 'processing' },
      { zone: 'Plugin System', label: 'skill-api-connector가 Google Calendar API 호출', phase: 'skill' },
      { zone: 'External LLM API', label: '오늘의 회의 및 이벤트 가져오기', phase: 'llm' },
      { zone: 'Plugin System', label: 'skill-api-connector가 Twitter/X API 호출', phase: 'skill' },
      { zone: 'External LLM API', label: '트렌딩 토픽 및 팔로우 계정 가져오기', phase: 'llm' },
      { zone: 'Plugin System', label: 'skill-browser가 뉴스 헤드라인 스크래핑', phase: 'skill' },
      { zone: 'Sandbox', label: '샌드박스에서 브라우저 스크래핑', phase: 'execution' },
      { zone: 'Local Machine', label: '뉴스 웹사이트 접속', phase: 'local' },
      { zone: 'Memory Engine', label: '사용자 선호도 및 과거 다이제스트 피드백 검색', phase: 'memory' },
      { zone: 'Agent Runtime', label: '에이전트가 모든 데이터 소스 통합', phase: 'processing' },
      { zone: 'External LLM API', label: 'LLM이 개인화된 다이제스트 요약 생성', phase: 'llm' },
      { zone: 'Agent Runtime', label: '우선순위 및 하이라이트로 다이제스트 포맷팅', phase: 'processing' },
      { zone: 'Gateway', label: '멀티 채널 전달 준비', phase: 'routing' },
      { zone: 'Channel Adapters', label: 'Slack + 이메일을 통해 아침 다이제스트 전송', phase: 'output' }
    ]}
];

const zoneCVEMap = {
  'Gateway': ['CVE-2026-25253', 'CVE-2026-26377', 'CVE-2026-28458', 'CVE-2026-28466'],
  'Agent Runtime': ['CVE-2026-25253', 'CVE-2026-25688', 'CVE-2026-27113', 'CVE-2026-27324', 'CVE-2026-27455', 'CVE-2026-26377'],
  'Plugin System': ['CVE-2026-25254', 'CVE-2026-25255', 'CVE-2026-25256', 'CVE-2026-27113', 'CVE-2026-28479'],
  'Sandbox': ['CVE-2026-26376', 'CVE-2026-28468'],
  'Memory Engine': ['CVE-2026-25688', 'CVE-2026-27324', 'CVE-2026-28479'],
  'Control UI': ['CVE-2026-28466'],
  'Channel Adapters': ['CVE-2026-27661', 'CVE-2026-28458']
};

// Zone positions for overlays (derived from box() calls in renderArchDiagram)
const archZonePositions = {
  'Gateway': { x: 195, y: 130, w: 100, h: 130, id: 'gateway' },
  'Agent Runtime': { x: 310, y: 140, w: 210, h: 220, id: 'agent-runtime' },
  'Plugin System': { x: 545, y: 130, w: 240, h: 310, id: 'plugin-system' },
  'Sandbox': { x: 545, y: 452, w: 240, h: 55, id: 'sandbox' },
  'Memory Engine': { x: 270, y: 376, w: 290, h: 170, id: 'memory-engine' },
  'Control UI': { x: 195, y: 380, w: 100, h: 70, id: 'control-ui' },
  'Channel Adapters': { x: 10, y: 70, w: 150, h: 490, id: 'channel-adapters' },
  'External LLM API': { x: 350, y: 58, w: 260, h: 68, id: 'external-llm' },
  'Local Machine': { x: 800, y: 70, w: 150, h: 490, id: 'local-machine' },
  'Hardware/IoT': { x: 10, y: 644, w: 290, h: 160, id: 'hardware' },
  'Cloud/Hosted': { x: 320, y: 644, w: 290, h: 160, id: 'cloud-hosted' },
  'China Ecosystem': { x: 630, y: 644, w: 320, h: 160, id: 'china-ecosystem' }
};

function setArchViewMode(mode) {
  archViewMode = mode;
  // Update toggle button states
  document.querySelectorAll('.arch-view-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });
  // Render overlays
  renderArchOverlay();
  // Render defense panel below diagram
  renderArchDefensePanel();
}

function renderArchViewToggle() {
  let html = '<div class="flex flex-wrap gap-2 mb-3">';
  archViewModes.forEach(m => {
    const activeClass = m.id === archViewMode ? ' active' : '';
    html += `<button class="arch-view-btn${activeClass}" data-mode="${m.id}" title="${m.title}" onclick="setArchViewMode('${m.id}')">${m.label}</button>`;
  });
  html += '</div>';
  return html;
}

function renderArchOverlay() {
  const svgEl = document.querySelector('#arch-diagram svg');
  if (!svgEl) return;

  // Remove existing overlay group
  const existing = svgEl.querySelector('#arch-overlay');
  if (existing) existing.remove();

  // Remove existing popover
  const existingPop = document.querySelector('.arch-popover');
  if (existingPop) existingPop.remove();

  // Remove attack flow dropdown if not in attack mode
  const attackDropdown = document.getElementById('arch-attack-dropdown');
  if (attackDropdown && archViewMode !== 'attack') attackDropdown.style.display = 'none';
  if (attackDropdown && archViewMode === 'attack') attackDropdown.style.display = '';

  // Hide/show usecase dropdown
  const usecaseDropdown = document.getElementById('arch-usecase-dropdown');
  if (usecaseDropdown && archViewMode !== 'usecase') usecaseDropdown.style.display = 'none';
  if (usecaseDropdown && archViewMode === 'usecase') usecaseDropdown.style.display = '';

  // Remove kill chain detail panel when not in killchain mode
  if (archViewMode !== 'killchain') {
    const kcContainer = document.getElementById('kc-detail-container');
    if (kcContainer) kcContainer.innerHTML = '';
    killChainSelectedPhase = null;
  }

  if (archViewMode === 'structure') return;

  let overlay = '';

  if (archViewMode === 'cve') {
    overlay = renderCVEOverlay();
  } else if (archViewMode === 'heatmap') {
    overlay = renderHeatmapOverlay();
  } else if (archViewMode === 'attack') {
    overlay = renderAttackFlowOverlay();
  } else if (archViewMode === 'usecase') {
    overlay = renderUseCaseOverlay();
  } else if (archViewMode === 'threat') {
    overlay = renderThreatOverlay();
  } else if (archViewMode === 'risk') {
    overlay = renderRiskScoreOverlay();
  } else if (archViewMode === 'defense') {
    overlay = renderDefenseOverlay();
  } else if (archViewMode === 'killchain') {
    overlay = renderKillChainFlowOverlay();
  }

  if (overlay) {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('id', 'arch-overlay');
    g.innerHTML = overlay;
    svgEl.appendChild(g);
  }
}

function renderCVEOverlay() {
  let svg = '';
  Object.entries(zoneCVEMap).forEach(([zone, cves]) => {
    const pos = archZonePositions[zone];
    if (!pos) return;
    const cx = pos.x + pos.w - 8;
    const cy = pos.y + 8;
    svg += `<g class="cve-badge" style="cursor:pointer" onclick="showArchCVEPopover('${zone}', ${cx}, ${cy})">`;
    svg += `<circle cx="${cx}" cy="${cy}" r="12" fill="#ef4444" stroke="#0a0e1a" stroke-width="2"/>`;
    svg += `<text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#ffffff" font-size="10" font-weight="700">${cves.length}</text>`;
    svg += `</g>`;
  });
  return svg;
}

function showArchCVEPopover(zone, svgX, svgY) {
  // Remove existing popover
  const existing = document.querySelector('.arch-popover');
  if (existing) existing.remove();

  const cves = zoneCVEMap[zone] || [];
  if (cves.length === 0) return;

  const wrapper = document.getElementById('arch-diagram-wrapper');
  if (!wrapper) return;

  const svgEl = wrapper.querySelector('svg');
  if (!svgEl) return;
  const rect = svgEl.getBoundingClientRect();
  const wrapperRect = wrapper.getBoundingClientRect();
  const scaleX = rect.width / 960;
  const scaleY = rect.height / 820;

  const popX = (svgX * scaleX) + rect.left - wrapperRect.left + wrapper.scrollLeft + 16;
  const popY = (svgY * scaleY) + rect.top - wrapperRect.top + wrapper.scrollTop;

  const popover = document.createElement('div');
  popover.className = 'arch-popover';
  popover.style.cssText = `position:absolute;left:${popX}px;top:${popY}px;z-index:50;background:var(--bg-input,#0d1321);border:1px solid #ef444440;border-radius:8px;padding:12px;min-width:220px;max-width:300px;box-shadow:0 4px 20px rgba(0,0,0,0.5)`;
  popover.innerHTML = `
    <div class="flex items-center justify-between mb-2">
      <span class="text-xs font-bold" style="color:#f87171">${zone} - ${cves.length} CVEs</span>
      <button onclick="this.parentElement.parentElement.remove()" style="color:#64748b;font-size:14px;cursor:pointer;background:none;border:none">&times;</button>
    </div>
    <div class="space-y-1">
      ${cves.map(c => `<div class="text-xs" style="color:#fca5a5;font-family:monospace;padding:2px 0">\u2022 ${c}</div>`).join('')}
    </div>
  `;
  wrapper.style.position = 'relative';
  wrapper.appendChild(popover);
}

function renderHeatmapOverlay() {
  let svg = '';
  // Calculate threat density per zone from DATA.threats
  const zoneThreatCounts = {};
  const zoneScenarioCounts = {};

  Object.keys(archZonePositions).forEach(zone => {
    zoneThreatCounts[zone] = 0;
    zoneScenarioCounts[zone] = 0;
  });

  // Map threats to zones based on affected_layers
  const zoneToLayer = {
    'Gateway': 'gateway',
    'Agent Runtime': 'agent-runtime',
    'Plugin System': 'plugin-system',
    'Sandbox': 'sandbox',
    'Memory Engine': 'memory-engine',
    'Control UI': 'control-ui',
    'Channel Adapters': 'channel-adapters'
  };

  (DATA.threats || []).forEach(t => {
    const affected = t.affected_layers || [];
    Object.entries(zoneToLayer).forEach(([zone, layerId]) => {
      if (affected.includes(layerId)) {
        zoneThreatCounts[zone] = (zoneThreatCounts[zone] || 0) + 1;
      }
    });
  });

  // Map scenarios to zones
  (DATA.attacks.scenarios || []).forEach(s => {
    const threatIds = s.threat_ids || [];
    threatIds.forEach(tid => {
      const threat = DATA.threats.find(t => t.id === tid);
      if (!threat) return;
      const affected = threat.affected_layers || [];
      Object.entries(zoneToLayer).forEach(([zone, layerId]) => {
        if (affected.includes(layerId)) {
          zoneScenarioCounts[zone] = (zoneScenarioCounts[zone] || 0) + 1;
        }
      });
    });
  });

  const maxThreats = Math.max(...Object.values(zoneThreatCounts), 1);

  Object.entries(archZonePositions).forEach(([zone, pos]) => {
    const count = zoneThreatCounts[zone] || 0;
    const scenarios = zoneScenarioCounts[zone] || 0;
    const ratio = count / maxThreats;

    // Color gradient: green -> yellow -> orange -> red
    let color;
    if (ratio < 0.25) color = 'rgba(34,197,94,0.25)';
    else if (ratio < 0.5) color = 'rgba(234,179,8,0.3)';
    else if (ratio < 0.75) color = 'rgba(249,115,22,0.35)';
    else color = 'rgba(239,68,68,0.4)';

    const safeZone = zone.replace(/'/g, "\\'");
    svg += `<g class="heatmap-overlay" style="cursor:pointer" onclick="event.stopPropagation();showHeatmapPopover('${safeZone}', ${pos.x + pos.w/2}, ${pos.y + pos.h/2})">`;
    svg += `<rect x="${pos.x}" y="${pos.y}" width="${pos.w}" height="${pos.h}" rx="8" fill="${color}" stroke="none" style="pointer-events:all"/>`;
    // Density label
    svg += `<text x="${pos.x + pos.w/2}" y="${pos.y + pos.h/2 + 4}" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700" style="pointer-events:none;text-shadow:0 1px 3px rgba(0,0,0,0.8)">${count} threats, ${scenarios} scenarios</text>`;
    svg += `</g>`;
  });
  return svg;
}

window.showHeatmapPopover = function(zone, svgX, svgY) {
  const existing = document.querySelector('.arch-popover');
  if (existing) existing.remove();

  const wrapper = document.getElementById('arch-diagram-wrapper');
  if (!wrapper) return;
  const svgEl = wrapper.querySelector('svg');
  if (!svgEl) return;

  const rect = svgEl.getBoundingClientRect();
  const wrapperRect = wrapper.getBoundingClientRect();
  const scaleX = rect.width / 960;
  const scaleY = rect.height / 820;
  const popX = (svgX * scaleX) + rect.left - wrapperRect.left + wrapper.scrollLeft + 16;
  const popY = (svgY * scaleY) + rect.top - wrapperRect.top + wrapper.scrollTop;

  const zoneToLayer = {
    'Gateway': 'gateway', 'Agent Runtime': 'agent-runtime', 'Plugin System': 'plugin-system',
    'Sandbox': 'sandbox', 'Memory Engine': 'memory-engine', 'Control UI': 'control-ui',
    'Channel Adapters': 'channel-adapters'
  };
  const layerId = zoneToLayer[zone];

  // Threats affecting this zone
  const threats = (DATA.threats || []).filter(t => (t.affected_layers || []).includes(layerId));

  // Scenarios linked via threats
  const threatIds = threats.map(t => t.id);
  const scenarios = (DATA.attacks.scenarios || []).filter(s =>
    (s.threat_ids || []).some(tid => threatIds.includes(tid))
  );

  const severityBadge = (sev) => {
    const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    return `<span style="background:${colors[sev] || '#888'};color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600">${sev}</span>`;
  };

  let html = '';
  html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">`;
  html += `<span style="font-weight:700;font-size:13px;color:#00e6a7">${zone}</span>`;
  html += `<button onclick="this.closest('.arch-popover').remove()" style="color:#64748b;font-size:14px;cursor:pointer;background:none;border:none">&times;</button>`;
  html += `</div>`;

  // Threats section
  html += `<div style="font-size:11px;color:#94a3b8;margin-bottom:4px;font-weight:600">Threats (${threats.length})</div>`;
  if (threats.length > 0) {
    threats.forEach(t => {
      html += `<div style="margin:3px 0;font-size:11px;line-height:1.5">`;
      html += `${severityBadge(t.severity)} <strong style="color:#e2e8f0">${t.name}</strong>`;
      html += `<div style="color:#94a3b8;font-size:10px;margin-top:1px">${t.description}</div>`;
      html += `</div>`;
    });
  } else {
    html += `<div style="font-size:10px;color:#64748b;margin:4px 0">No direct threats mapped</div>`;
  }

  // Scenarios section
  if (scenarios.length > 0) {
    html += `<div style="font-size:11px;color:#94a3b8;margin:8px 0 4px;font-weight:600">Related Scenarios (${scenarios.length})</div>`;
    scenarios.slice(0, 8).forEach(s => {
      const sev = s.severity || 'medium';
      html += `<div style="margin:2px 0;font-size:10px;line-height:1.4">`;
      html += `${severityBadge(sev)} <span style="color:#cbd5e1">${s.name}</span>`;
      html += `</div>`;
    });
    if (scenarios.length > 8) {
      html += `<div style="font-size:9px;color:#64748b;margin-top:4px">+ ${scenarios.length - 8} more scenarios</div>`;
    }
  }

  const popover = document.createElement('div');
  popover.className = 'arch-popover';
  popover.style.cssText = `position:absolute;left:${popX}px;top:${popY}px;z-index:50;background:var(--bg-input,#0d1321);border:1px solid #f9731640;border-radius:8px;padding:12px;min-width:240px;max-width:340px;box-shadow:0 4px 20px rgba(0,0,0,0.5);max-height:400px;overflow-y:auto`;
  popover.innerHTML = html;
  wrapper.style.position = 'relative';
  wrapper.appendChild(popover);
};

function renderThreatOverlay() {
  const threats = DATA.threats || [];
  if (threats.length === 0) return '';

  // Zone letter → archZonePositions name mapping
  const zoneLetterToName = {
    'A': 'Gateway', 'B': 'Agent Runtime', 'C': 'Plugin System',
    'D': 'Sandbox', 'E': 'Memory Engine', 'F': 'Control UI',
    'G': 'Control UI', 'H': 'Channel Adapters'
  };

  const severityColors = {
    'critical': { fill: 'rgba(239,68,68,0.30)', stroke: '#ef4444', badge: '#ef4444', text: '#fff' },
    'high':     { fill: 'rgba(249,115,22,0.25)', stroke: '#f97316', badge: '#f97316', text: '#fff' },
    'medium':   { fill: 'rgba(234,179,8,0.20)',  stroke: '#eab308', badge: '#eab308', text: '#000' },
    'low':      { fill: 'rgba(34,197,94,0.15)',   stroke: '#22c55e', badge: '#22c55e', text: '#000' }
  };

  // Collect threats per zone (primary + propagation)
  const zonePrimaryThreats = {};
  const zonePropagationThreats = {};
  const propagationArrows = [];

  threats.forEach(t => {
    const pz = t.primary_zones || [];
    const propz = t.propagation_zones || [];
    pz.forEach(z => {
      const name = zoneLetterToName[z];
      if (name) {
        if (!zonePrimaryThreats[name]) zonePrimaryThreats[name] = [];
        zonePrimaryThreats[name].push(t);
      }
    });
    propz.forEach(z => {
      const name = zoneLetterToName[z];
      if (name) {
        if (!zonePropagationThreats[name]) zonePropagationThreats[name] = [];
        zonePropagationThreats[name].push(t);
      }
    });
    // Arrows from primary to propagation zones
    pz.forEach(from => {
      propz.forEach(to => {
        if (from !== to) {
          const fromName = zoneLetterToName[from];
          const toName = zoneLetterToName[to];
          if (fromName && toName && fromName !== toName) {
            propagationArrows.push({ from: fromName, to: toName, threat: t });
          }
        }
      });
    });
  });

  let svg = '';

  // 1. Zone severity overlays
  Object.entries(archZonePositions).forEach(([zone, pos]) => {
    const primary = zonePrimaryThreats[zone] || [];
    const propagation = zonePropagationThreats[zone] || [];
    const allThreats = [...new Set([...primary, ...propagation])];
    if (allThreats.length === 0) return;

    // Determine max severity
    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    let maxSev = 'low';
    allThreats.forEach(t => {
      if ((severityRank[t.severity] || 0) > (severityRank[maxSev] || 0)) maxSev = t.severity;
    });
    const c = severityColors[maxSev] || severityColors.medium;

    svg += `<rect x="${pos.x}" y="${pos.y}" width="${pos.w}" height="${pos.h}" rx="8" fill="${c.fill}" stroke="${c.stroke}" stroke-width="2" stroke-dasharray="4 2" style="pointer-events:none"/>`;

    // Threat count badge (top-left) — use escaped zone name for onclick
    const bx = pos.x + 10;
    const by = pos.y + 12;
    const safeZone = zone.replace(/'/g, "\\'");
    svg += `<g style="cursor:pointer;pointer-events:all" onclick="event.stopPropagation();showArchThreatPopover('${safeZone}', ${bx + 50}, ${by})">`;
    svg += `<rect x="${bx}" y="${by - 8}" width="${primary.length > 0 ? 70 : 55}" height="16" rx="8" fill="${c.badge}" opacity="0.9" style="pointer-events:all"/>`;
    svg += `<text x="${bx + (primary.length > 0 ? 35 : 27)}" y="${by + 4}" text-anchor="middle" fill="${c.text}" font-size="9" font-weight="700" style="pointer-events:none">${primary.length} primary</text>`;
    svg += `</g>`;

    if (propagation.length > 0) {
      svg += `<g style="cursor:pointer;pointer-events:all" onclick="event.stopPropagation();showArchThreatPopover('${safeZone}', ${bx + 50}, ${by + 18})">`;
      svg += `<rect x="${bx}" y="${by + 10}" width="75" height="16" rx="8" fill="${c.badge}" opacity="0.5" style="pointer-events:all"/>`;
      svg += `<text x="${bx + 37}" y="${by + 22}" text-anchor="middle" fill="#fff" font-size="9" font-weight="600" style="pointer-events:none">${propagation.length} propagated</text>`;
      svg += `</g>`;
    }

    // Severity label (bottom center)
    svg += `<text x="${pos.x + pos.w/2}" y="${pos.y + pos.h - 8}" text-anchor="middle" fill="${c.stroke}" font-size="10" font-weight="700" style="pointer-events:none;text-shadow:0 1px 2px rgba(0,0,0,0.6)">${maxSev.toUpperCase()}</text>`;
  });

  // 2. Propagation arrows (deduplicated)
  const arrowKey = new Set();
  svg += `<defs><marker id="threat-arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#f97316" opacity="0.7"/></marker></defs>`;

  propagationArrows.forEach(({ from, to }) => {
    const key = `${from}->${to}`;
    if (arrowKey.has(key)) return;
    arrowKey.add(key);

    const fp = archZonePositions[from];
    const tp = archZonePositions[to];
    if (!fp || !tp) return;

    const x1 = fp.x + fp.w / 2;
    const y1 = fp.y + fp.h / 2;
    const x2 = tp.x + tp.w / 2;
    const y2 = tp.y + tp.h / 2;
    const mx = (x1 + x2) / 2 + (y2 - y1) * 0.15;
    const my = (y1 + y2) / 2 - (x2 - x1) * 0.15;

    svg += `<path d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" fill="none" stroke="#f97316" stroke-width="1.5" stroke-dasharray="5 3" marker-end="url(#threat-arrowhead)" opacity="0.6">`;
    svg += `<animate attributeName="stroke-dashoffset" from="16" to="0" dur="1.5s" repeatCount="indefinite"/></path>`;
  });

  // 3. Legend
  const lx = 10, ly = 570;
  svg += `<rect x="${lx}" y="${ly}" width="280" height="40" rx="6" fill="rgba(10,14,26,0.85)" stroke="#333" stroke-width="1"/>`;
  svg += `<text x="${lx + 8}" y="${ly + 14}" fill="#aaa" font-size="9" font-weight="600">THREAT SEVERITY</text>`;
  const legendItems = [
    { label: 'Critical', color: '#ef4444' },
    { label: 'High', color: '#f97316' },
    { label: 'Medium', color: '#eab308' },
    { label: 'Low', color: '#22c55e' }
  ];
  legendItems.forEach((item, i) => {
    const ix = lx + 8 + i * 65;
    svg += `<circle cx="${ix + 4}" cy="${ly + 30}" r="4" fill="${item.color}"/>`;
    svg += `<text x="${ix + 12}" y="${ly + 33}" fill="#ccc" font-size="9">${item.label}</text>`;
  });
  svg += `<text x="${lx + 275}" y="${ly + 33}" text-anchor="end" fill="#f97316" font-size="9">- - → propagation</text>`;

  return svg;
}

// Threat popover for Threat view
window.showArchThreatPopover = function(zone, svgX, svgY) {
  const existing = document.querySelector('.arch-popover');
  if (existing) existing.remove();

  const wrapper = document.getElementById('arch-diagram-wrapper');
  if (!wrapper) return;
  const svgEl = wrapper.querySelector('svg');
  if (!svgEl) return;

  // Convert SVG coordinates to screen coordinates (same as CVE popover)
  const rect = svgEl.getBoundingClientRect();
  const wrapperRect = wrapper.getBoundingClientRect();
  const scaleX = rect.width / 960;
  const scaleY = rect.height / 820;
  const popX = (svgX * scaleX) + rect.left - wrapperRect.left + wrapper.scrollLeft + 16;
  const popY = (svgY * scaleY) + rect.top - wrapperRect.top + wrapper.scrollTop;

  const zoneLetterToName = {
    'A': 'Gateway', 'B': 'Agent Runtime', 'C': 'Plugin System',
    'D': 'Sandbox', 'E': 'Memory Engine', 'F': 'Control UI',
    'G': 'Control UI', 'H': 'Channel Adapters'
  };
  const nameToLetter = {};
  Object.entries(zoneLetterToName).forEach(([k, v]) => { if (!nameToLetter[v]) nameToLetter[v] = k; });

  const threats = DATA.threats || [];
  const zoneLetter = nameToLetter[zone];
  const primary = threats.filter(t => (t.primary_zones || []).includes(zoneLetter));
  const propagated = threats.filter(t => (t.propagation_zones || []).includes(zoneLetter));

  const severityBadge = (sev) => {
    const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    return `<span style="background:${colors[sev] || '#888'};color:#fff;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600">${sev}</span>`;
  };

  let html = '';
  html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">`;
  html += `<span style="font-weight:700;font-size:13px;color:#00e6a7">${zone} — Threats</span>`;
  html += `<button onclick="this.closest('.arch-popover').remove()" style="color:#64748b;font-size:14px;cursor:pointer;background:none;border:none">&times;</button>`;
  html += `</div>`;

  if (primary.length > 0) {
    html += `<div style="font-size:11px;color:#94a3b8;margin-bottom:4px;font-weight:600">Primary Threats (${primary.length})</div>`;
    primary.forEach(t => {
      html += `<div style="margin:3px 0;font-size:11px;line-height:1.5">`;
      html += `${severityBadge(t.severity)} <strong style="color:#e2e8f0">${t.name}</strong>`;
      html += `<div style="color:#94a3b8;font-size:10px;margin-top:1px">${t.description}</div>`;
      if (t.mitre_ids && t.mitre_ids.length) {
        html += `<div style="color:#64748b;font-size:9px;margin-top:1px">${t.mitre_ids.join(', ')}</div>`;
      }
      html += `</div>`;
    });
  }

  if (propagated.length > 0) {
    html += `<div style="font-size:11px;color:#94a3b8;margin:6px 0 4px;font-weight:600">Propagated Threats (${propagated.length})</div>`;
    propagated.forEach(t => {
      html += `<div style="margin:3px 0;font-size:11px;line-height:1.5">`;
      html += `${severityBadge(t.severity)} <span style="color:#cbd5e1">${t.name}</span>`;
      const fromZones = (t.primary_zones || []).map(z => zoneLetterToName[z] || z).join(', ');
      html += `<span style="color:#64748b;font-size:9px"> ← from ${fromZones}</span>`;
      html += `</div>`;
    });
  }

  // Related controls
  const controls = DATA.controls || [];
  const zoneControls = controls.filter(c => (c.applicable_zones || []).includes(zoneLetter));
  if (zoneControls.length > 0) {
    html += `<div style="font-size:11px;color:#94a3b8;margin:6px 0 4px;font-weight:600">Controls (${zoneControls.length})</div>`;
    html += `<div style="display:flex;flex-wrap:wrap;gap:3px">`;
    zoneControls.forEach(c => {
      html += `<span style="background:rgba(0,228,167,0.15);color:#00e6a7;padding:1px 6px;border-radius:4px;font-size:9px">${c.name}</span>`;
    });
    html += `</div>`;
  }

  const popover = document.createElement('div');
  popover.className = 'arch-popover';
  popover.style.cssText = `position:absolute;left:${popX}px;top:${popY}px;z-index:50;background:var(--bg-input,#0d1321);border:1px solid #ef444440;border-radius:8px;padding:12px;min-width:240px;max-width:340px;box-shadow:0 4px 20px rgba(0,0,0,0.5);max-height:400px;overflow-y:auto`;
  popover.innerHTML = html;
  wrapper.style.position = 'relative';
  wrapper.appendChild(popover);
};

function renderAttackFlowOverlay() {
  const scenarios = DATA.attacks.scenarios || [];
  if (scenarios.length === 0) return '';

  // Show dropdown (rendered outside SVG, in the diagram wrapper)
  let dropdownEl = document.getElementById('arch-attack-dropdown');
  if (!dropdownEl) {
    dropdownEl = document.createElement('div');
    dropdownEl.id = 'arch-attack-dropdown';
    dropdownEl.style.cssText = 'margin-bottom:8px';
    dropdownEl.innerHTML = `
      <select id="arch-attack-select" onchange="animateAttackFlow(this.value)" class="text-xs px-3 py-1.5 rounded-lg" style="background:var(--bg-input,#141c2e);color:var(--text-primary,#e2e8f0);border:1px solid var(--border-primary,#1e293b);max-width:400px;width:100%">
        <option value="">-- Select attack scenario --</option>
        ${scenarios.map(s => `<option value="${s.id}">${s.name} (${s.severity})</option>`).join('')}
      </select>
    `;
    const wrapper = document.getElementById('arch-diagram-wrapper');
    if (wrapper) wrapper.parentElement.insertBefore(dropdownEl, wrapper);
  }
  dropdownEl.style.display = '';

  return '';
}

// Detailed attack flow paths per scenario — maps scenario category+id to
// concrete architecture zone steps with contextual labels.
const attackFlowPaths = {
  // Supply chain attacks: external → ClawHub(Plugin System) → Agent
  1:  [{ zone:'External LLM API', label:'공격자가 ClawHub에 오염된 스킬 게시' },
      { zone:'Plugin System', label:'악성 스킬이 ClawHub 검토 통과' },
      { zone:'Agent Runtime', label:'사용자가 스킬 설치; 에이전트가 로드' },
      { zone:'Sandbox', label:'스킬이 샌드박스에서 악성 페이로드 실행' },
      { zone:'Local Machine', label:'페이로드 탈출: 자격 증명 유출' }],
  40: [{ zone:'External LLM API', label:'1,184개의 악성 스킬이 ClawHub에 업로드' },
      { zone:'Plugin System', label:'스킬이 인기 패키지 모방 (타이포스쿼팅)' },
      { zone:'Agent Runtime', label:'에이전트가 트렌딩 스킬 자동 설치' },
      { zone:'Sandbox', label:'백도어 코드 실행' },
      { zone:'Local Machine', label:'82개국에서 대량 자격 증명 수집' }],
  17: [{ zone:'External LLM API', label:'공격자가 트로이 의존성 패키지 생성' },
      { zone:'Plugin System', label:'정상 스킬이 트로이 패키지에 의존' },
      { zone:'Agent Runtime', label:'스킬 설치 중 의존성 자동 해결' },
      { zone:'Local Machine', label:'의존성 설치 중 트로이 실행' }],
  41: [{ zone:'External LLM API', label:'손상된 npm 패키지 게시' },
      { zone:'Plugin System', label:'Cline CLI가 손상된 의존성 설치' },
      { zone:'Agent Runtime', label:'악성 postinstall 스크립트 실행' },
      { zone:'Local Machine', label:'리버스 쉘 수립' }],
  // Prompt injection via browser
  8:  [{ zone:'Channel Adapters', label:'사용자가 에이전트에게 웹 페이지 탐색 요청' },
      { zone:'Gateway', label:'에이전트로 요청 전달' },
      { zone:'Agent Runtime', label:'에이전트가 skill-browser 호출' },
      { zone:'Plugin System', label:'skill-browser 로드' },
      { zone:'Sandbox', label:'샌드박스에서 브라우저 실행' },
      { zone:'Local Machine', label:'브라우저가 악성 웹사이트로 이동' },
      { zone:'Sandbox', label:'페이지 DOM에서 숨겨진 프롬프트 추출' },
      { zone:'Agent Runtime', label:'주입된 프롬프트가 에이전트 추론 탈취' },
      { zone:'Plugin System', label:'에이전트가 skill-filesystem 호출 (공격자 의도)' },
      { zone:'Local Machine', label:'민감한 파일 읽기 및 유출' }],
  // Other prompt injections
  9:  [{ zone:'Plugin System', label:'SKILL.md에 숨겨진 명령 포함' },
      { zone:'Agent Runtime', label:'에이전트가 SKILL.md를 스킬 설정으로 읽기' },
      { zone:'Agent Runtime', label:'숨겨진 프롬프트가 에이전트 동작 재정의' },
      { zone:'Plugin System', label:'에이전트가 의도하지 않은 도구 호출' },
      { zone:'Local Machine', label:'로컬 시스템에서 무단 작업 수행' }],
  33: [{ zone:'Channel Adapters', label:'개발자가 숨겨진 프롬프트 포함 코드 붙여넣기' },
      { zone:'Gateway', label:'AI 코딩 어시스턴트에 코드 전송' },
      { zone:'Agent Runtime', label:'코드 주석의 주입된 프롬프트 활성화' },
      { zone:'External LLM API', label:'LLM이 주입된 명령 따르기' },
      { zone:'Plugin System', label:'에이전트가 코드베이스에 백도어 작성' },
      { zone:'Local Machine', label:'백도어 포함 코드가 저장소에 커밋' }],
  44: [{ zone:'External LLM API', label:'악성 MCP 서버가 조작된 샘플링 요청 전송' },
      { zone:'Agent Runtime', label:'에이전트가 샘플링 요청을 신뢰로 처리' },
      { zone:'Agent Runtime', label:'주입된 프롬프트가 에이전트 목표 재정의' },
      { zone:'Plugin System', label:'에이전트가 공격자 선택 도구 실행' }],
  46: [{ zone:'Plugin System', label:'3줄 쉘 페이로드가 포함된 악성 SKILL.md' },
      { zone:'Agent Runtime', label:'에이전트가 SKILL.md를 명령으로 파싱' },
      { zone:'Plugin System', label:'페이로드로 skill-shell 호출' },
      { zone:'Sandbox', label:'쉘 명령 실행' },
      { zone:'Local Machine', label:'전체 쉘 접근 권한 획득' }],
  // RCE attacks
  6:  [{ zone:'Channel Adapters', label:'공격자가 조작된 MCP 도구 요청 전송' },
      { zone:'Gateway', label:'게이트웨이의 SSRF 취약점 (CVE-2026-25253)' },
      { zone:'Agent Runtime', label:'악성 도구 호출이 런타임에 도달' },
      { zone:'Local Machine', label:'호스트에서 임의 코드 실행' }],
  7:  [{ zone:'Channel Adapters', label:'사용자가 비정제 입력으로 스킬 트리거' },
      { zone:'Agent Runtime', label:'에이전트가 skill-shell에 입력 전달' },
      { zone:'Plugin System', label:'스킬 파라미터에서 명령 주입' },
      { zone:'Sandbox', label:'주입된 명령이 샌드박스 탈출' },
      { zone:'Local Machine', label:'호스트 사용자로 시스템 명령 실행' }],
  34: [{ zone:'Channel Adapters', label:'공격자가 잘못된 음성 확장 요청 전송' },
      { zone:'Gateway', label:'음성 확장의 사전 인증 RCE (CVE-2026-28446)' },
      { zone:'Local Machine', label:'인증 없이 원격 코드 실행' }],
  // Credential theft
  11: [{ zone:'Channel Adapters', label:'무해해 보이는 요청이 파일 검색 트리거' },
      { zone:'Agent Runtime', label:'에이전트가 skill-filesystem으로 설정 파일 검색' },
      { zone:'Plugin System', label:'skill-filesystem이 .env, .aws/credentials 읽기' },
      { zone:'Local Machine', label:'파일시스템에서 자격 증명 파일 접근' },
      { zone:'Agent Runtime', label:'에이전트 응답에 자격 증명 포함' },
      { zone:'Channel Adapters', label:'채팅 출력에서 자격 증명 유출' }],
  12: [{ zone:'Agent Runtime', label:'손상된 에이전트가 SSH 키 검색' },
      { zone:'Plugin System', label:'skill-filesystem이 ~/.ssh/ 스캔' },
      { zone:'Local Machine', label:'파일시스템에서 개인 키 읽기' },
      { zone:'Agent Runtime', label:'키를 사용하여 다른 시스템 접근' },
      { zone:'External LLM API', label:'연결된 서버로 측면 이동' }],
  13: [{ zone:'Agent Runtime', label:'에이전트가 API 키 참조 요청 처리' },
      { zone:'Memory Engine', label:'대화 기록에서 API 키 발견' },
      { zone:'Agent Runtime', label:'메모리 컨텍스트에서 키 추출' },
      { zone:'Channel Adapters', label:'채널 응답을 통해 키 유출' }],
  38: [{ zone:'External LLM API', label:'Shodan/Censys 스캔으로 135K+ 노출 패널 발견' },
      { zone:'Gateway', label:'인증 없는 노출된 관리자 패널' },
      { zone:'Control UI', label:'공격자가 Control UI에 직접 접근' },
      { zone:'Agent Runtime', label:'에이전트 전체 제어 권한 획득' },
      { zone:'Memory Engine', label:'모든 대화 데이터 및 자격 증명 노출' }],
  // Memory/data poisoning
  15: [{ zone:'External LLM API', label:'공격자가 오염된 문서 제작' },
      { zone:'Plugin System', label:'RAG 파이프라인을 통해 문서 수집' },
      { zone:'Memory Engine', label:'오염된 벡터가 메모리에 저장' },
      { zone:'Agent Runtime', label:'에이전트가 쿼리에 대해 오염된 컨텍스트 검색' },
      { zone:'Channel Adapters', label:'사용자가 조작된 응답 수신' }],
  19: [{ zone:'Channel Adapters', label:'공격자가 숨겨진 페이로드 포함 대화 전송' },
      { zone:'Agent Runtime', label:'에이전트가 상호작용 처리 및 저장' },
      { zone:'Memory Engine', label:'악성 콘텐츠가 장기 메모리에 저장' },
      { zone:'Agent Runtime', label:'이후 쿼리가 오염된 메모리 검색' },
      { zone:'Channel Adapters', label:'손상된 컨텍스트로 모든 사용자 영향' }],
  // Hijacking
  5:  [{ zone:'External LLM API', label:'공격자가 노출된 WebSocket에 연결' },
      { zone:'Gateway', label:'WebSocket 인증 우회 악용' },
      { zone:'Agent Runtime', label:'공격자가 에이전트 세션에 명령 주입' },
      { zone:'Plugin System', label:'무단 도구 호출' },
      { zone:'Local Machine', label:'에이전트가 공격자 작업 수행' }],
  14: [{ zone:'Channel Adapters', label:'사용자가 에이전트 제어 브라우저로 탐색' },
      { zone:'Plugin System', label:'skill-browser가 대상 페이지 열기' },
      { zone:'Sandbox', label:'샌드박스에서 브라우저 세션 활성' },
      { zone:'Local Machine', label:'브라우저에서 세션 쿠키 도난' },
      { zone:'External LLM API', label:'공격자 C2 서버로 쿠키 전송' }],
  36: [{ zone:'External LLM API', label:'공격자가 브라우저 제어 인증 우회 악용' },
      { zone:'Plugin System', label:'인증 없이 skill-browser 조작 (CVE-2026-28485)' },
      { zone:'Sandbox', label:'공격자가 샌드박스 브라우저 제어' },
      { zone:'Local Machine', label:'브라우저를 통해 로컬 리소스 접근' }],
  42: [{ zone:'External LLM API', label:'Perplexity Comet을 통한 제로클릭 익스플로잇' },
      { zone:'Agent Runtime', label:'에이전트가 악성 콘텐츠 자동 처리' },
      { zone:'Agent Runtime', label:'사용자 상호작용 없이 에이전트 추론 탈취' },
      { zone:'Plugin System', label:'공격자 제어 작업 실행' }],
  // Multi-stage
  20: [{ zone:'Plugin System', label:'공격자가 여러 스킬을 연쇄 활용' },
      { zone:'Agent Runtime', label:'skill-browser가 페이로드 URL 가져오기' },
      { zone:'Sandbox', label:'브라우저를 통해 페이로드 다운로드' },
      { zone:'Plugin System', label:'skill-shell이 다운로드된 페이로드 실행' },
      { zone:'Local Machine', label:'멀티 스킬 체인으로 코드 실행 달성' }],
  24: [{ zone:'Channel Adapters', label:'AI 웜이 메시지 채널을 통해 진입' },
      { zone:'Agent Runtime', label:'에이전트가 웜 페이로드 처리' },
      { zone:'Memory Engine', label:'웜이 에이전트 메모리에 지속' },
      { zone:'Channel Adapters', label:'웜이 연결된 에이전트로 전파' },
      { zone:'Agent Runtime', label:'감염된 에이전트가 더 많은 채널로 확산' }],
  28: [{ zone:'Agent Runtime', label:'손상된 에이전트 A가 에이전트 B와 협력' },
      { zone:'Memory Engine', label:'C2 통신에 공유 메모리 사용' },
      { zone:'Agent Runtime', label:'에이전트 B가 권한 상승' },
      { zone:'Plugin System', label:'결합된 스킬 접근으로 제어 우회' },
      { zone:'Local Machine', label:'여러 시스템에 걸친 협력 공격' }],
  43: [{ zone:'External LLM API', label:'프롬프트웨어 페이로드 제작 및 배포' },
      { zone:'Channel Adapters', label:'일반 메시지를 통해 페이로드 전달' },
      { zone:'Agent Runtime', label:'에이전트가 프롬프트웨어 명령 실행' },
      { zone:'Plugin System', label:'프롬프트웨어가 영구 후크 설치' },
      { zone:'Memory Engine', label:'킬 체인이 세션 간 지속' },
      { zone:'Local Machine', label:'전체 시스템 침해 달성' }],
  // Resource abuse
  10: [{ zone:'Channel Adapters', label:'무해해 보이는 요청이 체인 시작' },
      { zone:'Agent Runtime', label:'에이전트가 재귀적 도구 호출 루프 진입' },
      { zone:'External LLM API', label:'반복당 대량 토큰 소비' },
      { zone:'Plugin System', label:'스킬이 수천 번 호출' },
      { zone:'Gateway', label:'속도 제한 소진; 서비스 저하' }],
  // Other
  27: [{ zone:'Channel Adapters', label:'에이전트가 채팅에서 신뢰할 수 있는 엔티티 사칭' },
      { zone:'Agent Runtime', label:'LLM이 소셜 엔지니어링 스크립트 생성' },
      { zone:'External LLM API', label:'LLM이 설득력 있는 피싱 콘텐츠 제작' },
      { zone:'Channel Adapters', label:'사용자가 자격 증명 노출에 속음' }],
  45: [{ zone:'Plugin System', label:'지연 호출 타이머가 포함된 도구 심기' },
      { zone:'Agent Runtime', label:'초기 검토 시 도구가 무해하게 보임' },
      { zone:'Agent Runtime', label:'승인 창이 닫힌 후 타이머 트리거' },
      { zone:'Plugin System', label:'지연된 악성 작업 실행' },
      { zone:'Local Machine', label:'무단 시스템 접근 달성' }],
};

// Kill Chain phase → primary architecture zone mapping
const killChainZoneMapping = {
  'reconnaissance': { zone: 'External LLM API', color: '#3b82f6' },
  'initial_access': { zone: 'Gateway', color: '#a855f7' },
  'execution': { zone: 'Agent Runtime', color: '#f59e0b' },
  'persistence': { zone: 'Memory Engine', color: '#06b6d4' },
  'privilege_escalation': { zone: 'Sandbox', color: '#ef4444' },
  'lateral_movement': { zone: 'Channel Adapters', color: '#10b981' },
  'impact': { zone: 'Local Machine', color: '#f43f5e' }
};

let killChainAnimTimer = null;
let killChainSelectedPhase = null;

function renderKillChainFlowOverlay() {
  const killChain = DATA.attacks.kill_chain || [];
  const scenarios = DATA.attacks.scenarios || [];
  const threats = DATA.threats || [];
  if (killChain.length === 0) return '';

  // Count scenarios and threats per phase
  const phaseCounts = {};
  killChain.forEach(kc => { phaseCounts[kc.phase] = 0; });
  scenarios.forEach(s => {
    if (s.phase && phaseCounts[s.phase] !== undefined) phaseCounts[s.phase]++;
  });
  const phaseThreatsMap = {};
  killChain.forEach(kc => { phaseThreatsMap[kc.phase] = []; });
  threats.forEach(t => {
    if (t.kill_chain_phase && phaseThreatsMap[t.kill_chain_phase]) phaseThreatsMap[t.kill_chain_phase].push(t);
  });

  let svg = '';

  // Semi-transparent dark overlay for contrast
  svg += `<rect x="0" y="0" width="960" height="820" rx="12" fill="rgba(10,14,26,0.55)" style="pointer-events:none"/>`;

  // Defs
  svg += `<defs>
    <filter id="kc-glow"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <marker id="kc-arrow" viewBox="0 0 12 8" refX="11" refY="4" markerWidth="10" markerHeight="7" orient="auto">
      <polygon points="0 0,12 4,0 8" fill="#00e6a7" opacity="0.8"/>
    </marker>
  </defs>`;

  // ─── TOP: Kill Chain Phases (clickable arrow strip) ───
  const stripY = 4;
  svg += `<rect x="5" y="${stripY}" width="950" height="42" rx="8" fill="rgba(10,14,26,0.9)" stroke="#1e3a5f" stroke-width="1"/>`;
  svg += `<text x="15" y="${stripY + 12}" fill="#64748b" font-size="7" font-weight="600">KILL CHAIN PHASES (클릭하여 상세 보기)</text>`;

  const phaseW = 132;
  const arrowY = stripY + 18;
  killChain.forEach((kc, i) => {
    const mapping = killChainZoneMapping[kc.phase];
    if (!mapping) return;
    const px = 12 + i * phaseW;
    const count = phaseCounts[kc.phase] || 0;
    const tCount = (phaseThreatsMap[kc.phase] || []).length;
    const isSelected = killChainSelectedPhase === kc.phase;
    const fillA = isSelected ? '50' : '25';
    const strokeA = isSelected ? 'ee' : '60';
    const sw = isSelected ? 2 : 1;

    svg += `<g style="cursor:pointer;pointer-events:all" onclick="showKillChainPhaseDetail('${kc.phase}')">`;
    // Arrow chevron shape
    if (i === 0) {
      svg += `<polygon points="${px},${arrowY} ${px + phaseW - 6},${arrowY} ${px + phaseW},${arrowY + 10} ${px + phaseW - 6},${arrowY + 20} ${px},${arrowY + 20}" fill="${mapping.color}${fillA}" stroke="${mapping.color}${strokeA}" stroke-width="${sw}"/>`;
    } else if (i < killChain.length - 1) {
      svg += `<polygon points="${px},${arrowY} ${px + phaseW - 6},${arrowY} ${px + phaseW},${arrowY + 10} ${px + phaseW - 6},${arrowY + 20} ${px},${arrowY + 20} ${px + 6},${arrowY + 10}" fill="${mapping.color}${fillA}" stroke="${mapping.color}${strokeA}" stroke-width="${sw}"/>`;
    } else {
      svg += `<polygon points="${px},${arrowY} ${px + phaseW},${arrowY} ${px + phaseW},${arrowY + 20} ${px},${arrowY + 20} ${px + 6},${arrowY + 10}" fill="${mapping.color}${fillA}" stroke="${mapping.color}${strokeA}" stroke-width="${sw}"/>`;
    }
    // Phase number + name
    svg += `<text x="${px + (i === 0 ? 0 : 6) + (phaseW - (i === 0 ? 0 : 6)) / 2}" y="${arrowY + 8}" text-anchor="middle" fill="${mapping.color}" font-size="7.5" font-weight="700">${i + 1}. ${kc.name}</text>`;
    // Counts
    svg += `<text x="${px + (i === 0 ? 0 : 6) + (phaseW - (i === 0 ? 0 : 6)) / 2}" y="${arrowY + 18}" text-anchor="middle" fill="${mapping.color}90" font-size="6">${tCount} threats · ${count} scenarios</text>`;
    svg += `</g>`;
  });

  // ─── Zone overlays with phase mapping ───
  const points = [];
  killChain.forEach((kc, i) => {
    const mapping = killChainZoneMapping[kc.phase];
    if (!mapping) return;
    const pos = archZonePositions[mapping.zone];
    if (!pos) return;
    points.push({
      x: pos.x + pos.w / 2, y: pos.y + pos.h / 2,
      zone: mapping.zone, color: mapping.color,
      phase: kc.phase, name: kc.name, description: kc.description,
      count: phaseCounts[kc.phase] || 0,
      threatCount: (phaseThreatsMap[kc.phase] || []).length,
      pos: pos, index: i
    });
  });

  // Highlight affected zones
  points.forEach(p => {
    const isSelected = killChainSelectedPhase === p.phase;
    svg += `<rect x="${p.pos.x}" y="${p.pos.y}" width="${p.pos.w}" height="${p.pos.h}" rx="8" fill="${p.color}${isSelected ? '25' : '10'}" stroke="${p.color}" stroke-width="${isSelected ? 4 : 2.5}" opacity="0.7" style="cursor:pointer;pointer-events:all" onclick="showKillChainPhaseDetail('${p.phase}')">
      <animate attributeName="opacity" values="${isSelected ? '0.8;1;0.8' : '0.5;0.9;0.5'}" dur="3s" begin="${p.index * 0.4}s" repeatCount="indefinite"/>
    </rect>`;
  });

  // Curved connecting paths
  for (let i = 0; i < points.length - 1; i++) {
    const p1 = points[i], p2 = points[i + 1];
    const dx = p2.x - p1.x, dy = p2.y - p1.y;
    const cpx = (p1.x + p2.x) / 2 + (dy > 0 ? -40 : 40);
    const cpy = (p1.y + p2.y) / 2 + (dx > 0 ? -30 : 30);
    svg += `<path d="M${p1.x},${p1.y} Q${cpx},${cpy} ${p2.x},${p2.y}" fill="none" stroke="${p2.color}" stroke-width="2.5" stroke-dasharray="10 5" opacity="0.6" marker-end="url(#kc-arrow)">
      <animate attributeName="stroke-dashoffset" from="30" to="0" dur="1.5s" repeatCount="indefinite"/>
    </path>`;
  }

  // Phase badges on each zone
  points.forEach((p, i) => {
    const badgeX = p.pos.x + p.pos.w / 2;
    const badgeY = p.pos.y + 20;
    const isSelected = killChainSelectedPhase === p.phase;

    svg += `<g style="cursor:pointer;pointer-events:all" onclick="showKillChainPhaseDetail('${p.phase}')">`;
    // Number circle
    svg += `<circle cx="${badgeX - 40}" cy="${badgeY}" r="${isSelected ? 16 : 14}" fill="${p.color}" stroke="${isSelected ? '#ffffff' : '#0a0e1a'}" stroke-width="2.5" filter="url(#kc-glow)">
      <animate attributeName="r" values="${isSelected ? '16;18;16' : '14;16;14'}" dur="2.5s" begin="${i * 0.3}s" repeatCount="indefinite"/>
    </circle>`;
    svg += `<text x="${badgeX - 40}" y="${badgeY + 1}" text-anchor="middle" dominant-baseline="middle" fill="#ffffff" font-size="10" font-weight="800">${i + 1}</text>`;
    // Phase name
    const labelW = p.name.length * 7 + 40;
    svg += `<rect x="${badgeX - 22}" y="${badgeY - 12}" width="${labelW}" height="24" rx="12" fill="${p.color}${isSelected ? '50' : '30'}" stroke="${p.color}${isSelected ? 'cc' : '80'}" stroke-width="${isSelected ? 2 : 1}"/>`;
    svg += `<text x="${badgeX - 18 + labelW / 2}" y="${badgeY + 1}" text-anchor="middle" dominant-baseline="middle" fill="${p.color}" font-size="9" font-weight="700">${p.name}</text>`;
    // Stats bar at bottom of zone
    const infoY = p.pos.y + p.pos.h - 20;
    if (p.count > 0 || p.threatCount > 0) {
      const infoX = p.pos.x + 10;
      svg += `<rect x="${infoX}" y="${infoY}" width="${p.pos.w - 20}" height="18" rx="4" fill="rgba(10,14,26,0.8)" stroke="${p.color}40" stroke-width="0.5"/>`;
      let infoText = '';
      if (p.threatCount > 0) infoText += `⚠ ${p.threatCount} threats`;
      if (p.count > 0) infoText += `${infoText ? '  ·  ' : ''}📋 ${p.count} scenarios`;
      svg += `<text x="${infoX + (p.pos.w - 20) / 2}" y="${infoY + 12}" text-anchor="middle" fill="${p.color}" font-size="7.5" font-weight="600">${infoText}</text>`;
    }
    svg += `</g>`;
  });

  // Animated moving dot
  if (points.length >= 2) {
    const segs = [];
    for (let i = 0; i < points.length - 1; i++) {
      const p1 = points[i], p2 = points[i + 1];
      const dx = p2.x - p1.x, dy = p2.y - p1.y;
      const cpx = (p1.x + p2.x) / 2 + (dy > 0 ? -40 : 40);
      const cpy = (p1.y + p2.y) / 2 + (dx > 0 ? -30 : 30);
      if (i === 0) segs.push(`M${p1.x},${p1.y}`);
      segs.push(`Q${cpx},${cpy} ${p2.x},${p2.y}`);
    }
    const fullPath = segs.join(' ');
    svg += `<circle r="6" fill="#ffffff" opacity="0.9" filter="url(#kc-glow)">
      <animateMotion dur="${points.length * 1.8}s" repeatCount="indefinite" path="${fullPath}"/>
    </circle>`;
    svg += `<circle r="3" fill="#00e6a7">
      <animateMotion dur="${points.length * 1.8}s" repeatCount="indefinite" path="${fullPath}"/>
    </circle>`;
  }

  // Render detail panel into dedicated container after overlay
  setTimeout(() => { renderKillChainDetailPanel(); }, 50);

  return svg;
}

window.showKillChainPhaseDetail = function(phase) {
  killChainSelectedPhase = (killChainSelectedPhase === phase) ? null : phase;
  renderArchOverlay();
};

function renderKillChainDetailPanel() {
  // Remove existing panel
  const existing = document.getElementById('kc-detail-panel');
  if (existing) existing.remove();

  if (!killChainSelectedPhase) return;

  const killChain = DATA.attacks.kill_chain || [];
  const scenarios = DATA.attacks.scenarios || [];
  const threats = DATA.threats || [];

  const kc = killChain.find(k => k.phase === killChainSelectedPhase);
  if (!kc) return;

  const mapping = killChainZoneMapping[killChainSelectedPhase];
  if (!mapping) return;

  const phaseIndex = killChain.indexOf(kc);
  const phaseThreats = threats.filter(t => t.kill_chain_phase === killChainSelectedPhase);
  const phaseScenarios = scenarios.filter(s => s.phase === killChainSelectedPhase);

  const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  let html = `<div id="kc-detail-panel" class="mt-4" style="border:2px solid ${mapping.color}40;border-radius:12px;background:var(--bg-card,#0d1321);overflow:hidden">`;

  // Header
  html += `<div style="padding:16px 20px;background:${mapping.color}10;border-bottom:1px solid ${mapping.color}30;display:flex;align-items:center;justify-content:space-between">`;
  html += `<div style="display:flex;align-items:center;gap:12px">`;
  html += `<span style="display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:50%;background:${mapping.color};color:#fff;font-weight:800;font-size:14px">${phaseIndex + 1}</span>`;
  html += `<div>`;
  html += `<div style="font-size:16px;font-weight:700;color:${mapping.color}">${kc.name}</div>`;
  html += `<div style="font-size:12px;color:var(--text-secondary,#94a3b8);margin-top:2px">${kc.description}</div>`;
  html += `</div></div>`;
  html += `<div style="display:flex;gap:16px;align-items:center">`;
  html += `<span style="font-size:12px;color:${mapping.color}"><span style="font-weight:700;font-size:16px">${phaseThreats.length}</span> Threats</span>`;
  html += `<span style="font-size:12px;color:${mapping.color}"><span style="font-weight:700;font-size:16px">${phaseScenarios.length}</span> Scenarios</span>`;
  html += `<span style="font-size:11px;padding:4px 10px;border-radius:6px;background:${mapping.color}15;color:${mapping.color};border:1px solid ${mapping.color}40">🎯 ${mapping.zone}</span>`;
  html += `<button onclick="showKillChainPhaseDetail('${killChainSelectedPhase}')" style="color:var(--text-secondary,#64748b);font-size:18px;cursor:pointer;background:none;border:none;padding:4px 8px">&times;</button>`;
  html += `</div></div>`;

  // Body — two columns: Threats | Scenarios
  html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:0;min-height:200px">`;

  // === Left: Threats ===
  html += `<div style="padding:16px 20px;border-right:1px solid ${mapping.color}15">`;
  html += `<div style="font-size:12px;font-weight:700;color:var(--text-primary,#e2e8f0);margin-bottom:12px;display:flex;align-items:center;gap:6px">⚠️ 관련 위협 (Threats)</div>`;

  if (phaseThreats.length === 0) {
    html += `<div style="font-size:12px;color:var(--text-secondary,#64748b);padding:20px 0;text-align:center">이 단계에 직접 매핑된 위협이 없습니다</div>`;
  } else {
    phaseThreats.forEach(t => {
      const sevColor = sevColors[t.severity] || '#64748b';
      const affectedZones = (t.primary_zones || []).concat(t.propagation_zones || []);
      html += `<div style="padding:10px 12px;margin-bottom:8px;border-radius:8px;background:var(--bg-hover,rgba(255,255,255,0.02));border:1px solid ${sevColor}20;cursor:default">`;
      html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">`;
      html += `<span style="font-size:12px;font-weight:700;color:var(--text-primary,#e2e8f0)">${t.name}</span>`;
      html += `<span style="font-size:9px;padding:2px 8px;border-radius:4px;background:${sevColor}20;color:${sevColor};font-weight:600;text-transform:uppercase">${t.severity}</span>`;
      html += `</div>`;
      html += `<div style="font-size:11px;color:var(--text-secondary,#94a3b8);margin-bottom:6px;line-height:1.4">${t.description}</div>`;
      // Affected layers
      if (t.affected_layers && t.affected_layers.length > 0) {
        html += `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:4px">`;
        t.affected_layers.forEach(l => {
          html += `<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:${mapping.color}10;color:${mapping.color};border:1px solid ${mapping.color}20">${l}</span>`;
        });
        html += `</div>`;
      }
      // MITRE IDs
      if (t.mitre_ids && t.mitre_ids.length > 0) {
        html += `<div style="font-size:9px;color:var(--text-secondary,#64748b);margin-top:4px">MITRE: ${t.mitre_ids.join(', ')}</div>`;
      }
      // Controls
      if (t.controls && t.controls.length > 0) {
        html += `<div style="font-size:9px;color:#22c55e;margin-top:2px">🛡 ${t.controls.join(', ')}</div>`;
      }
      html += `</div>`;
    });
  }
  html += `</div>`;

  // === Right: Scenarios ===
  html += `<div style="padding:16px 20px">`;
  html += `<div style="font-size:12px;font-weight:700;color:var(--text-primary,#e2e8f0);margin-bottom:12px;display:flex;align-items:center;gap:6px">📋 공격 시나리오 (Scenarios)</div>`;

  if (phaseScenarios.length === 0) {
    html += `<div style="font-size:12px;color:var(--text-secondary,#64748b);padding:20px 0;text-align:center">이 단계에 매핑된 시나리오가 없습니다</div>`;
  } else {
    // Show max 8 scenarios with scrollable container
    html += `<div style="max-height:400px;overflow-y:auto">`;
    phaseScenarios.forEach((s, si) => {
      const sevColor = sevColors[s.severity] || '#64748b';
      html += `<div style="padding:10px 12px;margin-bottom:8px;border-radius:8px;background:var(--bg-hover,rgba(255,255,255,0.02));border:1px solid ${sevColor}20">`;
      html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">`;
      html += `<span style="font-size:12px;font-weight:700;color:var(--text-primary,#e2e8f0)">${si + 1}. ${s.name}</span>`;
      html += `<span style="font-size:9px;padding:2px 8px;border-radius:4px;background:${sevColor}20;color:${sevColor};font-weight:600;text-transform:uppercase">${s.severity}</span>`;
      html += `</div>`;
      html += `<div style="font-size:11px;color:var(--text-secondary,#94a3b8);margin-bottom:6px;line-height:1.4">${s.description}</div>`;
      // Tags
      if (s.tags && s.tags.length > 0) {
        html += `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:4px">`;
        s.tags.forEach(tag => {
          html += `<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(255,255,255,0.04);color:var(--text-secondary,#94a3b8);border:1px solid rgba(255,255,255,0.06)">#${tag}</span>`;
        });
        html += `</div>`;
      }
      // Linked threats
      if (s.threat_ids && s.threat_ids.length > 0) {
        const linkedThreats = s.threat_ids.map(tid => threats.find(t => t.id === tid)).filter(Boolean);
        if (linkedThreats.length > 0) {
          html += `<div style="font-size:9px;color:#f97316;margin-top:4px">⚠ 관련 위협: ${linkedThreats.map(t => t.name).join(', ')}</div>`;
        }
      }
      // MITRE mapping
      if (s.mitre_ids && s.mitre_ids.length > 0) {
        html += `<div style="font-size:9px;color:var(--text-secondary,#64748b);margin-top:2px">MITRE: ${s.mitre_ids.join(', ')}</div>`;
      }
      // Flow path
      if (s.flow_path && s.flow_path.length > 0) {
        html += `<div style="font-size:9px;color:${mapping.color};margin-top:4px">🔗 Attack Path: ${s.flow_path.join(' → ')}</div>`;
      }
      // Reference
      if (s.reference) {
        html += `<div style="font-size:9px;color:var(--text-secondary,#64748b);margin-top:2px">📎 ${s.reference}</div>`;
      }
      html += `</div>`;
    });
    html += `</div>`;
  }
  html += `</div>`;

  html += `</div>`; // grid end
  html += `</div>`; // panel end

  // Insert panel into the dedicated container (between SVG and layer reference)
  const container = document.getElementById('kc-detail-container');
  if (container) {
    container.innerHTML = html;
  }
}

function animateAttackFlow(scenarioId) {
  if (!scenarioId) {
    const overlay = document.querySelector('#arch-overlay');
    if (overlay) overlay.innerHTML = '';
    const info = document.getElementById('attack-step-info');
    if (info) info.innerHTML = '';
    return;
  }

  const scenario = DATA.attacks.scenarios.find(s => String(s.id) === String(scenarioId));
  if (!scenario) return;

  const svgEl = document.querySelector('#arch-diagram svg');
  if (!svgEl) return;

  let overlay = svgEl.querySelector('#arch-overlay');
  if (!overlay) {
    overlay = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    overlay.setAttribute('id', 'arch-overlay');
    svgEl.appendChild(overlay);
  }

  // Get detailed path for this scenario, or generate a default one
  const detailedPath = attackFlowPaths[scenario.id];
  const steps = detailedPath || generateDefaultAttackPath(scenario);

  let svgContent = '';
  const points = [];

  steps.forEach((step, i) => {
    const pos = archZonePositions[step.zone];
    if (!pos) return;
    // Offset to avoid overlapping when same zone appears multiple times
    const sameZonePrev = points.filter(p => p.zone === step.zone).length;
    const offsetX = sameZonePrev * 18 - (sameZonePrev > 0 ? 9 : 0);
    const offsetY = sameZonePrev * 12;
    points.push({
      x: pos.x + pos.w / 2 + offsetX,
      y: pos.y + pos.h / 2 + offsetY,
      zone: step.zone, label: step.label, index: i
    });
  });

  // Draw curved connecting lines
  for (let i = 0; i < points.length - 1; i++) {
    const p1 = points[i], p2 = points[i + 1];
    const midX = (p1.x + p2.x) / 2;
    const midY = (p1.y + p2.y) / 2 - 15;
    svgContent += `<path d="M${p1.x},${p1.y} Q${midX},${midY} ${p2.x},${p2.y}" fill="none" stroke="#ef4444" stroke-width="2" stroke-dasharray="8 4" opacity="0.6">
      <animate attributeName="stroke-dashoffset" from="24" to="0" dur="1.2s" repeatCount="indefinite"/>
    </path>`;
  }

  // Highlight affected zones with pulsing borders
  const uniqueZones = [...new Set(steps.map(s => s.zone))];
  uniqueZones.forEach(zone => {
    const pos = archZonePositions[zone];
    if (!pos) return;
    svgContent += `<rect x="${pos.x}" y="${pos.y}" width="${pos.w}" height="${pos.h}" rx="8" fill="rgba(239,68,68,0.06)" stroke="#ef4444" stroke-width="2" opacity="0.7">
      <animate attributeName="opacity" values="0.4;0.8;0.4" dur="2s" repeatCount="indefinite"/>
    </rect>`;
  });

  // Draw step circles with numbers
  points.forEach((p, i) => {
    svgContent += `<circle cx="${p.x}" cy="${p.y}" r="11" fill="#ef4444" opacity="0.9" stroke="#0a0e1a" stroke-width="2">
      <animate attributeName="r" values="11;13;11" dur="2s" begin="${i * 0.2}s" repeatCount="indefinite"/>
    </circle>`;
    svgContent += `<text x="${p.x}" y="${p.y + 1}" text-anchor="middle" dominant-baseline="middle" fill="white" font-size="8" font-weight="bold">${i + 1}</text>`;
  });

  // Animated moving dot along path
  if (points.length >= 2) {
    const pathD = points.map((p, i) => (i === 0 ? `M${p.x},${p.y}` : `L${p.x},${p.y}`)).join(' ');
    svgContent += `<circle r="5" fill="#ff4757" opacity="0.9">
      <animateMotion dur="${points.length * 1.2}s" repeatCount="indefinite" path="${pathD}"/>
    </circle>`;
  }

  // Scenario info box at bottom
  svgContent += `<rect x="10" y="570" width="940" height="40" rx="6" fill="rgba(239,68,68,0.08)" stroke="#ef444420" stroke-width="1"/>`;
  const sev = scenario.severity === 'critical' ? '#ef4444' : scenario.severity === 'high' ? '#f97316' : '#eab308';
  svgContent += `<text x="20" y="588" fill="${sev}" font-size="9" font-weight="700">⚠ ${scenario.name}</text>`;
  const descShort = scenario.description && scenario.description.length > 100 ? scenario.description.substring(0, 100) + '...' : (scenario.description || '');
  svgContent += `<text x="20" y="602" fill="#94a3b8" font-size="7.5">${descShort}</text>`;

  overlay.innerHTML = svgContent;

  // Show step descriptions below SVG
  let infoEl = document.getElementById('attack-step-info');
  if (!infoEl) {
    infoEl = document.createElement('div');
    infoEl.id = 'attack-step-info';
    infoEl.className = 'mt-2 text-xs';
    infoEl.style.color = 'var(--text-secondary,#94a3b8)';
    const dropdown = document.getElementById('arch-attack-dropdown');
    if (dropdown) dropdown.appendChild(infoEl);
  }
  infoEl.innerHTML = steps.map((s, i) =>
    `<span class="inline-flex items-center gap-1 mr-3 mb-1"><span style="display:inline-block;width:18px;height:18px;border-radius:50%;background:#ef4444;text-align:center;line-height:18px;font-size:8px;font-weight:bold;color:white">${i+1}</span> <span style="color:var(--risk-extreme,#f87171)">${s.zone}</span>: ${s.label}</span>`
  ).join('');
}

// Generate a sensible default attack path for scenarios without custom mapping
function generateDefaultAttackPath(scenario) {
  const cat = scenario.category || '';
  const phase = scenario.phase || 'execution';
  const steps = [];

  if (cat.includes('supply-chain')) {
    steps.push({ zone: 'External LLM API', label: '악성 패키지/스킬 게시' });
    steps.push({ zone: 'Plugin System', label: '손상된 컴포넌트 설치' });
    steps.push({ zone: 'Agent Runtime', label: '에이전트가 악성 코드 로드' });
    steps.push({ zone: 'Local Machine', label: '호스트에서 페이로드 실행' });
  } else if (cat.includes('prompt-injection')) {
    steps.push({ zone: 'Channel Adapters', label: '조작된 입력이 시스템 진입' });
    steps.push({ zone: 'Gateway', label: '에이전트로 입력 전달' });
    steps.push({ zone: 'Agent Runtime', label: '주입된 프롬프트가 추론 탈취' });
    steps.push({ zone: 'Plugin System', label: '의도하지 않은 도구 호출' });
  } else if (cat.includes('remote-code') || cat.includes('rce')) {
    steps.push({ zone: 'Channel Adapters', label: '익스플로잇 페이로드 전달' });
    steps.push({ zone: 'Gateway', label: '취약점 트리거' });
    steps.push({ zone: 'Agent Runtime', label: '코드 실행 달성' });
    steps.push({ zone: 'Local Machine', label: '시스템 침해' });
  } else if (cat.includes('credential')) {
    steps.push({ zone: 'Agent Runtime', label: '에이전트가 민감한 데이터 접근' });
    steps.push({ zone: 'Plugin System', label: '파일시스템/메모리 스킬 사용' });
    steps.push({ zone: 'Local Machine', label: '시스템에서 자격 증명 읽기' });
    steps.push({ zone: 'Channel Adapters', label: '데이터 유출' });
  } else if (cat.includes('hijack')) {
    steps.push({ zone: 'External LLM API', label: '공격자가 무단 접근 획득' });
    steps.push({ zone: 'Agent Runtime', label: '에이전트 세션 탈취' });
    steps.push({ zone: 'Plugin System', label: '무단 작업 수행' });
  } else if (cat.includes('multi-stage')) {
    steps.push({ zone: 'Channel Adapters', label: '초기 공격 벡터' });
    steps.push({ zone: 'Agent Runtime', label: '1단계 실행' });
    steps.push({ zone: 'Plugin System', label: '멀티 도구 체인 활성화' });
    steps.push({ zone: 'Memory Engine', label: '지속성 수립' });
    steps.push({ zone: 'Local Machine', label: '전체 침해' });
  } else {
    steps.push({ zone: 'Channel Adapters', label: '공격 시작' });
    steps.push({ zone: 'Gateway', label: '진입점 악용' });
    steps.push({ zone: 'Agent Runtime', label: '에이전트 침해' });
    if (phase === 'impact') steps.push({ zone: 'Local Machine', label: '대상에 대한 영향' });
  }
  return steps;
}

function renderRiskScoreOverlay() {
  let svg = '';
  const archComps = DATA.basic.architecture?.components || [];

  // Calculate risk scores per zone
  Object.entries(archZonePositions).forEach(([zone, pos]) => {
    const repos = DATA.repos.filter(r => {
      const comp = DATA.components.find(c => c.id === r.layer);
      if (!comp) return false;
      return comp.name === zone || (zone === 'Agent Runtime' && comp.name === 'Agent Runtime') || r.layer === pos.id;
    });

    const totalThreats = new Set(repos.flatMap(r => r.threat_ids || [])).size;
    const totalControls = new Set(repos.flatMap(r => r.control_ids || [])).size;
    const totalGaps = repos.reduce((s, r) => s + findControlGaps(r).length, 0);
    const coverage = totalThreats > 0 ? Math.round(totalControls / (totalControls + totalGaps) * 100) : 100;

    // Risk score: inverse of coverage weighted by threat count
    const riskScore = Math.round((100 - coverage) * Math.min(totalThreats / 5, 1) + totalThreats * 3);
    const clampedScore = Math.min(100, riskScore);

    // Color based on risk
    let borderColor, fillColor;
    if (clampedScore >= 70) { borderColor = '#ef4444'; fillColor = 'rgba(239,68,68,0.15)'; }
    else if (clampedScore >= 40) { borderColor = '#f97316'; fillColor = 'rgba(249,115,22,0.12)'; }
    else if (clampedScore >= 20) { borderColor = '#eab308'; fillColor = 'rgba(234,179,8,0.1)'; }
    else { borderColor = '#22c55e'; fillColor = 'rgba(34,197,94,0.08)'; }

    // Zone highlight border
    svg += `<rect x="${pos.x}" y="${pos.y}" width="${pos.w}" height="${pos.h}" rx="8" fill="${fillColor}" stroke="${borderColor}" stroke-width="2.5"/>`;

    // Risk score badge
    const cx = pos.x + pos.w/2;
    const cy = pos.y + pos.h/2;

    // Mini donut chart
    const donutR = 18;
    const circumference = 2 * Math.PI * donutR;
    const filled = (clampedScore / 100) * circumference;
    const remaining = circumference - filled;

    svg += `<circle cx="${cx}" cy="${cy}" r="${donutR}" fill="rgba(10,14,26,0.8)" stroke="#1e293b" stroke-width="1"/>`;
    svg += `<circle cx="${cx}" cy="${cy}" r="${donutR - 3}" fill="none" stroke="#1e293b" stroke-width="4"/>`;
    svg += `<circle cx="${cx}" cy="${cy}" r="${donutR - 3}" fill="none" stroke="${borderColor}" stroke-width="4" stroke-dasharray="${filled} ${remaining}" stroke-dashoffset="${circumference * 0.25}" stroke-linecap="round"/>`;
    svg += `<text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#ffffff" font-size="10" font-weight="700">${clampedScore}</text>`;
  });
  return svg;
}

function renderArchDefensePanel() {
  const defensePanel = document.getElementById('arch-defense-panel');
  if (archViewMode !== 'defense') {
    if (defensePanel) defensePanel.style.display = 'none';
    return;
  }

  if (!defensePanel) {
    // Create the defense panel below the diagram
    const el = document.createElement('div');
    el.id = 'arch-defense-panel';
    el.className = 'card mt-4';
    const diagramCard = document.querySelector('#arch-diagram')?.closest('.card');
    if (diagramCard) {
      diagramCard.parentElement.insertBefore(el, diagramCard.nextSibling);
    }
  }

  const panel = document.getElementById('arch-defense-panel');
  if (!panel) return;
  panel.style.display = '';

  let html = '<h3 class="card-title mb-3">\ud83c\udff0 Defense Coverage Matrix</h3>';
  html += '<div class="space-y-3">';

  Object.entries(archZonePositions).forEach(([zone, pos]) => {
    const repos = DATA.repos.filter(r => r.layer === pos.id);
    const threatIds = [...new Set(repos.flatMap(r => r.threat_ids || []))];
    const controlIds = [...new Set(repos.flatMap(r => r.control_ids || []))];
    const gaps = repos.flatMap(r => findControlGaps(r));
    const missingIds = [...new Set(gaps.flatMap(g => g.missing))];
    const totalThreats = threatIds.length;
    const coveredThreats = Math.max(0, totalThreats - missingIds.length);
    const coverage = totalThreats > 0 ? Math.round(coveredThreats / totalThreats * 100) : 100;
    const cveCount = (zoneCVEMap[zone] || []).length;

    html += `
      <div class="coverage-bar" style="background:var(--bg-input,#0d1321);border:1px solid #141c2e;border-radius:8px;padding:12px;cursor:pointer" onclick="this.querySelector('.coverage-details').classList.toggle('hidden')">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold" style="color:#e2e8f0">${zone}</span>
          <div class="flex items-center gap-3">
            <span class="text-xs text-gray-500">${totalThreats} threats</span>
            <span class="text-xs text-gray-500">${controlIds.length} controls</span>
            ${cveCount > 0 ? `<span class="text-xs" style="color:#ef4444">${cveCount} CVEs</span>` : ''}
            <span class="text-xs font-bold" style="color:${coverage >= 80 ? '#22c55e' : coverage >= 50 ? '#eab308' : '#ef4444'}">${coverage}%</span>
          </div>
        </div>
        <div class="w-full h-3 rounded-full" style="background:var(--bg-card,#141c2e);overflow:hidden">
          <div class="coverage-fill h-full rounded-full" style="width:${coverage}%;background:${coverage >= 80 ? '#22c55e' : coverage >= 50 ? '#eab308' : '#ef4444'};transition:width 0.3s"></div>
        </div>
        <div class="coverage-details hidden mt-3">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <div class="text-xs text-gray-500 mb-1">Covered Threats</div>
              ${threatIds.slice(0, coveredThreats).map(tid => {
                const t = DATA.threats.find(th => th.id === tid);
                return t ? `<div class="text-xs" style="color:#22c55e">\u2713 ${t.name}</div>` : '';
              }).join('')}
            </div>
            <div>
              <div class="text-xs text-gray-500 mb-1">Gaps</div>
              ${missingIds.map(mid => {
                const c = DATA.controls.find(ct => ct.id === mid);
                return c ? `<div class="text-xs" style="color:#ef4444">\u2717 ${c.name}</div>` : '';
              }).join('')}
              ${missingIds.length === 0 ? '<div class="text-xs" style="color:#22c55e">No gaps detected</div>' : ''}
            </div>
          </div>
        </div>
      </div>
    `;
  });

  html += '</div>';
  panel.innerHTML = html;
}

// === Use Case Flow Visualization ===
function renderUseCaseOverlay() {
  // Add use case dropdown if not exists
  let dropdown = document.getElementById('arch-usecase-dropdown');
  if (!dropdown) {
    dropdown = document.createElement('div');
    dropdown.id = 'arch-usecase-dropdown';
    dropdown.className = 'mb-3';
    dropdown.innerHTML = `
      <select id="arch-usecase-select" class="text-xs px-3 py-1.5 rounded" style="background:var(--bg-input,#0d1117);border:1px solid var(--border-primary,#1e293b);color:var(--text-primary,#e2e8f0);min-width:280px" onchange="animateUseCaseFlow(this.value)">
        <option value="">-- Select a use case --</option>
        ${archUseCases.map(uc => `<option value="${uc.id}">${uc.name} — ${uc.description}</option>`).join('')}
      </select>
      <div id="usecase-step-info" class="mt-2 text-xs" style="color:var(--text-secondary,#94a3b8)"></div>
    `;
    const diagramEl = document.getElementById('arch-diagram');
    if (diagramEl) diagramEl.parentElement.insertBefore(dropdown, diagramEl);
  }
  dropdown.style.display = '';
  return '';
}

function animateUseCaseFlow(usecaseId) {
  const svgEl = document.querySelector('#arch-diagram svg');
  if (!svgEl) return;

  // Clear previous animation
  const prev = svgEl.querySelector('#usecase-flow');
  if (prev) prev.remove();

  const uc = archUseCases.find(u => u.id === usecaseId);
  if (!uc) return;

  const stepInfo = document.getElementById('usecase-step-info');
  const phaseColors = {
    input: '#3b82f6', routing: '#f59e0b', processing: '#8b5cf6',
    memory: '#06b6d4', skill: '#10b981', execution: '#f97316',
    output: '#22c55e', admin: '#ec4899',
    local: '#f59e0b', llm: '#a78bfa'
  };

  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.setAttribute('id', 'usecase-flow');

  // Draw flow path and step indicators
  const points = [];
  uc.steps.forEach((step, i) => {
    const pos = archZonePositions[step.zone];
    if (!pos) return;
    // Offset each step slightly to avoid overlapping
    const offsetX = (i % 3 - 1) * 15;
    const offsetY = (Math.floor(i / 3) % 2) * 10;
    points.push({ x: pos.x + pos.w / 2 + offsetX, y: pos.y + pos.h / 2 + offsetY, step, index: i });
  });

  // Draw connecting lines with gradient
  for (let i = 0; i < points.length - 1; i++) {
    const p1 = points[i], p2 = points[i + 1];
    const color = phaseColors[p1.step.phase] || '#00e6a7';
    // Curved path
    const midX = (p1.x + p2.x) / 2;
    const midY = (p1.y + p2.y) / 2 - 20;
    g.innerHTML += `<path d="M${p1.x},${p1.y} Q${midX},${midY} ${p2.x},${p2.y}" fill="none" stroke="${color}" stroke-width="2.5" stroke-dasharray="8 4" opacity="0.7">
      <animate attributeName="stroke-dashoffset" from="24" to="0" dur="1.5s" repeatCount="indefinite"/>
    </path>`;
    // Arrow at midpoint
    const angle = Math.atan2(p2.y - p1.y, p2.x - p1.x);
    const ax = midX, ay = midY + 10;
    g.innerHTML += `<polygon points="${ax},${ay-4} ${ax+8},${ay} ${ax},${ay+4}" fill="${color}" opacity="0.8" transform="rotate(${angle*180/Math.PI},${ax},${ay})"/>`;
  }

  // Draw step circles with numbers
  points.forEach((p, i) => {
    const color = phaseColors[p.step.phase] || '#00e6a7';
    g.innerHTML += `
      <circle cx="${p.x}" cy="${p.y}" r="14" fill="${color}" opacity="0.9" stroke="#fff" stroke-width="1.5">
        <animate attributeName="r" values="14;16;14" dur="2s" begin="${i * 0.3}s" repeatCount="indefinite"/>
      </circle>
      <text x="${p.x}" y="${p.y + 1}" text-anchor="middle" dominant-baseline="middle" fill="white" font-size="10" font-weight="bold">${i + 1}</text>
    `;
  });

  // Append overlay
  const overlayGroup = svgEl.querySelector('#arch-overlay');
  if (overlayGroup) {
    overlayGroup.appendChild(g);
  } else {
    const newG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    newG.setAttribute('id', 'arch-overlay');
    newG.appendChild(g);
    svgEl.appendChild(newG);
  }

  // Show step descriptions
  if (stepInfo) {
    stepInfo.innerHTML = `<div class="font-bold mb-2" style="color:#e2e8f0">${uc.name}</div>` +
      uc.steps.map((s, i) => {
        const color = phaseColors[s.phase] || '#00e6a7';
        return `<span class="inline-flex items-center gap-1 mr-3 mb-1"><span style="display:inline-block;width:18px;height:18px;border-radius:50%;background:${color};text-align:center;line-height:18px;font-size:9px;font-weight:bold;color:white">${i+1}</span> ${s.label}</span>`;
      }).join('');
  }
}

// === Defense SVG Overlay (zone border coloring) ===
function renderDefenseOverlay() {
  let overlay = '';
  Object.entries(archZonePositions).forEach(([zone, pos]) => {
    const repos = DATA.repos.filter(r => r.layer === pos.id);
    const threatIds = [...new Set(repos.flatMap(r => r.threat_ids || []))];
    const totalThreats = threatIds.length;
    const gaps = repos.flatMap(r => findControlGaps(r));
    const missingCount = [...new Set(gaps.flatMap(g => g.missing))].length;
    const coverage = totalThreats > 0 ? Math.round((totalThreats - missingCount) / totalThreats * 100) : 100;
    const color = coverage >= 80 ? '#22c55e' : coverage >= 50 ? '#eab308' : '#ef4444';

    overlay += `<rect x="${pos.x}" y="${pos.y}" width="${pos.w}" height="${pos.h}" rx="8" fill="${color}" opacity="0.15" stroke="${color}" stroke-width="2" stroke-dasharray="6 3"/>`;
    overlay += `<text x="${pos.x + pos.w/2}" y="${pos.y + pos.h/2 + 4}" text-anchor="middle" fill="${color}" font-size="16" font-weight="bold">${coverage}%</text>`;
  });
  return overlay;
}
