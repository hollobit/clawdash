# OpenClaw Ecosystem Dashboard - 업데이트 이력

## 2026-03-11 (Session 9): Kill Chain 시각화 + 데이터/코드 품질 + 데이터 업데이트

### Kill Chain 인터랙티브 시각화 (Architecture 탭)
- **9번째 뷰 모드 추가**: Kill Chain 흐름 시각화
- **`renderKillChainFlowOverlay()`**: SVG 오버레이 (상단 7단계 화살표, 존 하이라이트, 곡선 연결 경로, 애니메이션 점)
- **`renderKillChainDetailPanel()`**: 선택한 단계의 위협/시나리오 상세 패널
  - 2-column 그리드: 위협 (심각도, MITRE ID, 컨트롤), 시나리오 (태그, flow_path, 참조)
- **`showKillChainPhaseDetail()`**: 단계 토글, `kc-detail-container`에 삽입
- **`killChainZoneMapping`**: 7단계 → 아키텍처 존 매핑 + 색상 정의

### 데이터 품질 개선 (Phase 6)
- `data/attacks.json`: malicious_percent 11.9→8.0 수정, 설명 노트 추가
- `data/timeline.json`: stats.cves 15→26 수정, 24개 YYYY-MM 날짜를 YYYY-MM-15로 정규화
- `data/skills.json`: Uncategorized 카테고리 추가 (9,282개), categories_count 35→36
- `data/arch-security-map.json`: Zone E coverage_pct 100.0→71.4 수정
- `data/papers.json`: 29개 논문 mapped_components 중복 제거
- `data/repos.json`: skill-python에 ecosystem_repo_id 추가
- 7개 JSON 파일에 `data_as_of` 필드 추가

### 코드 품질 개선 (Phase 7)
- **`escapeHtml()`**: XSS 방지 유틸리티 함수 추가, `highlightMatch()` 및 검색 결과에 적용
- **`debounce()`**: 300ms 검색 입력 디바운싱 (eco/skill/attack/timeline 검색)
- **CSS 변수 폴백**: 63개 하드코딩 색상값을 CSS 변수 + 폴백으로 교체
- **`STATE` 객체**: 전역 변수 통합 관리 패턴 도입
- **이벤트 리스너 정리**: `addEventListener` → `onclick` 프로퍼티 할당 (렌더 함수)
- **`switchTab()` 통합**: `initTabs()`, `navigateToLayer()` 호출 일관화

### 데이터 업데이트
- **timeline.json**: 5건 신규 이벤트 추가 (총 60건)
  - ROME 인시던트 (Alibaba AI 에이전트 자율 크립토마이닝)
  - 30 MCP CVEs in 60 Days 마일스톤
  - Gravitee AI Agent Security 2026 보고서
  - CrowdStrike 2026: AI 공격 89% 증가
  - IBM X-Force 2026: 앱 익스플로잇 44% 증가
- **papers.json**: 8건 신규 논문 추가 (총 45편)
  - AgentDyn, SMCP, OpenAgentSafety, TAIP Framework
  - Memory Poisoning Defense, MemoryGraft
  - From Prompt Injections to Protocol Exploits
  - MCP at First Glance

### 빌드
- `index.html`: 재빌드 (~673KB, ~4,700줄 JS)
- JS 문법 검증: 통과
- 전체 JSON 파일: 유효

---

## 2026-03-11 (Session 8): 아키텍처 시각화 확장 + 버그 수정

### Architecture 뷰 모드 확장 (6 → 8개)

#### Use Cases 뷰 (신규)
- **14개 사용 사례 흐름** 시각화: 드롭다운으로 선택, SVG 애니메이션
  - 기본 5개: Chat, Skill Execution, Memory Retrieval, Multi-Channel, Admin
  - 확장 4개: File Ops, Web Browsing, LLM Reasoning, Code Execution
  - 고급 4개: Multi-Agent Orchestration, Voice Call, Coding Assistant, Scheduled Digest
- 각 흐름은 존 간 단계별 경로 + 페이즈 색상 코딩 (input/routing/processing/skill/memory/output)
- External LLM API + Local Machine 존 포함

#### Threats 뷰 (신규)
- **12개 위협 유형**을 아키텍처 존별로 시각화
- 존 오버레이: 최고 심각도 기준 색상 (Critical/High/Medium/Low)
- Primary vs Propagated 위협 배지 (클릭 시 상세 팝오버)
- 전파 화살표: 주황색 점선 애니메이션으로 위협 전파 경로 표시
- 팝오버: 위협 설명, MITRE ID, 적용 컨트롤 표시

#### Attack Flow 뷰 전면 재작성
- **`attackFlowPaths`**: 25+ 시나리오별 상세 공격 경로 (기존 `phaseToZone` 단순 매핑 대체)
- 시나리오별 실제 컴포넌트 연결 (예: Browser skill → Plugin System → Sandbox → Local Machine)
- Supply Chain → ClawHub(Plugin System) 경유 흐름 반영
- **`generateDefaultAttackPath()`**: 카테고리 기반 폴백 (미매핑 시나리오용)
- 곡선 SVG 경로, 번호 원형, 펄싱 존 하이라이트, 단계 설명

### Architecture 다이어그램 확장
- **SVG 확장**: 960×620 → 960×820, 하단에 Ecosystem Extensions 행 추가
- **Hardware/IoT 존**: ESP32-Claw, MimiClaw, RoboClaw, HomeClaw 등 8개 하드웨어 레포
- **Cloud/Hosted 존**: CloudClaw, ServerlessClaw, MoltWorker 등 7개 클라우드 레포
- **China Ecosystem 존**: MaxClaw(MiniMax), CoPaw(Alibaba), ArkClaw(ByteDance), WorkBuddy(Tencent), AutoClaw(Zhipu) 6개
- 각 존 클릭 → Ecosystem 탭 해당 카테고리 필터로 이동
- `archZonePositions`에 3개 신규 존 추가, scaleY 620→820 업데이트

### 한글화
- **Use Case 시각화**: 13개 사용 사례의 제목, 설명, 단계별 라벨 전체 한글화
- **Attack Flow 시각화**: 26개 시나리오별 공격 경로 라벨 한글화
- **기본 공격 경로**: `generateDefaultAttackPath()` 7개 카테고리 폴백 라벨 한글화

### Light Mode 가독성 개선
- CSS 변수 강화: `--text-primary` #0f172a, `--text-secondary` #334155, `--text-muted` #64748b
- 인라인 스타일 오버라이드 13개 추가 (#e2e8f0, #cbd5e1, 악센트 색상 등)
- Tailwind `text-gray-*` 클래스 전체 한 단계 어둡게

### 버그 수정
- **Heatmap 0 threats 문제**: `zoneToLayer` ID 매핑 불일치 수정
- **Heatmap 클릭 팝오버 추가**: 존 클릭 시 위협 목록 + 관련 시나리오 상세 표시
- **Threat 팝오버 클릭 수정**: SVG→화면 좌표 변환, `pointer-events` 설정
- **Architecture 다이어그램 중복 스크롤 수정**: `overflow:visible`로 변경
- **Use Case/Attack Flow 드롭다운 Light Mode 수정**: 하드코딩 다크 배경 → CSS 변수

### 빌드
- `index.html`: 재빌드 (~604KB, ~4,300줄 JS)
- JS 문법 검증: 통과

---

## 2026-03-11 (Session 7): 대규모 UI/UX 개편 + 아키텍처 동적 시각화 + 데이터 자동화

### 5개 워크스트림 병렬 구현

#### 1. CSS 대개편 (`css/style.css`)
- **CSS 변수 시스템**: `:root`에 35+ 커스텀 프로퍼티 (배경, 텍스트, 액센트, 리스크, 그림자, 반경, 트랜지션)
- **`[data-theme="light"]` 오버라이드**: 라이트 테마 변수 분리
- **통합 카드 컴포넌트**: `.dash-card`, `.dash-card-header`, `.dash-card-body`, `.dash-card.clickable`
- **통합 필터 바**: `.filter-bar`, `.filter-btn`, `.filter-count` (카운트 배지 포함)
- **반응형 브레이크포인트**: 태블릿(1024px), 모바일(640px)
- **마이크로 인터랙션**: `fadeIn` 탭 전환, `pulse-critical` 긴급값, 스크롤바 스타일
- **아키텍처 시각화 CSS**: `.arch-view-btn`, `.cve-badge`, `.heatmap-overlay`, `.attack-flow-path`, `.zone-active`, `.coverage-bar`, `.arch-popover`

#### 2. 데이터 크로스레퍼런스 강화
- `data/attacks.json`: 25개 CVE에 `affected_zones` + `kill_chain_path` 추가, 46개 시나리오에 `flow_path` 추가
- `data/threats.json`: 12개 위협에 `primary_zones` + `propagation_zones` 추가
- `data/controls.json`: 30개 컨트롤에 `applicable_zones` 추가
- `data/arch-security-map.json` 신규: 존별 보안 요약 (zone_summary, zone_cves, zone_threats, zone_controls, coverage_gaps)

#### 3. 데이터 자동화 스크립트 (`scripts/`)
- `validate_data.py`: 45+ 체크 (스키마, 크로스레퍼런스, 데이터 품질, 통계 일관성)
- `collect_github.py`: GitHub API 기반 생태계 레포 자동 수집
- `collect_arxiv.py`: arXiv API 기반 논문 수집 + 자동 태깅 (moltbook/openclaw/mcp)
- `collect_cves.py`: NVD 2.0 + GitHub Advisory 기반 CVE 수집
- `update_stats.py`: 전체 데이터 파일 통계 감사 + 자동 갱신
- `generate_report.py`: Markdown/HTML 보안 리포트 자동 생성
- `README.md`: 스크립트 사용 가이드

#### 4. 아키텍처 동적 시각화 (`js/app.js` +456줄)
- **뷰 모드 토글**: 6개 모드 (Structure/Heatmap/CVE Map/Attack Flow/Defense/Risk Score)
- **CVE 배지**: 각 존 우측 상단에 CVE 카운트 빨간 배지, 클릭 시 CVE 목록 팝오버
- **위협 히트맵**: 존별 위협 밀도에 따른 색상 오버레이 (녹→황→적)
- **공격 플로우 애니메이션**: 시나리오 선택 → 존 간 공격 경로 SVG 애니메이션, Kill Chain 단계 표시
- **방어 커버리지 매트릭스**: 존별 위협 vs 컨트롤 커버리지 바, Gap 표시
- **리스크 스코어 오버레이**: 존 내 미니 도넛 차트 + 색상 코딩

#### 5. Overview 리디자인 + 카드 통합 (`js/app.js` +226줄)
- **Executive Summary 배너**: 보안 상태 표시 (HIGH RISK + CVE 카운트 + 시나리오 + 이벤트)
- **메트릭 그리드**: 6-column 통합 메트릭 (Repos, Skills, CVEs, Scenarios, Controls, Threats)
- **최근 이벤트 피드**: 최신 7건 타임라인 이벤트 실시간 표시
- **내비게이션 카드**: 8개 탭별 프리뷰 데이터 카운트
- **Top Risk 모듈**: 최고 위험 5개 모듈 리스크 바
- **카드 통합**: 전체 11개 탭에 `dash-card` 클래스 적용
- **필터 바 헬퍼**: `renderFilterBar()` 공통 함수 (Research Monitor, Attacks, Timeline 적용)

### 빌드
- `index.html`: 재빌드 (532,974자, ~533KB)
- JS 문법 검증: 통과
- JSON 15개 파일: 모두 유효

---

## 2026-03-10 (Session 6): 대규모 데이터 업데이트 + 링크 연결 + UI 개선

### 데이터 대규모 업데이트 (리서치 에이전트 4개 병렬 조사)
- `data/ecosystem.json`: **16개 신규 레포** 추가 (160~200+ 총 레포)
  - OpenClaw 공식: lobster(786★), acpx(665★), nix-openclaw(516★), openclaw-ansible(478★), clawdinators(137★), trust(29★)
  - 경량 변형: nullclaw/nullclaw(Zig), nearai/ironclaw(Rust/WASM)
  - MCP 생태계: github/github-mcp-server(4.2K★), microsoft/mcp(1.8K★), modelcontextprotocol/servers(15.2K★), awesome-mcp-servers(8.9K★)
  - 프레임워크: obra/superpowers(27K★), cloudflare/moltworker, DenchClaw, aliasrobotics/cai
  - 기존 레포 스타 수 업데이트 (openclaw 295.5K 등)
- `data/attacks.json`: **4개 신규 CVE** + **6개 신규 공격 시나리오** + **2개 신규 공격 표면**
  - CVE: CVE-2026-28458(Browser Relay WebSocket), CVE-2026-28466(Gateway Approval), CVE-2026-28468(Sandbox Browser Bridge), CVE-2026-28479(SHA-1 Cache Poisoning)
  - 시나리오: Cline CLI Supply Chain, Perplexity Comet Zero-Click, Promptware Kill Chain(Schneier), MCP Sampling Injection, Delayed Tool Invocation, SKILL.md to Shell(3줄)
  - 공격 표면: MCP Sampling Injection, Delayed Tool Invocation (Agent Reasoning 레이어)
  - 총 46 시나리오, 42 공격 표면, 15 CVE
- `data/timeline.json`: **8개 신규 이벤트** 추가 (총 55건)
  - Cline 공급망 공격(2/17), MITRE ATLAS OpenClaw 조사(2/9), Perplexity Comet PleaseFix(3/3)
  - Promptware Kill Chain(2월), Claude Code 취약점(2/25), NIST AI Agent 표준(2월)
  - Tencent WeKnora CVE 3건(3/7), Cisco State of AI Security 2026(3/9)
- `data/skills.json`: **3개 신규 카테고리** + **11개 신규 스킬** 추가
  - 카테고리: Observability & Monitoring(68), Legal & Compliance(42), Enterprise & Governance(55)
  - 스킬: datadog-mcp, grafana-agent, sentry-monitor, pagerduty-ops, gdpr-compliance, contract-analyzer, sox-auditor, okta-identity, jira-workflow, confluence-wiki, vault-secrets
  - 총 14,850 스킬, 35 카테고리, 136 top skills
- `data/controls.json`: **3개 신규 컨트롤** 추가 (총 30개)
  - OIDC Package Publishing, Agent Filesystem Restrictions, MCP Auth Enforcement

### 외부 링크 연결 (전체 탭)
- **Overview**: CVE → NVD 상세 링크
- **Basic**: 모든 Docs 링크 정상 URL 검증 및 수정 (57개 URL 검증, 28개 수정)
  - OpenAI URL: platform.openai.com → developers.openai.com
  - GitHub openclaw docs: 실제 경로 매핑 (workspace/→reference/, memory/→concepts/, architecture/→gateway/ 등)
- **Attacks**: CVE → NVD + MITRE 상세 링크 버튼
- **Incident**: 타임라인 역시간순 정렬, 참조 → 클릭 가능 링크 (arXiv→직접, 기타→Google 검색)
- **Security Review**: ATLAS/ATT&CK ID → MITRE 사이트 링크
- **Research Monitor**: 논문 제목 → arXiv 링크 + arXiv 뱃지
- **Moltbook**: Incidents 참조 + Controversies 소스 → 클릭 가능 링크

### Research Monitor 필터 확장
- "Moltbook", "OpenClaw" 카테고리 필터 추가 (topic_tags 기반 필터링)

### Moltbook 탭 업데이트
- 주요 수치 최신화: 2.14M agents, 22K humans, 287K posts, 18.7K submolts
- "Data as of 2026-03-10" 날짜 표시 추가

### 아키텍처 모델 통일
- `data/components.json`: 추상 8-Layer → 8개 구체 컴포넌트로 전면 교체
  - Gateway(A), Agent Runtime(B), Plugin System(C), Sandbox(D), Memory Engine(E), Control UI(F), TUI/CLI(G), Channel Adapters(H)
- `data/repos.json`: 21개 모듈의 layer 필드를 신규 컴포넌트 ID로 매핑
- `data/threats.json`: 12개 위협의 affected_layers를 신규 ID로 매핑 + 중복 제거
- `data/papers.json`: 50개 논문의 mapped_components를 신규 ID로 매핑 + 렌더링 시 dedup

### Skills 확장
- Top Skills by Downloads: 47개 → 136개 (31→35 카테고리 커버)

### 탭 이름 변경
- Resource Directory → **Risk/Threat**

### UI 개선
- 전체 base font-size: 15px → **16px** (+1px)

### 빌드
- `index.html`: 재빌드 (~486KB)

---

## 2026-03-10 (Session 5): arXiv 논문 대규모 추가

### Research Monitor 대폭 확장 (27 → 50편)
- `data/papers.json`: 23개 신규 arXiv 논문 추가 (총 50편)
  - **OpenClaw 보안 5편**:
    - Proof-of-Guardrail (2603.05786): 형식 안전 검증 프레임워크
    - Clawdrain (2603.00902): 토큰 고갈 공격
    - Clawdbot Safety Audit (2602.14364): 궤적 기반 안전 감사
    - Frontier AI Risk Framework (2602.14457): 리스크 관리 프레임워크
    - Visibility vs Verification (2602.11412): 빠른 배포의 보안 위험
  - **Moltbook 분석 12편**:
    - Molt Dynamics (2603.03555), MoltGraph (2603.00646), MoltNet (2602.13458)
    - Interaction Theater (2602.20059), Social Graph Anatomy (2602.10131)
    - Collective Behavior (2602.09270), Fast Response or Silence (2602.07667)
    - Moltbook Illusion (2602.07432), Network Topology (2602.13920)
    - Structural Divergence (2602.15064), Statistical Signature (2602.18152)
    - Privasis (2602.03183)
  - **에이전트 사회 연구 4편**:
    - Silicon-Based Societies (2602.02613), Agents as Personas (2603.03140)
    - Informal Learners (2602.18832), Agents Teach Each Other (2602.14477)
  - **소셜 네트워크 분석 2편**:
    - Let There Be Claws (2602.20044), Human Control Anchor (2602.09286)
- `index.html`: 재빌드 (367KB)

---

## 2026-03-10 (Session 4): Basic/Moltbook 탭 + 대규모 데이터 확장

### Basic 탭 신규 추가
- `data/basic.json` 신규 생성: 프로젝트 기본 정보, 메모리 시스템, 아키텍처, CLI 명령어
  - 28개 릴리즈 이력 (Warelay 1.1.0 ~ OpenClaw 2026.3.8)
  - 명칭 변천사 4단계 (Warelay → Clawdis → Clawdbot → OpenClaw)
  - 10개 워크스페이스 파일 설명 + 보안 주의사항
  - 2-Layer 메모리 시스템 (하이브리드 검색 Vector 70% + BM25 30%)
  - 8개 아키텍처 컴포넌트, 11개 CLI 명령어
  - 15개 LLM 프로바이더, 12개 메시징 채널
- `js/app.js`: `renderBasic()` 함수 추가 (~150줄)
- `index.html`: Basic 탭 HTML (Overview 바로 다음 2번째 위치)
- `rebuild.py`: basic.json/BASIC_DATA 추가

### Moltbook 탭 신규 추가 (SNS 탭 대체)
- `data/moltbook.json` 신규 생성: Moltbook 전용 심층 분석
  - 개요: Matt Schlicht 창시, Supabase 기반, 코드 0줄 AI 빌드
  - 21개 이벤트 타임라인 (런칭부터 DB 패치까지 분 단위)
  - 4개 보안 사건 (Supabase DB 노출, 프롬프트 인젝션 전파, ClawHub 악성 스킬, MOLT 밈코인)
  - 6개 주요 논쟁 (99% 가짜 계정, 인간 LARP, 디지털 종교, 디지털 마약, 반인간 감시, 안전 퇴화)
  - 6명 주요 인물, 8개 서브몰트, 6개 arXiv 논문, 18개 미디어 보도
- `data/social.json` 유지 (SNS 탭에서 분리, 향후 참조용)
- `js/app.js`: `renderSocial()` → `renderMoltbook()` 교체 (~140줄)
- `index.html`: SNS 탭 → Moltbook 탭 교체
- `rebuild.py`: social→moltbook 데이터 교체

### Ecosystem 데이터 대폭 확장
- `data/ecosystem.json`: 12개 신규 레포 추가 (총 131개)
  - alphaclaw, skyclaw, openclaw-mission-control, ClawWork, clawdeck, clawhost 등
  - k8s-operator, openclaw-security-monitor, secure-openclaw, openclaw-helm, adversa-secureclaw
- `data/repos.json`: 3개 심층 분석 추가 (총 21개)
  - skyclaw (Risk 70, Critical), clawwork (Risk 68, Critical), alphaclaw (Risk 55, High)

### Research Monitor 대폭 확장
- `data/papers.json`: 10개 신규 논문 추가 (총 27개)
  - OpenClaw 직접 관련: PASB 보안 벤치마크 (2602.08412), SoK 프롬프트 인젝션 (2601.17548)
  - Moltbook 분석 6편: First Look (2602.10127), Risky Instructions (2602.02625),
    Agents in the Wild (2602.13284), Devil Behind Moltbook (2602.09877),
    Socialization (2602.14299), Discourse Analysis (2602.12634)
  - ClawdLab (2602.19810), AI Agent Index (2602.17753)

### Security 데이터 대폭 확장 (에이전트 수행)
- `data/attacks.json`: 7개 신규 공격 시나리오 추가 (총 40개), 8개 신규 CVE 추가 (총 11개)
  - CVE-2026-28446 Voice Extension Pre-Auth RCE (CVSS 9.8)
  - CVE-2026-28484, CVE-2026-29610, CVE-2026-28462, CVE-2026-28485
  - CVE-2026-28478, CVE-2026-28394, CVE-2026-28450, CVE-2026-28465
  - ClawHavoc 캠페인 (1,184+ 악성 스킬), Mass Instance Exposure (135K+)
- `data/timeline.json`: 10개 신규 이벤트 추가 (총 47개)
  - SecurityScorecard 135K+ 노출 보고, Microsoft Security Blog 경고
  - GitHub Advisory DB 245 취약점, v2026.2.26 보안 강화 릴리즈

### 탭 재구성
- Timeline → **Incident** (탭 라벨 변경)
- Basic 탭을 Overview 바로 다음 2번째 위치로 이동
- 탭 순서: Overview → Basic → Ecosystem → Skills → Resource Directory → Attacks → Incident → Security Review → Research Monitor → Moltbook

---

## 2026-03-10 (Session 3): 리스크 스코어링 + 종합 리뷰

### 리스크 스코어링 모델 적용
- **리스크 스코어링 프레임워크 도입**: 5요소 가중 평가 모델 (Execution 30%, Data Access 25%, External Dependency 20%, Privilege 15%, Social Engineering 10%)
- `data/repos.json`: 15개 핵심 모듈에 `risk_score` 필드 추가 (total, level, policy, 5개 요소별 점수)
- `data/skills.json`: 40개 top_skills에 `risk_score` 필드 추가
- `data/skill-risk-scores.json`: 40개 스킬 상세 리스크 분석 결과 (요소별 근거 포함)
- `js/app.js`: `calcRiskLevel()` 함수 업데이트 — `risk_score.level` 기반 판정 우선
- `js/app.js`: `riskScoreLabel()`, `policyBadgeHtml()` 헬퍼 함수 추가
- Resource Directory 카드에 점수(XX/100) + Policy 뱃지(Allow/Sandbox/Restricted/Block) 표시
- Skills 탭 스킬 목록에 점수 + Policy 뱃지 표시
- `merge_risk_scores.py`: 리스크 스코어 데이터 병합 스크립트 작성

### 종합 시스템 리뷰
- 3개 전문가 에이전트 병렬 분석 수행:
  - **OpenClaw 전문가**: 8개 탭 간 8쌍 중복/혼동 관계 식별
  - **OpenClaw 개발자**: Ecosystem/Skills/Directory 간 데이터·기능 중복 분석
  - **사이버보안 전문가**: Attacks/Timeline/Security Review 간 위협 데이터 중복 + P0 버그 발견
- Team Lead 에이전트가 종합 수정 계획안 수립 → `MODIFICATION_PLAN.md`
  - Phase 1 (P0 긴급): 4건 — Kill Chain 버그, 데이터 로딩, 수치 불일치
  - Phase 2 (단기): 7건 — FK 추가, MITRE 통일, 중복 정리, 공통 함수 추출
  - Phase 3 (중기): 6건 — 크로스-탭 네비게이션, URL 라우팅, 검색 통합
  - Phase 4 (장기): 5건 — 공격-방어 매트릭스, 데이터 내보내기, 차트
  - Phase 5 (Overview 개선): 6건 — Alert Banner, Stat 확장, Executive Summary

### 컬러 테마 리디자인
- **Dark Mode**: 기존 blue/gray → Obsidian (#0a0e1a) + Electric Teal (#00e6a7/#00d4aa)
- **Light Mode**: 기존 generic → Cool Pearl (#f4f6f9) + Emerald (#047857/#00b894)
- `css/style.css` 전면 재작성 (626줄)
- `js/app.js`: 인라인 컬러 전체 교체 (#1e293b→#141c2e, #60a5fa→#00e6a7, #3b82f6→#00d4aa 등)
- `data/timeline.json`, `data/ecosystem.json`: phase color 값 업데이트
- Light mode 오버라이드 추가: `background:#141c2e`, `color:#5a6d84`, `color:#ffc312`

---

## 2026-03-09 (Session 2): Timeline + Attacks + 가독성 개선

### Timeline 탭 추가
- `data/timeline.json` 신규 생성: 32 보안 이벤트 (2023-2026), 4 진화 단계, 3 구조적 원인
- `js/app.js`: `initTimeline()`, `renderTimeline()`, `timelineSeverityColor()`, `timelineCategoryIcon()` 함수 추가
- `index.html`: Timeline 탭 HTML 템플릿 추가 (stat 카드, 진화 단계, 구조적 원인, 연도별 이벤트)

### Attacks 탭 추가
- `data/attacks.json` 신규 생성: 30 시나리오, 40 공격 표면 (7계층), 3 CVE, 6단계 Kill Chain, MITRE 매핑
- `js/app.js`: `initAttacks()`, `renderAttacks()` 함수 추가
- `index.html`: Attacks 탭 HTML 템플릿 추가 (stat 카드, Kill Chain, 공격 표면, CVE, 시나리오, MITRE)

### Ecosystem 업데이트
- `data/ecosystem.json`: dependency_network 섹션 추가 (Hub-and-Spoke 모델, 5 의존성 유형, 공급망 시각화)

### 한국어 가독성 개선
- Pretendard 폰트 CDN 추가
- `css/style.css`: font-size 최소 0.8rem, line-height 1.65, word-break: keep-all
- Light mode 인라인 스타일 오버라이드 106건 추가
- Dark mode 텍스트 대비 향상 (#e2e8f0 → #cbd5e1)

---

## 2026-03-08 (Session 1): 초기 대시보드 구축

### 프로젝트 생성
- Single-file SPA 아키텍처 설계 (file:// 프로토콜 호환)
- Tailwind CSS v2 CDN 기반 스타일링

### 6개 탭 구현
- **Overview**: 4 stat 카드, Risk Distribution, Top Threats, Architecture Layers
- **Ecosystem**: 12 카테고리, 100+ 레포 카탈로그, 검색/정렬
- **Skills**: 13,729 스킬 통계, 32 카테고리, top 40 다운로드 순위
- **Resource Directory**: 15 핵심 모듈, 필터 사이드바, 상세 패널 (위협/컨트롤/갭/논문)
- **Security Review**: 위협 카탈로그 (12), 컨트롤 카탈로그 (27), Kill Chain
- **Research Monitor**: 10 논문, 타입 필터, 토픽 분포, Paper-Component 매핑

### 데이터 파일 생성
- `data/components.json`: 8개 아키텍처 레이어 (Brain~Security)
- `data/repos.json`: 15개 핵심 모듈 (위협/컨트롤/논문/MITRE 매핑)
- `data/ecosystem.json`: 100+ 생태계 레포 (12 카테고리)
- `data/skills.json`: ClawHub 스킬 통계 + top 40
- `data/threats.json`: 12 위협 유형 (severity, kill_chain_phase, MITRE, controls)
- `data/controls.json`: 27 보안 컨트롤
- `data/papers.json`: 10 연구 논문 (2025)

### 빌드 시스템
- `rebuild.py`: CSS + JS + 9개 JSON → 단일 index.html 빌드
- loadData() → 인라인 데이터 할당으로 변환 (file:// CORS 해결)
- JS 문법 검증 체계 구축
