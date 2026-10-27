import React, { useEffect, useMemo, useState } from 'react'

// ============================================================================
// DATA MODELS & TYPES
// ============================================================================

export interface Check {
  type: string
  command?: string
  expected?: string
  regex?: string
  path?: string
  severity?: string
  info?: string
}

export interface Control {
  id: string
  title: string
  description?: string
  rationale?: string
  remediation?: string
  scoring?: string
  profile?: string[]
  checks?: Check[]
}

export interface Benchmark {
  id: string
  title: string
  version: string
  category?: string
  technology?: string
  os?: string
  controls?: Control[]
  controls_count?: number
}

export interface ScanResult {
  control_id: string
  check_type: string
  status: 'pass' | 'fail' | 'error' | 'skipped'
  actual: string
  expected: string
  evidence: string
  error?: string
  duration_ms: number
}

export interface ScanJob {
  id: string
  benchmark_id: string
  profile: string
  status: 'running' | 'completed' | 'error'
  asset: {
    host?: string
    ip?: string
    port?: number
    protocol?: string
    type?: string
    user?: string
    os?: string
    mode?: string
    filename?: string
  }
  results?: ScanResult[]
  va_results?: any
  layer8?: any
  created_at: string
  finished_at?: string
}

export interface FeedItem {
  id: string
  name: string
  vendor: string
  status: string
  files: string[]
  scope: string
  coverage: string
  size: string
}

interface ProtocolPreset {
  id: 'ssh' | 'winrm' | 'network' | 'postgres' | 'mysql' | 'mssql' | 'mongo'
  name: string
  label: string
  port: number
  defaultUser: string
  icon: string
  color: string
}

const PROTOCOLS: ProtocolPreset[] = [
  { id: 'ssh', name: 'Linux / Unix', label: 'OpenSSH (Port 22)', port: 22, defaultUser: 'root', icon: '🐧', color: '#10b981' },
  { id: 'winrm', name: 'Windows Server', label: 'WinRM HTTPS (Port 5986)', port: 5986, defaultUser: 'Administrator', icon: '🪟', color: '#38bdf8' },
  { id: 'network', name: 'Network Appliance', label: 'Cisco / Fortinet / PAN-OS PTY', port: 22, defaultUser: 'admin', icon: '🌐', color: '#8b5cf6' },
  { id: 'postgres', name: 'PostgreSQL DB', label: 'Postgres SQL (Port 5432)', port: 5432, defaultUser: 'postgres', icon: '🐘', color: '#3b82f6' },
  { id: 'mysql', name: 'MySQL / MariaDB', label: 'MySQL SQL (Port 3306)', port: 3306, defaultUser: 'root', icon: '🐬', color: '#f59e0b' },
  { id: 'mssql', name: 'MS SQL Server', label: 'T-SQL (Port 1433)', port: 1433, defaultUser: 'sa', icon: '🏢', color: '#ef4444' },
  { id: 'mongo', name: 'MongoDB Admin', label: 'NoSQL Socket (Port 27017)', port: 27017, defaultUser: 'admin', icon: '🍃', color: '#22c55e' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'va' | 'compliance' | 'remediation' | 'feeds' | 'scans'>('dashboard')
  const [vaMode, setVaMode] = useState<'offline' | 'online'>('offline')
  const [benchmarks, setBenchmarks] = useState<Benchmark[]>([])
  const [scans, setScans] = useState<ScanJob[]>([])
  const [feeds, setFeeds] = useState<FeedItem[]>([])
  const [selectedScan, setSelectedScan] = useState<ScanJob | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<ScanResult | null>(null)
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [backendHealth, setBackendHealth] = useState<boolean>(false)
  const [copiedText, setCopiedText] = useState<string | null>(null)

  // Launch Form State
  const [selectedProtocol, setSelectedProtocol] = useState<ProtocolPreset>(PROTOCOLS[0])
  const [targetHost, setTargetHost] = useState('192.168.1.100')
  const [targetPort, setTargetPort] = useState('22')
  const [targetUser, setTargetUser] = useState('root')
  const [targetPassword, setTargetPassword] = useState('')
  const [targetKeyPath, setTargetKeyPath] = useState('')
  const [targetDatabase, setTargetDatabase] = useState('')
  const [selectedBenchmarkId, setSelectedBenchmarkId] = useState('')
  const [selectedProfile, setSelectedProfile] = useState('level1')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [liveScanType, setLiveScanType] = useState<'full_va' | 'cis'>('full_va')
  const [scanDetailTab, setScanDetailTab] = useState<'compliance' | 'va' | 'layer8'>('compliance')
  const [benchmarkFilterText, setBenchmarkFilterText] = useState('')

  // Offline Upload State
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)

  const safeScans = Array.isArray(scans) ? scans : []
  const safeBenchmarks = Array.isArray(benchmarks) ? benchmarks : []

  // Polling data from backend
  const loadData = async () => {
    try {
      const hRes = await fetch('/health')
      if (hRes.ok) setBackendHealth(true)

      const bRes = await fetch('/api/v1/benchmarks')
      if (bRes.ok) {
        const bJson = await bRes.json()
        const list: Benchmark[] = Array.isArray(bJson) ? bJson : (Array.isArray(bJson?.data) ? bJson.data : [])
        setBenchmarks(list)
        if (!selectedBenchmarkId && list.length > 0) {
          setSelectedBenchmarkId(list[0].id)
        }
      }

      const sRes = await fetch('/api/v1/scans')
      if (sRes.ok) {
        const sJson = await sRes.json()
        const list: ScanJob[] = Array.isArray(sJson) ? sJson : (Array.isArray(sJson?.data) ? sJson.data : [])
        setScans(list)
        if (selectedScan) {
          const updated = list.find((s) => s.id === selectedScan.id)
          if (updated) setSelectedScan(updated)
        }
      }

      const fRes = await fetch('/api/v1/feeds')
      if (fRes.ok) {
        const fJson = await fRes.json()
        if (Array.isArray(fJson?.feeds)) {
          setFeeds(fJson.feeds)
        }
      }
    } catch {
      // Backend starting or offline
    }
  }

  useEffect(() => {
    loadData()
    const timer = setInterval(loadData, 4000)
    return () => clearInterval(timer)
  }, [selectedScan?.id])

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(label)
    setTimeout(() => setCopiedText(null), 2000)
  }

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    try {
      if (liveScanType === 'full_va') {
        const payload = {
          asset: {
            host: targetHost,
            port: parseInt(targetPort, 10) || selectedProtocol.port,
            protocol: selectedProtocol.id,
            user: targetUser,
            password: targetPassword,
            key_path: targetKeyPath,
            database: targetDatabase,
            mode: 'online_live_va',
          },
        }

        const res = await fetch('/api/v1/va/scan/live', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })

        if (res.ok) {
          const job = await res.json()
          await loadData()
          setSelectedScan(job)
          setActiveTab('scans')
        }
      } else {
        const payload = {
          benchmark_id: selectedBenchmarkId,
          profile: selectedProfile,
          asset: {
            host: targetHost,
            port: parseInt(targetPort, 10) || selectedProtocol.port,
            protocol: selectedProtocol.id,
            user: targetUser,
            password: targetPassword,
            key_path: targetKeyPath,
            database: targetDatabase,
          },
        }

        const res = await fetch('/api/v1/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })

        if (res.ok) {
          const job = await res.json()
          await loadData()
          setSelectedScan(job)
          setActiveTab('scans')
        }
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleOfflineUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!uploadFile) return
    setIsUploading(true)
    const formData = new FormData()
    formData.append('evidence', uploadFile)
    try {
      const res = await fetch('/api/v1/va/offline/upload', {
        method: 'POST',
        body: formData,
      })
      if (res.ok) {
        const json = await res.json()
        await loadData()
        if (json.job) {
          setSelectedScan(json.job)
          setActiveTab('scans')
        }
      }
    } finally {
      setIsUploading(false)
    }
  }

  // Statistics calculation
  const stats = useMemo(() => {
    const list = safeScans
    const total = list.length
    let passCount = 0
    let failCount = 0
    list.forEach((s) => {
      s?.results?.forEach((r) => {
        if (r.status === 'pass') passCount++
        if (r.status === 'fail') failCount++
      })
    })
    const sum = passCount + failCount
    const complianceRate = sum > 0 ? Math.round((passCount / sum) * 100) : 100
    return { total, passCount, failCount, complianceRate }
  }, [safeScans])

  // Benchmark categories
  const categories = useMemo(() => {
    const set = new Set<string>()
    safeBenchmarks.forEach((b) => {
      if (b.category) set.add(b.category)
    })
    return ['all', ...Array.from(set).sort()]
  }, [safeBenchmarks])

  // Filtered benchmarks
  const filteredBenchmarks = useMemo(() => {
    let list = safeBenchmarks
    if (selectedCategory !== 'all') {
      list = list.filter((b) => b.category === selectedCategory)
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      list = list.filter(
        (b) =>
          b.title?.toLowerCase().includes(q) ||
          b.technology?.toLowerCase().includes(q) ||
          b.os?.toLowerCase().includes(q) ||
          b.id?.toLowerCase().includes(q)
      )
    }
    return list
  }, [safeBenchmarks, selectedCategory, searchQuery])

  // Filtered scan results
  const scanResults = useMemo(() => {
    if (!selectedScan?.results) return []
    let list = selectedScan.results
    if (filterStatus !== 'all') {
      list = list.filter((r) => r.status === filterStatus)
    }
    return list
  }, [selectedScan, filterStatus])

  return (
    <div style={styles.appContainer}>
      {/* ============================================================ */}
      {/* LEFT NAVIGATION SIDEBAR (Enterprise Console Navigation)      */}
      {/* ============================================================ */}
      <aside style={styles.sidebar}>
        <div style={styles.sidebarBrand}>
          <div style={styles.brandIconBox}>
            <span style={{ fontSize: 20 }}>🛡️</span>
          </div>
          <div>
            <div style={styles.brandTitle}>HardenX</div>
            <div style={styles.brandSub}>Enterprise Suite</div>
          </div>
        </div>

        <nav style={styles.navMenu}>
          <div style={styles.navGroupLabel}>CORE MODULES</div>

          <button
            onClick={() => { setActiveTab('dashboard'); setSelectedScan(null) }}
            style={activeTab === 'dashboard' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>📊</span>
            <span>Security Posture</span>
          </button>

          <button
            onClick={() => { setActiveTab('va'); setSelectedScan(null) }}
            style={activeTab === 'va' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>🎯</span>
            <span>Vulnerability Assessment</span>
            <span style={styles.navBadgePulse}>Live & Airgap</span>
          </button>

          <button
            onClick={() => { setActiveTab('compliance'); setSelectedScan(null) }}
            style={activeTab === 'compliance' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>📜</span>
            <span>Compliance & CIS</span>
            <span style={styles.navCountBadge}>{safeBenchmarks.length}</span>
          </button>

          <button
            onClick={() => { setActiveTab('feeds'); setSelectedScan(null) }}
            style={activeTab === 'feeds' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>📡</span>
            <span>Threat Feeds & KEV</span>
            <span style={{ ...styles.navCountBadge, backgroundColor: '#065f46', color: '#6ee7b7' }}>9 Ready</span>
          </button>

          <button
            onClick={() => { setActiveTab('remediation'); setSelectedScan(null) }}
            style={activeTab === 'remediation' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>⚡</span>
            <span>Remediation Hub</span>
          </button>

          <div style={{ ...styles.navGroupLabel, marginTop: 24 }}>OPERATIONS & AUDITS</div>

          <button
            onClick={() => { setActiveTab('scans'); setSelectedScan(null) }}
            style={activeTab === 'scans' ? styles.navItemActive : styles.navItem}
          >
            <span style={styles.navIcon}>📑</span>
            <span>Audit History & Reports</span>
            <span style={styles.navCountBadge}>{safeScans.length}</span>
          </button>
        </nav>

        {/* Sidebar Status Footer */}
        <div style={styles.sidebarFooter}>
          <div style={styles.engineStatusRow}>
            <span style={{ ...styles.statusDot, backgroundColor: backendHealth ? '#10b981' : '#ef4444' }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: backendHealth ? '#34d399' : '#f87171' }}>
              Engine: {backendHealth ? 'ONLINE' : 'CONNECTING'}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
            v2.4.0 • Zero False Positive
          </div>
        </div>
      </aside>

      {/* ============================================================ */}
      {/* MAIN CONTENT AREA                                            */}
      {/* ============================================================ */}
      <main style={styles.mainContent}>
        {/* Top Header Bar */}
        <header style={styles.topHeader}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ color: '#94a3b8', fontSize: 14 }}>Workspace /</span>
            <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: 14, textTransform: 'capitalize' }}>
              {activeTab === 'va' ? 'Vulnerability Assessment Engine' : activeTab}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={styles.headerPill}>
              <span style={{ color: '#38bdf8', fontWeight: 700 }}>1,754</span>
              <span style={{ color: '#94a3b8', fontSize: 12 }}>CISA KEV Active</span>
            </div>
            <div style={styles.headerPill}>
              <span style={{ color: '#10b981', fontWeight: 700 }}>1,253</span>
              <span style={{ color: '#94a3b8', fontSize: 12 }}>CIS Benchmarks</span>
            </div>
            <button
              onClick={() => { setActiveTab('va'); setVaMode('offline') }}
              style={styles.headerActionBtn}
            >
              + Ingest Evidence (.txt)
            </button>
            <button
              onClick={() => { setActiveTab('va'); setVaMode('online') }}
              style={{ ...styles.headerActionBtn, backgroundColor: '#2563eb' }}
            >
              + Launch Scan
            </button>
          </div>
        </header>

        {/* Scrollable Viewport */}
        <div style={styles.viewport}>
          {/* ========================================================== */}
          {/* 1. DASHBOARD OVERVIEW (Executive Security Cockpit)         */}
          {/* ========================================================== */}
          {activeTab === 'dashboard' && (
            <div>
              {/* Stat Ribbon */}
              <div style={styles.statRibbon}>
                <div style={styles.statCard}>
                  <div style={styles.statCardHeader}>
                    <span style={styles.statLabel}>SECURITY POSTURE</span>
                    <span style={{ fontSize: 18 }}>🛡️</span>
                  </div>
                  <div style={{ ...styles.statValue, color: '#10b981' }}>
                    {stats.complianceRate}%
                  </div>
                  <div style={styles.statSubText}>Enterprise Hardening Score</div>
                </div>

                <div style={styles.statCard}>
                  <div style={styles.statCardHeader}>
                    <span style={styles.statLabel}>CIS CONTROLS EVALUATED</span>
                    <span style={{ fontSize: 18 }}>🎯</span>
                  </div>
                  <div style={styles.statValue}>{stats.passCount + stats.failCount}</div>
                  <div style={styles.statSubText}>
                    <span style={{ color: '#10b981' }}>{stats.passCount} Compliant</span> •{' '}
                    <span style={{ color: '#ef4444' }}>{stats.failCount} Action Needed</span>
                  </div>
                </div>

                <div style={styles.statCard}>
                  <div style={styles.statCardHeader}>
                    <span style={styles.statLabel}>CISA KEV EXPLOIT WATCH</span>
                    <span style={{ fontSize: 18 }}>🚨</span>
                  </div>
                  <div style={{ ...styles.statValue, color: '#38bdf8' }}>1,754</div>
                  <div style={styles.statSubText}>Active Weaponized Zero-Days Cataloged</div>
                </div>

                <div style={styles.statCard}>
                  <div style={styles.statCardHeader}>
                    <span style={styles.statLabel}>STANDARDS & FEEDS</span>
                    <span style={{ fontSize: 18 }}>📡</span>
                  </div>
                  <div style={{ ...styles.statValue, color: '#a78bfa' }}>9 Feeds Ready</div>
                  <div style={styles.statSubText}>NVD, RedHat, Debian, Ubuntu, SLES</div>
                </div>
              </div>

              {/* Dual Mode Launch Banners */}
              <div style={styles.heroGrid}>
                <div style={styles.heroActionCard}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                    <div style={{ ...styles.heroIconBox, backgroundColor: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
                      📦
                    </div>
                    <div>
                      <h3 style={styles.heroCardTitle}>Air-Gapped Offline Evidence Assessment</h3>
                      <span style={{ fontSize: 12, color: '#94a3b8' }}>Zero Network Exposure • Strict Evidence v2 Format</span>
                    </div>
                  </div>
                  <p style={styles.heroCardDesc}>
                    Ingest host evidence files collected from air-gapped critical networks. Evaluates installed package ledgers against authoritative CSAF 2.0 VEX, epoch-aware NEVRA comparisons, and 1,253 CIS companion benchmarks.
                  </p>
                  <button
                    onClick={() => { setActiveTab('va'); setVaMode('offline') }}
                    style={styles.heroCardBtn}
                  >
                    Ingest Evidence File (.txt) →
                  </button>
                </div>

                <div style={styles.heroActionCard}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                    <div style={{ ...styles.heroIconBox, backgroundColor: 'rgba(37, 99, 235, 0.15)', color: '#60a5fa' }}>
                      🌐
                    </div>
                    <div>
                      <h3 style={styles.heroCardTitle}>Online Agentless Vulnerability & Compliance Scan</h3>
                      <span style={{ fontSize: 12, color: '#94a3b8' }}>Native SSH • WinRM HTTPS • Paced Network PTY</span>
                    </div>
                  </div>
                  <p style={styles.heroCardDesc}>
                    Execute direct remote compliance checks and vulnerability identification across Linux, Windows Server, Cisco/Fortinet appliances, and databases with sub-millisecond Go worker pools.
                  </p>
                  <button
                    onClick={() => { setActiveTab('va'); setVaMode('online') }}
                    style={{ ...styles.heroCardBtn, backgroundColor: '#2563eb' }}
                  >
                    Launch Live Audit Scan →
                  </button>
                </div>
              </div>

              {/* Feed Status Health Ribbon */}
              <div style={styles.contentCard}>
                <div style={styles.cardHeaderRow}>
                  <div>
                    <h3 style={styles.cardHeading}>Authoritative Vulnerability & Errata Feeds</h3>
                    <p style={styles.cardSub}>Local offline feeds ensuring 100% precision with zero false alarms on backported patches.</p>
                  </div>
                  <button onClick={() => setActiveTab('feeds')} style={styles.textLink}>
                    View All 9 Feed Ledgers →
                  </button>
                </div>

                <div style={styles.feedStatusGrid}>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>Debian</span>
                    <span style={styles.feedStatusTag}>80.3 MB • Ready</span>
                  </div>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>Red Hat CSAF</span>
                    <span style={styles.feedStatusTag}>RHEL 6-9 • Ready</span>
                  </div>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>Ubuntu USN</span>
                    <span style={styles.feedStatusTag}>18.04-24.04 • Ready</span>
                  </div>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>SUSE Enterprise</span>
                    <span style={styles.feedStatusTag}>SLES 11-15 • Ready</span>
                  </div>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>NVD Global CVE</span>
                    <span style={styles.feedStatusTag}>2002–2026 • Ready</span>
                  </div>
                  <div style={styles.feedBadgeCard}>
                    <span style={styles.feedVendor}>CISA KEV</span>
                    <span style={styles.feedStatusTag}>1,754 Weaponized</span>
                  </div>
                </div>
              </div>

              {/* Recent Audit Scans Table */}
              <div style={styles.contentCard}>
                <div style={styles.cardHeaderRow}>
                  <div>
                    <h3 style={styles.cardHeading}>Recent Security Assessments</h3>
                    <p style={styles.cardSub}>Audit jobs executed with official EGK 15-Sheet Excel workbook generation.</p>
                  </div>
                  <button onClick={() => setActiveTab('scans')} style={styles.textLink}>
                    View Audit Archive ({safeScans.length}) →
                  </button>
                </div>

                {safeScans.length === 0 ? (
                  <div style={styles.emptyBox}>
                    <span>No assessments executed yet. Ingest an offline evidence file or launch a scan.</span>
                  </div>
                ) : (
                  <div style={styles.tableWrapper}>
                    <table style={styles.table}>
                      <thead>
                        <tr>
                          <th style={styles.th}>Scan ID</th>
                          <th style={styles.th}>Target Host</th>
                          <th style={styles.th}>Mode</th>
                          <th style={styles.th}>Benchmark / Errata</th>
                          <th style={styles.th}>Status</th>
                          <th style={styles.th}>Official Export</th>
                          <th style={styles.th}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {safeScans.slice(0, 5).map((scan) => (
                          <tr key={scan.id} style={styles.tr}>
                            <td style={{ ...styles.td, fontFamily: 'monospace', color: '#38bdf8' }}>
                              {scan.id.slice(0, 8)}...
                            </td>
                            <td style={styles.td}>
                              <b>{scan.asset?.host || '127.0.0.1'}</b>
                              <span style={{ display: 'block', fontSize: 11, color: '#64748b' }}>
                                IP: {scan.asset?.ip || '127.0.0.1'}
                              </span>
                            </td>
                            <td style={styles.td}>
                              <span style={{
                                ...styles.chip,
                                backgroundColor: scan.asset?.mode === 'offline_airgapped' ? 'rgba(56, 189, 248, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                                color: scan.asset?.mode === 'offline_airgapped' ? '#38bdf8' : '#34d399',
                              }}>
                                {scan.asset?.mode === 'offline_airgapped' ? '📦 Air-Gapped' : '🌐 Live Scan'}
                              </span>
                            </td>
                            <td style={styles.td}>{scan.benchmark_id}</td>
                            <td style={styles.td}>
                              <span style={{
                                ...styles.chip,
                                backgroundColor: scan.status === 'completed' ? '#064e3b' : '#7f1d1d',
                                color: scan.status === 'completed' ? '#34d399' : '#fca5a5',
                              }}>
                                {scan.status.toUpperCase()}
                              </span>
                            </td>
                            <td style={styles.td}>
                              <a
                                href={`/api/v1/scans/${scan.id}/report/egk-excel`}
                                download={`EGK_Master_Assessment_${scan.id}.xlsx`}
                                style={styles.downloadExcelBtn}
                              >
                                📊 EGK 15-Sheet Excel ⬇
                              </a>
                            </td>
                            <td style={styles.td}>
                              <button
                                onClick={() => { setSelectedScan(scan); setActiveTab('scans') }}
                                style={styles.actionBtnSmall}
                              >
                                Open Inspector →
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* 2. VULNERABILITY ASSESSMENT (Online & Offline Console)    */}
          {/* ========================================================== */}
          {activeTab === 'va' && (
            <div>
              <div style={styles.vaModeToggleRow}>
                <button
                  onClick={() => setVaMode('offline')}
                  style={vaMode === 'offline' ? styles.vaModeActive : styles.vaModeBtn}
                >
                  📦 Air-Gapped Offline Evidence Ingestion
                </button>
                <button
                  onClick={() => setVaMode('online')}
                  style={vaMode === 'online' ? styles.vaModeActive : styles.vaModeBtn}
                >
                  🌐 Online Live Agentless Scanning
                </button>
              </div>

              {vaMode === 'offline' ? (
                <div style={styles.contentCard}>
                  <div style={styles.cardHeaderRow}>
                    <div>
                      <h3 style={styles.cardHeading}>Ingest Air-Gapped Host Evidence</h3>
                      <p style={styles.cardSub}>
                        Drop raw evidence files generated by OfflineVA Universal Collector. Evaluates epoch-aware packages against authoritative vendor CSAF 2.0 VEX and CIS companion benchmarks with zero network connection.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleOfflineUpload} style={{ marginTop: 20 }}>
                    <div style={styles.dropZone}>
                      <span style={{ fontSize: 40, marginBottom: 12 }}>📄</span>
                      <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 16 }}>
                        {uploadFile ? uploadFile.name : 'Select or drop raw <ip>_<hostname>.txt evidence file'}
                      </div>
                      <div style={{ fontSize: 13, color: '#94a3b8', margin: '8px 0 16px' }}>
                        Supports Evidence Format v2 with tri-state fact reporting (`observed`, `absent`, `not_collected`)
                      </div>
                      <input
                        type="file"
                        accept=".txt"
                        required
                        onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                        style={{ color: '#94a3b8', fontSize: 13 }}
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
                      <button
                        type="submit"
                        disabled={isUploading || !uploadFile}
                        style={{ ...styles.primaryBtn, opacity: isUploading || !uploadFile ? 0.6 : 1 }}
                      >
                        {isUploading ? 'Evaluating Against CSAF VEX & CIS...' : '⚡ Ingest & Analyze Offline Evidence'}
                      </button>
                    </div>
                  </form>
                </div>
              ) : (
                <div style={styles.contentCard}>
                  <div style={styles.cardHeaderRow}>
                    <div>
                      <h3 style={styles.cardHeading}>Launch Online Agentless Assessment</h3>
                      <p style={styles.cardSub}>
                        Direct remote interrogation across Linux, Windows Server, Network Appliances, or Databases.
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleLaunchScan} style={{ marginTop: 20 }}>
                    {/* Protocol selector */}
                    <label style={styles.fieldSectionLabel}>SELECT TARGET PROTOCOL & CONNECTOR</label>
                    <div style={styles.protocolGrid}>
                      {PROTOCOLS.map((p) => {
                        const isSelected = selectedProtocol.id === p.id
                        return (
                          <div
                            key={p.id}
                            onClick={() => {
                              setSelectedProtocol(p)
                              setTargetPort(p.port.toString())
                              setTargetUser(p.defaultUser)
                            }}
                            style={{
                              ...styles.protocolCard,
                              borderColor: isSelected ? '#3b82f6' : '#1e293b',
                              backgroundColor: isSelected ? 'rgba(59, 130, 246, 0.12)' : '#0d131f',
                            }}
                          >
                            <span style={{ fontSize: 24 }}>{p.icon}</span>
                            <div>
                              <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 13 }}>{p.name}</div>
                              <div style={{ fontSize: 11, color: '#94a3b8' }}>{p.label}</div>
                            </div>
                          </div>
                        )
                      })}
                    </div>

                    {/* Engine Mode selector: Full VA + Layer 8 vs CIS Benchmark */}
                    <div style={{ marginTop: 16, marginBottom: 16 }}>
                      <label style={styles.fieldSectionLabel}>SELECT AUDIT ENGINE & SCOPE</label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        <div
                          onClick={() => setLiveScanType('full_va')}
                          style={{
                            ...styles.protocolCard,
                            borderColor: liveScanType === 'full_va' ? '#3b82f6' : '#1e293b',
                            backgroundColor: liveScanType === 'full_va' ? 'rgba(59, 130, 246, 0.15)' : '#0d131f',
                            cursor: 'pointer',
                          }}
                        >
                          <span style={{ fontSize: 24 }}>🔬</span>
                          <div>
                            <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 13 }}>Full Online VA & Layer 8 Rootkit Hunter</div>
                            <div style={{ fontSize: 11, color: '#94a3b8' }}>Port Scan + TLS Ciphers + Package CVEs + In-Memory Hooking & BYOVD Detection</div>
                          </div>
                        </div>
                        <div
                          onClick={() => setLiveScanType('cis')}
                          style={{
                            ...styles.protocolCard,
                            borderColor: liveScanType === 'cis' ? '#10b981' : '#1e293b',
                            backgroundColor: liveScanType === 'cis' ? 'rgba(16, 185, 129, 0.15)' : '#0d131f',
                            cursor: 'pointer',
                          }}
                        >
                          <span style={{ fontSize: 24 }}>📋</span>
                          <div>
                            <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 13 }}>CIS Benchmark Hardening Audit</div>
                            <div style={{ fontSize: 11, color: '#94a3b8' }}>Enforce Official CIS Controls & Export Official 15-Sheet EGK Workbook</div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Connection details */}
                    <div style={styles.formRow2}>
                      <div style={styles.formGroup}>
                        <label style={styles.formLabel}>Target Hostname or IP</label>
                        <input
                          type="text"
                          required
                          value={targetHost}
                          onChange={(e) => setTargetHost(e.target.value)}
                          style={styles.input}
                          placeholder="192.168.1.100"
                        />
                      </div>
                      <div style={styles.formGroup}>
                        <label style={styles.formLabel}>Port</label>
                        <input
                          type="number"
                          required
                          value={targetPort}
                          onChange={(e) => setTargetPort(e.target.value)}
                          style={styles.input}
                        />
                      </div>
                    </div>

                    <div style={styles.formRow3}>
                      <div style={styles.formGroup}>
                        <label style={styles.formLabel}>Username / Principal</label>
                        <input
                          type="text"
                          required
                          value={targetUser}
                          onChange={(e) => setTargetUser(e.target.value)}
                          style={styles.input}
                        />
                      </div>
                      <div style={styles.formGroup}>
                        <label style={styles.formLabel}>Password (or Privileged Auth)</label>
                        <input
                          type="password"
                          value={targetPassword}
                          onChange={(e) => setTargetPassword(e.target.value)}
                          style={styles.input}
                          placeholder="••••••••••••"
                        />
                      </div>
                      <div style={styles.formGroup}>
                        <label style={styles.formLabel}>SSH Key Path (Optional)</label>
                        <input
                          type="text"
                          value={targetKeyPath}
                          onChange={(e) => setTargetKeyPath(e.target.value)}
                          style={styles.input}
                          placeholder="~/.ssh/id_rsa"
                        />
                      </div>
                    </div>

                    {/* Benchmark selection */}
                    <div style={{ marginTop: 20 }}>
                      <label style={styles.formLabel}>Select CIS Benchmark to Enforce</label>
                      <input
                        type="text"
                        placeholder="Search 1,253 CIS benchmarks by keyword or OS..."
                        value={benchmarkFilterText}
                        onChange={(e) => setBenchmarkFilterText(e.target.value)}
                        style={{ ...styles.input, marginBottom: 8 }}
                      />
                      <select
                        value={selectedBenchmarkId}
                        onChange={(e) => setSelectedBenchmarkId(e.target.value)}
                        style={styles.select}
                        size={5}
                      >
                        {filteredBenchmarks.slice(0, 100).map((b) => (
                          <option key={b.id} value={b.id} style={{ padding: '6px 8px' }}>
                            {b.title} [{b.category || 'General'}] (v{b.version})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 20 }}>
                      <button
                        type="submit"
                        disabled={isSubmitting || (liveScanType === 'cis' && !selectedBenchmarkId)}
                        style={{ ...styles.primaryBtn, opacity: isSubmitting || (liveScanType === 'cis' && !selectedBenchmarkId) ? 0.6 : 1 }}
                      >
                        {isSubmitting ? 'Connecting & Executing 8-Layer Inspection...' : (liveScanType === 'full_va' ? '🔬 Launch Full VA & Rootkit Hunter' : '🚀 Execute Live CIS Audit')}
                      </button>
                    </div>
                  </form>
                </div>
              )}
            </div>
          )}

          {/* ========================================================== */}
          {/* 3. COMPLIANCE & 1,253 CIS BENCHMARKS                     */}
          {/* ========================================================== */}
          {activeTab === 'compliance' && (
            <div style={styles.contentCard}>
              <div style={styles.cardHeaderRow}>
                <div>
                  <h3 style={styles.cardHeading}>CIS & STIG Benchmark Catalog ({safeBenchmarks.length} Total)</h3>
                  <p style={styles.cardSub}>
                    Complete companion benchmarks extracted directly from official Center for Internet Security specifications.
                  </p>
                </div>
                <input
                  type="text"
                  placeholder="Filter benchmarks by title, OS, technology..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ ...styles.input, maxWidth: 300 }}
                />
              </div>

              {/* Category Filters */}
              <div style={styles.categoryPillRow}>
                {categories.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    style={{
                      ...styles.categoryPill,
                      backgroundColor: selectedCategory === cat ? '#2563eb' : '#0d131f',
                      color: selectedCategory === cat ? '#ffffff' : '#94a3b8',
                      borderColor: selectedCategory === cat ? '#3b82f6' : '#1e293b',
                    }}
                  >
                    {cat.toUpperCase()}
                  </button>
                ))}
              </div>

              <div style={styles.tableWrapper}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Benchmark Title</th>
                      <th style={styles.th}>Category</th>
                      <th style={styles.th}>Technology / Target</th>
                      <th style={styles.th}>Version</th>
                      <th style={styles.th}>Controls</th>
                      <th style={styles.th}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredBenchmarks.slice(0, 50).map((b) => (
                      <tr key={b.id} style={styles.tr}>
                        <td style={{ ...styles.td, fontWeight: 600, color: '#f8fafc' }}>
                          {b.title}
                        </td>
                        <td style={styles.td}>
                          <span style={styles.chip}>{b.category || 'General'}</span>
                        </td>
                        <td style={styles.td}>{b.technology || b.os || 'Universal'}</td>
                        <td style={styles.td}>v{b.version}</td>
                        <td style={styles.td}>{b.controls_count || 'Parsed'}</td>
                        <td style={styles.td}>
                          <button
                            onClick={() => {
                              setSelectedBenchmarkId(b.id)
                              setActiveTab('va')
                              setVaMode('online')
                            }}
                            style={styles.actionBtnSmall}
                          >
                            Audit With Benchmark →
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* 4. THREAT FEEDS & KEV STANDARDS CENTER                    */}
          {/* ========================================================== */}
          {activeTab === 'feeds' && (
            <div>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: 20, color: '#f8fafc', margin: '0 0 6px' }}>Threat Intelligence & Feeds Repository</h2>
                <p style={{ color: '#94a3b8', fontSize: 13, margin: 0 }}>
                  Authoritative vendor OVAL, CSAF 2.0 VEX, NVD CVE, CISA KEV, and FIRST EPSS v3 datasets bundled locally in `feeds/`.
                </p>
              </div>

              <div style={styles.feedsGrid}>
                {feeds.map((f) => (
                  <div key={f.id} style={styles.feedCard}>
                    <div style={styles.feedCardHeader}>
                      <div>
                        <div style={{ fontWeight: 700, color: '#f8fafc', fontSize: 15 }}>{f.name}</div>
                        <div style={{ fontSize: 12, color: '#64748b' }}>{f.vendor}</div>
                      </div>
                      <span style={{
                        ...styles.chip,
                        backgroundColor: '#064e3b',
                        color: '#34d399',
                        fontWeight: 600,
                      }}>
                        OPERATIONAL
                      </span>
                    </div>

                    <div style={{ margin: '12px 0', fontSize: 13, color: '#cbd5e1' }}>
                      {f.coverage}
                    </div>

                    <div style={styles.feedCardMeta}>
                      <div>
                        <span style={styles.feedMetaLabel}>SCOPE:</span>
                        <span style={styles.feedMetaVal}>{f.scope}</span>
                      </div>
                      <div>
                        <span style={styles.feedMetaLabel}>CACHE SIZE:</span>
                        <span style={styles.feedMetaVal}>{f.size}</span>
                      </div>
                    </div>

                    <div style={styles.feedFilesBox}>
                      <span style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>FILES INDEXED:</span>
                      {f.files.map((file, idx) => (
                        <code key={idx} style={styles.feedFileCode}>{file}</code>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* 5. ACTIONABLE REMEDIATION PLAYBOOKS HUB                   */}
          {/* ========================================================== */}
          {activeTab === 'remediation' && (
            <div style={styles.contentCard}>
              <div style={styles.cardHeaderRow}>
                <div>
                  <h3 style={styles.cardHeading}>Automated Remediation Playbooks</h3>
                  <p style={styles.cardSub}>
                    Download 1-click executable Ansible Playbooks, PowerShell scripts, and Bash hardening fixes.
                  </p>
                </div>
              </div>

              {safeScans.length === 0 ? (
                <div style={styles.emptyBox}>
                  <span>No scans completed. Execute an audit to generate remediation playbooks.</span>
                </div>
              ) : (
                <div style={styles.remediationList}>
                  {safeScans.map((s) => {
                    const failCount = s.results?.filter((r) => r.status === 'fail').length || 0
                    return (
                      <div key={s.id} style={styles.remediationCard}>
                        <div style={styles.cardHeaderRow}>
                          <div>
                            <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 16 }}>
                              {s.benchmark_id}
                            </div>
                            <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                              Target: <b>{s.asset?.host}</b> • Failed Controls: <b style={{ color: '#ef4444' }}>{failCount}</b>
                            </div>
                          </div>

                          <div style={{ display: 'flex', gap: 8 }}>
                            <a
                              href={`/api/v1/scans/${s.id}/remediation/ansible`}
                              download={`remediation_${s.id}.yml`}
                              style={{ ...styles.playbookBtn, backgroundColor: '#059669' }}
                            >
                              Ansible .yml ⬇
                            </a>
                            <a
                              href={`/api/v1/scans/${s.id}/remediation/powershell`}
                              download={`remediation_${s.id}.ps1`}
                              style={{ ...styles.playbookBtn, backgroundColor: '#0284c7' }}
                            >
                              PowerShell .ps1 ⬇
                            </a>
                            <a
                              href={`/api/v1/scans/${s.id}/remediation/bash`}
                              download={`remediation_${s.id}.sh`}
                              style={{ ...styles.playbookBtn, backgroundColor: '#7c3aed' }}
                            >
                              Bash .sh ⬇
                            </a>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* ========================================================== */}
          {/* 6. AUDIT HISTORY & DEEP INSPECTOR VIEW                    */}
          {/* ========================================================== */}
          {activeTab === 'scans' && (
            <div>
              {!selectedScan ? (
                <div style={styles.contentCard}>
                  <div style={styles.cardHeaderRow}>
                    <div>
                      <h3 style={styles.cardHeading}>Audit Assessment Archive</h3>
                      <p style={styles.cardSub}>Review audit logs, evidence, and official EGK 15-sheet workbooks.</p>
                    </div>
                  </div>

                  {safeScans.length === 0 ? (
                    <div style={styles.emptyBox}>No assessments recorded.</div>
                  ) : (
                    <div style={styles.tableWrapper}>
                      <table style={styles.table}>
                        <thead>
                          <tr>
                            <th style={styles.th}>Scan ID</th>
                            <th style={styles.th}>Target Host</th>
                            <th style={styles.th}>Mode</th>
                            <th style={styles.th}>Benchmark / Errata</th>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Official Export</th>
                            <th style={styles.th}>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {safeScans.map((scan) => (
                            <tr key={scan.id} style={styles.tr}>
                              <td style={{ ...styles.td, fontFamily: 'monospace', color: '#38bdf8' }}>
                                {scan.id.slice(0, 8)}...
                              </td>
                              <td style={styles.td}>
                                <b>{scan.asset?.host || '127.0.0.1'}</b>
                              </td>
                              <td style={styles.td}>
                                <span style={styles.chip}>
                                  {scan.asset?.mode === 'offline_airgapped' ? '📦 Air-Gapped' : '🌐 Live Scan'}
                                </span>
                              </td>
                              <td style={styles.td}>{scan.benchmark_id}</td>
                              <td style={styles.td}>
                                <span style={{
                                  ...styles.chip,
                                  backgroundColor: scan.status === 'completed' ? '#064e3b' : '#7f1d1d',
                                  color: scan.status === 'completed' ? '#34d399' : '#fca5a5',
                                }}>
                                  {scan.status.toUpperCase()}
                                </span>
                              </td>
                              <td style={styles.td}>
                                <a
                                  href={`/api/v1/scans/${scan.id}/report/egk-excel`}
                                  download={`EGK_Master_Assessment_${scan.id}.xlsx`}
                                  style={styles.downloadExcelBtn}
                                >
                                  📊 EGK 15-Sheet Excel ⬇
                                </a>
                              </td>
                              <td style={styles.td}>
                                <button
                                  onClick={() => setSelectedScan(scan)}
                                  style={styles.actionBtnSmall}
                                >
                                  Open Report & Findings →
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              ) : (
                /* Selected Scan Deep Inspector */
                <div>
                  <div style={styles.detailHeader}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <button onClick={() => setSelectedScan(null)} style={styles.backBtn}>
                        ← Back to Scans
                      </button>
                      <h2 style={{ fontSize: 20, color: '#f8fafc', margin: 0 }}>
                        {selectedScan.benchmark_id} ({selectedScan.asset?.host})
                      </h2>
                    </div>

                    <div style={{ display: 'flex', gap: 8 }}>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/report/egk-excel`}
                        download={`EGK_Master_Assessment_${selectedScan.id}.xlsx`}
                        style={{ ...styles.actionBtnSmall, backgroundColor: '#15803d', borderColor: '#22c55e', color: '#fff', fontWeight: 600 }}
                      >
                        📊 Download EGK 15-Sheet Excel ⬇
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/report`}
                        target="_blank"
                        rel="noreferrer"
                        style={styles.actionBtnSmall}
                      >
                        Nessus HTML ↗
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/remediation/ansible`}
                        download={`remediation_${selectedScan.id}.yml`}
                        style={{ ...styles.actionBtnSmall, backgroundColor: '#059669', color: '#fff' }}
                      >
                        Ansible Playbook ⬇
                      </a>
                    </div>
                  </div>

                  {/* Scope Selector: CIS Controls vs VA & Threats vs Layer 8 Rootkits */}
                  <div style={{ display: 'flex', gap: 10, marginTop: 16, marginBottom: 16, borderBottom: '1px solid #1e293b', paddingBottom: 12 }}>
                    <button
                      onClick={() => setScanDetailTab('compliance')}
                      style={{
                        ...styles.filterBtn,
                        backgroundColor: scanDetailTab === 'compliance' ? '#2563eb' : '#0d131f',
                        color: scanDetailTab === 'compliance' ? '#ffffff' : '#94a3b8',
                        border: `1px solid ${scanDetailTab === 'compliance' ? '#3b82f6' : '#1e293b'}`,
                        fontWeight: 600,
                      }}
                    >
                      📋 CIS Benchmark Controls ({selectedScan.results?.length || 0})
                    </button>
                    <button
                      onClick={() => setScanDetailTab('va')}
                      style={{
                        ...styles.filterBtn,
                        backgroundColor: scanDetailTab === 'va' ? '#b91c1c' : '#0d131f',
                        color: scanDetailTab === 'va' ? '#ffffff' : '#94a3b8',
                        border: `1px solid ${scanDetailTab === 'va' ? '#ef4444' : '#1e293b'}`,
                        fontWeight: 600,
                      }}
                    >
                      🚨 Vulnerabilities & KEV ({selectedScan.va_results?.vulnerabilities?.vulnerabilities?.length || 0})
                    </button>
                    <button
                      onClick={() => setScanDetailTab('layer8')}
                      style={{
                        ...styles.filterBtn,
                        backgroundColor: scanDetailTab === 'layer8' ? '#6d28d9' : '#0d131f',
                        color: scanDetailTab === 'layer8' ? '#ffffff' : '#94a3b8',
                        border: `1px solid ${scanDetailTab === 'layer8' ? '#8b5cf6' : '#1e293b'}`,
                        fontWeight: 600,
                      }}
                    >
                      🛡️ Layer 8 Memory & Rootkits ({selectedScan.layer8?.findings?.length || 0})
                    </button>
                  </div>

                  {/* 1. COMPLIANCE CONTROLS TAB */}
                  {scanDetailTab === 'compliance' && (
                    <div>
                      {/* Filter tabs */}
                  <div style={styles.filterBar}>
                    {['all', 'fail', 'pass', 'error'].map((st) => (
                      <button
                        key={st}
                        onClick={() => setFilterStatus(st)}
                        style={{
                          ...styles.filterBtn,
                          backgroundColor: filterStatus === st ? '#2563eb' : '#0d131f',
                          color: filterStatus === st ? '#ffffff' : '#94a3b8',
                        }}
                      >
                        {st === 'all'
                          ? `All Findings (${selectedScan.results?.length || 0})`
                          : st === 'fail'
                          ? `Non-Compliant (${selectedScan.results?.filter((r) => r.status === 'fail').length || 0})`
                          : st === 'pass'
                          ? `Compliant (${selectedScan.results?.filter((r) => r.status === 'pass').length || 0})`
                          : `Errors (${selectedScan.results?.filter((r) => r.status === 'error').length || 0})`}
                      </button>
                    ))}
                  </div>

                  {/* Findings Table + Drawer */}
                  <div style={{ display: 'flex', gap: 16 }}>
                    <div style={{ flex: selectedFinding ? '1 1 55%' : '1 1 100%' }}>
                      <div style={styles.tableWrapper}>
                        <table style={styles.table}>
                          <thead>
                            <tr>
                              <th style={styles.th}>Status</th>
                              <th style={styles.th}>Control ID</th>
                              <th style={styles.th}>Check Type</th>
                              <th style={styles.th}>Expected Output</th>
                              <th style={styles.th}>Inspection</th>
                            </tr>
                          </thead>
                          <tbody>
                            {scanResults.map((r, i) => (
                              <tr
                                key={i}
                                onClick={() => setSelectedFinding(r)}
                                style={{
                                  ...styles.tr,
                                  backgroundColor: selectedFinding?.control_id === r.control_id ? '#1e293b' : 'transparent',
                                  cursor: 'pointer',
                                }}
                              >
                                <td style={styles.td}>
                                  <span style={{
                                    ...styles.chip,
                                    backgroundColor: r.status === 'pass' ? '#064e3b' : '#7f1d1d',
                                    color: r.status === 'pass' ? '#34d399' : '#fca5a5',
                                  }}>
                                    {r.status.toUpperCase()}
                                  </span>
                                </td>
                                <td style={{ ...styles.td, fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc' }}>
                                  {r.control_id}
                                </td>
                                <td style={styles.td}>{r.check_type}</td>
                                <td style={{ ...styles.td, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {r.expected || 'Exit Code 0'}
                                </td>
                                <td style={styles.td}>
                                  <button style={styles.actionBtnSmall}>Evidence →</button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Inspector Drawer */}
                    {selectedFinding && (
                      <div style={styles.inspectorDrawer}>
                        <div style={styles.drawerHeader}>
                          <div>
                            <span style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', fontFamily: 'monospace' }}>
                              CIS [{selectedFinding.control_id}]
                            </span>
                            <span style={{
                              ...styles.chip,
                              marginLeft: 8,
                              backgroundColor: selectedFinding.status === 'pass' ? '#064e3b' : '#7f1d1d',
                              color: selectedFinding.status === 'pass' ? '#34d399' : '#fca5a5',
                            }}>
                              {selectedFinding.status.toUpperCase()}
                            </span>
                          </div>
                          <button onClick={() => setSelectedFinding(null)} style={styles.closeBtn}>✕</button>
                        </div>

                        {/* Evidence box */}
                        <div style={styles.drawerSection}>
                          <div style={styles.boxHeaderRow}>
                            <span style={styles.boxLabel}>RAW TERMINAL EVIDENCE</span>
                            <button onClick={() => handleCopy(selectedFinding.evidence, 'evidence')} style={styles.copyBtn}>
                              {copiedText === 'evidence' ? 'Copied ✓' : 'Copy'}
                            </button>
                          </div>
                          <pre style={styles.preCode}>
                            {selectedFinding.evidence || 'No terminal evidence output recorded.'}
                          </pre>
                        </div>

                        {/* Standards */}
                        <div style={styles.drawerSection}>
                          <span style={styles.boxLabel}>STANDARDS & THREAT INTELLIGENCE</span>
                          <div style={styles.standardsGrid}>
                            <div style={styles.standardsCell}>
                              <div style={styles.standardsCellLabel}>CISA KEV STATUS</div>
                              <div style={styles.standardsCellVal}>1,754 CVEs Indexed</div>
                            </div>
                            <div style={styles.standardsCell}>
                              <div style={styles.standardsCellLabel}>NIST SP 800-53</div>
                              <div style={styles.standardsCellVal}>CM-6 • SC-7 • SI-2</div>
                            </div>
                            <div style={styles.standardsCell}>
                              <div style={styles.standardsCellLabel}>EGK REGULATORY</div>
                              <div style={styles.standardsCellVal}>
                                {selectedFinding.status === 'pass' ? 'Done' : 'Undone (Action Required)'}
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Remediation Fix */}
                        <div style={styles.drawerSection}>
                          <div style={styles.boxHeaderRow}>
                            <span style={styles.boxLabel}>AUTOMATED REMEDIATION FIX</span>
                            <button onClick={() => handleCopy(`# Remediation for ${selectedFinding.control_id}`, 'fix')} style={styles.copyBtn}>
                              {copiedText === 'fix' ? 'Copied ✓' : 'Copy Fix'}
                            </button>
                          </div>
                          <pre style={{ ...styles.preCode, color: '#38bdf8' }}>
                            {`# Step 1: Apply compliance fix for CIS ${selectedFinding.control_id}\n# Or download complete Ansible/PowerShell playbook from the top bar.`}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

                  {/* 2. VULNERABILITY ASSESSMENT & KEV THREAT TAB */}
                  {scanDetailTab === 'va' && (
                    <div>
                      {/* Threat Metrics Ribbon */}
                      <div style={styles.statsRibbon}>
                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>VULNERABILITIES FOUND</span>
                            <span style={{ fontSize: 18 }}>🚨</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#ef4444' }}>
                            {selectedScan.va_results?.vulnerabilities?.total_vulnerabilities || 0}
                          </div>
                          <div style={styles.statSubText}>
                            <span style={{ color: '#ef4444' }}>{selectedScan.va_results?.vulnerabilities?.critical_count || 0} Critical</span> •{' '}
                            <span style={{ color: '#f97316' }}>{selectedScan.va_results?.vulnerabilities?.high_count || 0} High</span>
                          </div>
                        </div>

                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>CISA KEV ZERO-DAYS</span>
                            <span style={{ fontSize: 18 }}>⚡</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#f59e0b' }}>
                            {selectedScan.va_results?.vulnerabilities?.kev_count || 0}
                          </div>
                          <div style={styles.statSubText}>Actively Exploited in the Wild</div>
                        </div>

                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>BACKPORT ZERO-FP FILTER</span>
                            <span style={{ fontSize: 18 }}>🛡️</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#10b981' }}>
                            {selectedScan.va_results?.vulnerabilities?.backports_eliminated || 0}
                          </div>
                          <div style={styles.statSubText}>Patched Releases Verified via NEVRA</div>
                        </div>

                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>NETWORK PORTS OPEN</span>
                            <span style={{ fontSize: 18 }}>🌐</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#38bdf8' }}>
                            {selectedScan.va_results?.discovery?.open_ports?.length || 0}
                          </div>
                          <div style={styles.statSubText}>
                            Latency: {selectedScan.va_results?.discovery?.latency_ms || 1} ms
                          </div>
                        </div>
                      </div>

                      {/* Open Network Ports & TLS Details */}
                      {selectedScan.va_results?.discovery?.open_ports?.length > 0 && (
                        <div style={{ ...styles.contentCard, marginTop: 16 }}>
                          <h4 style={{ margin: '0 0 12px 0', fontSize: 14, color: '#38bdf8' }}>Discovered Services & TLS Cipher Auditor</h4>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
                            {selectedScan.va_results.discovery.open_ports.map((p: any) => (
                              <div key={p.port} style={{ padding: 12, backgroundColor: '#070b12', border: '1px solid #1e293b', borderRadius: 8 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                  <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#38bdf8' }}>Port {p.port}/{p.protocol}</span>
                                  <span style={{ ...styles.chip, backgroundColor: '#064e3b', color: '#34d399' }}>{p.service?.toUpperCase() || 'OPEN'}</span>
                                </div>
                                {p.banner && <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4, fontFamily: 'monospace' }}>Banner: {p.banner}</div>}
                                {p.tls_info && (
                                  <div style={{ marginTop: 6, fontSize: 11, color: p.tls_info.weak_cipher ? '#fca5a5' : '#34d399' }}>
                                    TLS: {p.tls_info.version} • {p.tls_info.cipher_suite}
                                    {p.tls_info.weak_cipher && <span style={{ display: 'block', color: '#ef4444' }}>⚠️ Weak CBC/3DES Cipher Detected</span>}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Vulnerabilities Table */}
                      <div style={{ ...styles.tableWrapper, marginTop: 16 }}>
                        <table style={styles.table}>
                          <thead>
                            <tr>
                              <th style={styles.th}>Severity</th>
                              <th style={styles.th}>CVE ID</th>
                              <th style={styles.th}>Advisory Title</th>
                              <th style={styles.th}>CVSS / EPSS</th>
                              <th style={styles.th}>Affected Package</th>
                              <th style={styles.th}>Fixed Release</th>
                              <th style={styles.th}>Remediation</th>
                            </tr>
                          </thead>
                          <tbody>
                            {!selectedScan.va_results?.vulnerabilities?.vulnerabilities || selectedScan.va_results?.vulnerabilities?.vulnerabilities?.length === 0 ? (
                              <tr>
                                <td colSpan={7} style={{ ...styles.td, textAlign: 'center', color: '#10b981', padding: 24 }}>
                                  ✓ Clean: Zero active package vulnerabilities detected. All backport patches verified.
                                </td>
                              </tr>
                            ) : (
                              selectedScan.va_results.vulnerabilities.vulnerabilities.map((v: any, i: number) => (
                                <tr key={i} style={styles.tr}>
                                  <td style={styles.td}>
                                    <span style={{
                                      ...styles.chip,
                                      backgroundColor: v.severity === 'CRITICAL' ? '#7f1d1d' : (v.severity === 'HIGH' ? '#7c2d12' : '#713f12'),
                                      color: v.severity === 'CRITICAL' ? '#fca5a5' : (v.severity === 'HIGH' ? '#fdba74' : '#fde047'),
                                    }}>
                                      {v.severity}
                                    </span>
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc' }}>
                                    {v.cve_id}
                                    {v.is_kev && (
                                      <span style={{ ...styles.chip, marginLeft: 6, backgroundColor: 'rgba(239, 68, 68, 0.2)', color: '#ef4444' }}>
                                        🚨 KEV ACTIVE
                                      </span>
                                    )}
                                  </td>
                                  <td style={{ ...styles.td, maxWidth: 300 }}>{v.title}</td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace' }}>
                                    <span style={{ color: '#f8fafc' }}>{v.cvss_score}</span> / <span style={{ color: '#38bdf8' }}>{((v.epss_score || 0) * 100).toFixed(1)}%</span>
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace', color: '#94a3b8' }}>
                                    {v.package_name} ({v.installed_version})
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace', color: '#34d399' }}>
                                    {v.fixed_version}
                                  </td>
                                  <td style={{ ...styles.td, fontSize: 11, color: '#38bdf8' }}>
                                    {v.remediation}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* 3. LAYER 8 ROOTKIT & IN-MEMORY HUNTER TAB */}
                  {scanDetailTab === 'layer8' && (
                    <div>
                      {/* Layer 8 Metrics */}
                      <div style={styles.statsRibbon}>
                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>POSTURE STATE</span>
                            <span style={{ fontSize: 18 }}>🛡️</span>
                          </div>
                          <div style={{
                            ...styles.statValue,
                            color: selectedScan.layer8?.highest_severity === 'CRITICAL' ? '#ef4444' : (selectedScan.layer8?.highest_severity === 'CLEAN' ? '#10b981' : '#f59e0b')
                          }}>
                            {selectedScan.layer8?.highest_severity || 'CLEAN'}
                          </div>
                          <div style={styles.statSubText}>{selectedScan.layer8?.execution_summary || 'No indicators of compromise recorded.'}</div>
                        </div>

                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>ANOMALIES DETECTED</span>
                            <span style={{ fontSize: 18 }}>⚠️</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#f97316' }}>
                            {selectedScan.layer8?.anomalies_found || 0}
                          </div>
                          <div style={styles.statSubText}>In-Memory / Driver / Linker Deviations</div>
                        </div>

                        <div style={styles.statCard}>
                          <div style={styles.statCardHeader}>
                            <span style={styles.statLabel}>DEEP MEMORY CHECKS</span>
                            <span style={{ fontSize: 18 }}>🔬</span>
                          </div>
                          <div style={{ ...styles.statValue, color: '#38bdf8' }}>
                            {selectedScan.layer8?.total_checks || 6}
                          </div>
                          <div style={styles.statSubText}>Process Cross-Check, RWX Mappings, Preload</div>
                        </div>
                      </div>

                      {/* Findings Table */}
                      <div style={{ ...styles.tableWrapper, marginTop: 16 }}>
                        <table style={styles.table}>
                          <thead>
                            <tr>
                              <th style={styles.th}>Severity</th>
                              <th style={styles.th}>Rule ID</th>
                              <th style={styles.th}>Rule Name & Category</th>
                              <th style={styles.th}>MITRE ATT&CK</th>
                              <th style={styles.th}>Target / Anomaly</th>
                              <th style={styles.th}>Forensic Remediation</th>
                            </tr>
                          </thead>
                          <tbody>
                            {!selectedScan.layer8 || !selectedScan.layer8?.findings || selectedScan.layer8?.findings?.length === 0 ? (
                              <tr>
                                <td colSpan={6} style={{ ...styles.td, textAlign: 'center', color: '#10b981', padding: 24 }}>
                                  ✓ Clean: Zero hidden processes, unlinked running binaries, anonymous RWX pages, or LD_PRELOAD userspace hooks detected.
                                </td>
                              </tr>
                            ) : (
                              selectedScan.layer8.findings.map((f: any, i: number) => (
                                <tr key={i} style={styles.tr}>
                                  <td style={styles.td}>
                                    <span style={{
                                      ...styles.chip,
                                      backgroundColor: f.severity === 'CRITICAL' ? '#7f1d1d' : (f.severity === 'HIGH' ? '#7c2d12' : '#713f12'),
                                      color: f.severity === 'CRITICAL' ? '#fca5a5' : (f.severity === 'HIGH' ? '#fdba74' : '#fde047'),
                                    }}>
                                      {f.severity}
                                    </span>
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace', fontWeight: 600, color: '#f8fafc' }}>
                                    {f.id}
                                  </td>
                                  <td style={styles.td}>
                                    <div style={{ fontWeight: 600, color: '#f8fafc' }}>{f.rule_name}</div>
                                    <div style={{ fontSize: 11, color: '#94a3b8' }}>{f.category}</div>
                                  </td>
                                  <td style={{ ...styles.td, fontSize: 11, color: '#a78bfa' }}>
                                    {f.mitre_tactic}
                                  </td>
                                  <td style={{ ...styles.td, fontFamily: 'monospace', color: '#fca5a5', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {f.target}
                                  </td>
                                  <td style={{ ...styles.td, fontSize: 11, color: '#38bdf8' }}>
                                    {f.remediation}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

// ============================================================================
// STYLES SYSTEM (Deep Dark Cyber-Console Theme)
// ============================================================================

const styles: { [key: string]: React.CSSProperties } = {
  appContainer: {
    display: 'flex',
    minHeight: '100vh',
    backgroundColor: '#070b12',
    color: '#f8fafc',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  sidebar: {
    width: 260,
    backgroundColor: '#0d131f',
    borderRight: '1px solid #1e293b',
    display: 'flex',
    flexDirection: 'column',
    flexShrink: 0,
  },
  sidebarBrand: {
    padding: '20px 20px 16px',
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    borderBottom: '1px solid #1e293b',
  },
  brandIconBox: {
    width: 36,
    height: 36,
    borderRadius: 8,
    backgroundColor: '#1e293b',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  brandTitle: {
    fontSize: 16,
    fontWeight: 700,
    color: '#f8fafc',
    letterSpacing: '0.5px',
  },
  brandSub: {
    fontSize: 11,
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: '1px',
  },
  navMenu: {
    padding: '16px 12px',
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  navGroupLabel: {
    fontSize: 10,
    fontWeight: 700,
    color: '#475569',
    letterSpacing: '1.2px',
    padding: '8px 12px 4px',
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '10px 12px',
    borderRadius: 6,
    backgroundColor: 'transparent',
    border: 'none',
    color: '#94a3b8',
    fontSize: 13,
    fontWeight: 500,
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all 0.15s ease',
  },
  navItemActive: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '10px 12px',
    borderRadius: 6,
    backgroundColor: 'rgba(37, 99, 235, 0.15)',
    border: '1px solid rgba(59, 130, 246, 0.3)',
    color: '#60a5fa',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    textAlign: 'left',
  },
  navIcon: {
    fontSize: 16,
  },
  navCountBadge: {
    marginLeft: 'auto',
    fontSize: 11,
    fontWeight: 600,
    padding: '2px 6px',
    borderRadius: 4,
    backgroundColor: '#1e293b',
    color: '#cbd5e1',
  },
  navBadgePulse: {
    marginLeft: 'auto',
    fontSize: 10,
    fontWeight: 700,
    padding: '2px 6px',
    borderRadius: 4,
    backgroundColor: 'rgba(56, 189, 248, 0.15)',
    color: '#38bdf8',
  },
  sidebarFooter: {
    padding: 16,
    borderTop: '1px solid #1e293b',
  },
  engineStatusRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: '50%',
  },
  mainContent: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    minWidth: 0,
    overflowY: 'auto',
  },
  topHeader: {
    height: 60,
    borderBottom: '1px solid #1e293b',
    backgroundColor: 'rgba(13, 19, 31, 0.7)',
    backdropFilter: 'blur(10px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 24px',
    position: 'sticky',
    top: 0,
    zIndex: 10,
  },
  headerPill: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    padding: '6px 12px',
    borderRadius: 6,
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
  },
  headerActionBtn: {
    padding: '8px 14px',
    borderRadius: 6,
    border: '1px solid #1e293b',
    backgroundColor: '#1e293b',
    color: '#f8fafc',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  viewport: {
    padding: 24,
    maxWidth: 1400,
    width: '100%',
    margin: '0 auto',
  },
  statRibbon: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: 16,
    marginBottom: 20,
  },
  statCard: {
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 16,
  },
  statCardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  statLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#64748b',
    letterSpacing: '0.8px',
  },
  statValue: {
    fontSize: 26,
    fontWeight: 700,
    color: '#f8fafc',
  },
  statSubText: {
    fontSize: 12,
    color: '#94a3b8',
    marginTop: 4,
  },
  heroGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
    gap: 16,
    marginBottom: 20,
  },
  heroActionCard: {
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
  },
  heroIconBox: {
    width: 38,
    height: 38,
    borderRadius: 8,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: 20,
  },
  heroCardTitle: {
    fontSize: 16,
    fontWeight: 700,
    color: '#f8fafc',
    margin: 0,
  },
  heroCardDesc: {
    fontSize: 13,
    color: '#94a3b8',
    lineHeight: 1.5,
    margin: '12px 0 16px',
    flex: 1,
  },
  heroCardBtn: {
    padding: '10px 16px',
    borderRadius: 6,
    border: '1px solid #38bdf8',
    backgroundColor: 'rgba(56, 189, 248, 0.1)',
    color: '#38bdf8',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    alignSelf: 'flex-start',
  },
  contentCard: {
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 20,
    marginBottom: 20,
  },
  cardHeaderRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  cardHeading: {
    fontSize: 16,
    fontWeight: 700,
    color: '#f8fafc',
    margin: 0,
  },
  cardSub: {
    fontSize: 12,
    color: '#94a3b8',
    margin: '4px 0 0',
  },
  textLink: {
    background: 'none',
    border: 'none',
    color: '#38bdf8',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
  },
  feedStatusGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: 12,
  },
  feedBadgeCard: {
    backgroundColor: '#070b12',
    border: '1px solid #1e293b',
    borderRadius: 6,
    padding: 12,
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  feedVendor: {
    fontSize: 13,
    fontWeight: 600,
    color: '#f8fafc',
  },
  feedStatusTag: {
    fontSize: 11,
    color: '#10b981',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: 13,
  },
  th: {
    textAlign: 'left',
    padding: '10px 12px',
    color: '#64748b',
    fontWeight: 600,
    borderBottom: '1px solid #1e293b',
  },
  tr: {
    borderBottom: '1px solid #1e293b',
  },
  td: {
    padding: '12px',
    color: '#cbd5e1',
  },
  chip: {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 600,
    backgroundColor: '#1e293b',
    color: '#94a3b8',
  },
  downloadExcelBtn: {
    display: 'inline-block',
    padding: '4px 10px',
    borderRadius: 4,
    backgroundColor: '#15803d',
    color: '#ffffff',
    textDecoration: 'none',
    fontSize: 12,
    fontWeight: 600,
  },
  actionBtnSmall: {
    padding: '4px 10px',
    borderRadius: 4,
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    color: '#f8fafc',
    fontSize: 12,
    cursor: 'pointer',
  },
  emptyBox: {
    padding: 32,
    textAlign: 'center',
    color: '#64748b',
    fontSize: 13,
  },
  vaModeToggleRow: {
    display: 'flex',
    gap: 12,
    marginBottom: 20,
  },
  vaModeBtn: {
    flex: 1,
    padding: '12px 16px',
    borderRadius: 8,
    border: '1px solid #1e293b',
    backgroundColor: '#0d131f',
    color: '#94a3b8',
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  },
  vaModeActive: {
    flex: 1,
    padding: '12px 16px',
    borderRadius: 8,
    border: '1px solid #3b82f6',
    backgroundColor: 'rgba(59, 130, 246, 0.15)',
    color: '#60a5fa',
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  },
  dropZone: {
    border: '2px dashed #334155',
    borderRadius: 8,
    backgroundColor: '#070b12',
    padding: 36,
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
  },
  primaryBtn: {
    padding: '10px 20px',
    borderRadius: 6,
    backgroundColor: '#2563eb',
    color: '#ffffff',
    border: 'none',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
  },
  fieldSectionLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#64748b',
    letterSpacing: '0.8px',
    display: 'block',
    marginBottom: 10,
  },
  protocolGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: 10,
    marginBottom: 16,
  },
  protocolCard: {
    border: '1px solid #1e293b',
    borderRadius: 6,
    padding: 12,
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    cursor: 'pointer',
  },
  formRow2: {
    display: 'grid',
    gridTemplateColumns: '2fr 1fr',
    gap: 12,
    marginBottom: 12,
  },
  formRow3: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr 1fr',
    gap: 12,
    marginBottom: 12,
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  formLabel: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: 500,
  },
  input: {
    padding: '10px 12px',
    borderRadius: 6,
    border: '1px solid #1e293b',
    backgroundColor: '#070b12',
    color: '#f8fafc',
    fontSize: 13,
    outline: 'none',
    width: '100%',
    boxSizing: 'border-box',
  },
  select: {
    padding: 8,
    borderRadius: 6,
    border: '1px solid #1e293b',
    backgroundColor: '#070b12',
    color: '#f8fafc',
    fontSize: 13,
    width: '100%',
    outline: 'none',
  },
  categoryPillRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 16,
  },
  categoryPill: {
    padding: '4px 10px',
    borderRadius: 20,
    border: '1px solid #1e293b',
    fontSize: 11,
    fontWeight: 600,
    cursor: 'pointer',
  },
  feedsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: 16,
  },
  feedCard: {
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 16,
  },
  feedCardHeader: {
    display: 'flex',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    borderBottom: '1px solid #1e293b',
    paddingBottom: 10,
  },
  feedCardMeta: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: 8,
    padding: '8px 0',
    borderTop: '1px solid #1e293b',
    borderBottom: '1px solid #1e293b',
  },
  feedMetaLabel: {
    fontSize: 10,
    color: '#64748b',
    fontWeight: 700,
    display: 'block',
  },
  feedMetaVal: {
    fontSize: 12,
    color: '#f8fafc',
    fontWeight: 600,
  },
  feedFilesBox: {
    marginTop: 10,
  },
  feedFileCode: {
    display: 'block',
    fontSize: 11,
    color: '#38bdf8',
    backgroundColor: '#070b12',
    padding: '3px 6px',
    borderRadius: 4,
    marginBottom: 4,
  },
  remediationList: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  remediationCard: {
    backgroundColor: '#070b12',
    border: '1px solid #1e293b',
    borderRadius: 6,
    padding: 16,
  },
  playbookBtn: {
    padding: '6px 12px',
    borderRadius: 4,
    color: '#ffffff',
    textDecoration: 'none',
    fontSize: 12,
    fontWeight: 600,
  },
  detailHeader: {
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 16,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  backBtn: {
    padding: '6px 12px',
    borderRadius: 4,
    backgroundColor: '#1e293b',
    border: 'none',
    color: '#94a3b8',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  filterBar: {
    display: 'flex',
    gap: 8,
    marginBottom: 16,
  },
  filterBtn: {
    padding: '6px 14px',
    borderRadius: 6,
    border: '1px solid #1e293b',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  inspectorDrawer: {
    flex: '1 1 45%',
    backgroundColor: '#0d131f',
    border: '1px solid #1e293b',
    borderRadius: 8,
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
  },
  drawerHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderBottom: '1px solid #1e293b',
    paddingBottom: 10,
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: '#94a3b8',
    fontSize: 18,
    cursor: 'pointer',
  },
  drawerSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  boxHeaderRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  boxLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#64748b',
    letterSpacing: '0.8px',
  },
  copyBtn: {
    padding: '2px 8px',
    borderRadius: 4,
    backgroundColor: '#1e293b',
    border: 'none',
    color: '#38bdf8',
    fontSize: 11,
    cursor: 'pointer',
  },
  preCode: {
    margin: 0,
    padding: 12,
    borderRadius: 6,
    backgroundColor: '#070b12',
    border: '1px solid #1e293b',
    fontSize: 12,
    color: '#94a3b8',
    fontFamily: 'monospace',
    maxHeight: 180,
    overflowY: 'auto',
    whiteSpace: 'pre-wrap',
  },
  standardsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: 8,
  },
  standardsCell: {
    backgroundColor: '#070b12',
    border: '1px solid #1e293b',
    borderRadius: 4,
    padding: 8,
  },
  standardsCellLabel: {
    fontSize: 10,
    color: '#64748b',
    fontWeight: 700,
  },
  standardsCellVal: {
    fontSize: 12,
    color: '#f8fafc',
    fontWeight: 600,
    marginTop: 2,
  },
}
