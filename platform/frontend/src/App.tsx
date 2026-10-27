import React, { useEffect, useMemo, useState } from 'react'

// --- Types ---
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
    port?: number
    protocol?: string
    type?: string
    user?: string
    os?: string
  }
  results?: ScanResult[]
  created_at: string
  finished_at?: string
}

// --- Target Protocols ---
interface ProtocolPreset {
  id: 'ssh' | 'winrm' | 'network' | 'postgres' | 'mysql' | 'mssql' | 'mongo'
  name: string
  label: string
  port: number
  defaultUser: string
  icon: string
  badgeColor: string
}

const PROTOCOLS: ProtocolPreset[] = [
  { id: 'ssh', name: 'Linux / Unix', label: 'OpenSSH (Port 22)', port: 22, defaultUser: 'root', icon: '🐧', badgeColor: '#10b981' },
  { id: 'winrm', name: 'Windows Server', label: 'WinRM (Port 5985)', port: 5985, defaultUser: 'Administrator', icon: '🪟', badgeColor: '#38bdf8' },
  { id: 'network', name: 'Network Appliance', label: 'Cisco / Fortinet / PAN-OS (Port 22)', port: 22, defaultUser: 'admin', icon: '🌐', badgeColor: '#a855f7' },
  { id: 'postgres', name: 'PostgreSQL DB', label: 'Postgres SQL (Port 5432)', port: 5432, defaultUser: 'postgres', icon: '🐘', badgeColor: '#3b82f6' },
  { id: 'mysql', name: 'MySQL / MariaDB', label: 'MySQL SQL (Port 3306)', port: 3306, defaultUser: 'root', icon: '🐬', badgeColor: '#f59e0b' },
  { id: 'mssql', name: 'MS SQL Server', label: 'T-SQL (Port 1433)', port: 1433, defaultUser: 'sa', icon: '🏢', badgeColor: '#ef4444' },
  { id: 'mongo', name: 'MongoDB', label: 'NoSQL Admin (Port 27017)', port: 27017, defaultUser: 'admin', icon: '🍃', badgeColor: '#22c55e' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'scans' | 'new_scan' | 'benchmarks' | 'remediation'>('overview')
  const [benchmarks, setBenchmarks] = useState<Benchmark[]>([])
  const [scans, setScans] = useState<ScanJob[]>([])
  const [selectedScan, setSelectedScan] = useState<ScanJob | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<ScanResult | null>(null)
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [backendHealth, setBackendHealth] = useState<boolean>(false)

  // Launch Scan Form State
  const [selectedProtocol, setSelectedProtocol] = useState<ProtocolPreset>(PROTOCOLS[0])
  const [targetHost, setTargetHost] = useState('127.0.0.1')
  const [targetPort, setTargetPort] = useState('22')
  const [targetUser, setTargetUser] = useState('root')
  const [targetPassword, setTargetPassword] = useState('')
  const [targetKeyPath, setTargetKeyPath] = useState('')
  const [targetDatabase, setTargetDatabase] = useState('')
  const [selectedBenchmarkId, setSelectedBenchmarkId] = useState('')
  const [selectedProfile, setSelectedProfile] = useState('level1')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [benchmarkFilterText, setBenchmarkFilterText] = useState('')
  const [copiedText, setCopiedText] = useState<string | null>(null)
  const [auditMode, setAuditMode] = useState<'online' | 'offline'>('online')
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)

  const handleOfflineUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!uploadFile) return
    setUploading(true)
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
    } catch (err) {
      console.error('Upload failed', err)
    } finally {
      setUploading(false)
    }
  }

  // Polling data
  const loadData = async () => {
    try {
      const hRes = await fetch('/health')
      if (hRes.ok) setBackendHealth(true)

      const bRes = await fetch('/api/v1/benchmarks')
      if (bRes.ok) {
        const bJson = await bRes.json()
        const list: Benchmark[] = bJson.data || bJson || []
        setBenchmarks(list)
        if (!selectedBenchmarkId && list.length > 0) {
          setSelectedBenchmarkId(list[0].id)
        }
      }

      const sRes = await fetch('/api/v1/scans')
      if (sRes.ok) {
        const sJson = await sRes.json()
        const list: ScanJob[] = sJson || []
        setScans(list)
        if (selectedScan) {
          const updated = list.find((s) => s.id === selectedScan.id)
          if (updated) setSelectedScan(updated)
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

  // Change protocol handler
  const handleSelectProtocol = (p: ProtocolPreset) => {
    setSelectedProtocol(p)
    setTargetPort(p.port.toString())
    setTargetUser(p.defaultUser)
  }

  // Copy helper
  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(label)
    setTimeout(() => setCopiedText(null), 2000)
  }

  // Handle launch scan
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    try {
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
    } finally {
      setIsSubmitting(false)
    }
  }

  // Metrics helper
  const stats = useMemo(() => {
    const total = scans.length
    let passCount = 0
    let failCount = 0
    scans.forEach((s) => {
      s.results?.forEach((r) => {
        if (r.status === 'pass') passCount++
        if (r.status === 'fail') failCount++
      })
    })
    const sum = passCount + failCount
    const avgScore = sum > 0 ? Math.round((passCount / sum) * 100) : 100
    return { total, passCount, failCount, avgScore }
  }, [scans])

  // Filtered benchmarks for selector
  const filteredBenchmarks = useMemo(() => {
    if (!benchmarkFilterText) return benchmarks
    const q = benchmarkFilterText.toLowerCase()
    return benchmarks.filter(
      (b) =>
        b.title?.toLowerCase().includes(q) ||
        b.technology?.toLowerCase().includes(q) ||
        b.category?.toLowerCase().includes(q) ||
        b.id?.toLowerCase().includes(q)
    )
  }, [benchmarks, benchmarkFilterText])

  // Filtered scan results
  const scanResults = useMemo(() => {
    if (!selectedScan?.results) return []
    let list = selectedScan.results
    if (filterStatus !== 'all') {
      list = list.filter((r) => r.status === filterStatus)
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      list = list.filter((r) => r.control_id.toLowerCase().includes(q) || r.expected?.toLowerCase().includes(q))
    }
    return list
  }, [selectedScan, filterStatus, searchQuery])

  // Scan score calculation
  const scanScore = useMemo(() => {
    if (!selectedScan?.results || selectedScan.results.length === 0) return 0
    const passed = selectedScan.results.filter((r) => r.status === 'pass').length
    const failed = selectedScan.results.filter((r) => r.status === 'fail').length
    const total = passed + failed
    return total > 0 ? Math.round((passed / total) * 100) : 0
  }, [selectedScan])

  return (
    <div style={styles.appContainer}>
      {/* --- Top Vigolium-Style Navigation Bar --- */}
      <header style={styles.header}>
        <div style={styles.brandRow}>
          <div style={styles.logoPill}>
            <span style={styles.logoIcon}>🛡️</span>
            <span style={styles.brandName}>HardenX</span>
            <span style={styles.badgePro}>CIS ENGINE</span>
          </div>

          <div style={styles.statusPill}>
            <span
              style={{
                ...styles.statusDot,
                backgroundColor: backendHealth ? '#10b981' : '#f59e0b',
                boxShadow: backendHealth ? '0 0 10px #10b981' : 'none',
              }}
            />
            <span style={styles.statusText}>
              {backendHealth ? 'Engine: Ready' : 'Connecting to Core...'}
            </span>
            <span style={styles.separator}>|</span>
            <span style={styles.metaStat}>
              <b>{benchmarks.length}</b> Benchmarks Indexed
            </span>
          </div>
        </div>

        {/* Global Tabs */}
        <nav style={styles.navTabs}>
          <button
            onClick={() => setActiveTab('overview')}
            style={activeTab === 'overview' ? styles.navTabActive : styles.navTab}
          >
            📊 Dashboard
          </button>
          <button
            onClick={() => setActiveTab('scans')}
            style={activeTab === 'scans' ? styles.navTabActive : styles.navTab}
          >
            🎯 Scans & Audits ({scans.length})
          </button>
          <button
            onClick={() => setActiveTab('new_scan')}
            style={activeTab === 'new_scan' ? styles.navTabActive : styles.navTab}
          >
            🚀 Launch Audit
          </button>
          <button
            onClick={() => setActiveTab('benchmarks')}
            style={activeTab === 'benchmarks' ? styles.navTabActive : styles.navTab}
          >
            📑 Benchmark Catalog
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            style={activeTab === 'remediation' ? styles.navTabActive : styles.navTab}
          >
            🛡️ Remediation Hub
          </button>
        </nav>
      </header>

      {/* --- Main Workspace Canvas --- */}
      <main style={styles.mainCanvas}>
        {/* ============================================================ */}
        {/* MODULE 1: OVERVIEW / DASHBOARD (Vigolium Minimalist Cards)   */}
        {/* ============================================================ */}
        {activeTab === 'overview' && (
          <div style={styles.tabContent}>
            <div style={styles.heroBanner}>
              <div>
                <h1 style={styles.heroTitle}>Autonomous Infrastructure Compliance</h1>
                <p style={styles.heroSubtitle}>
                  Agentless CIS benchmark verification with native SSH, WinRM, SQL, and Network CLI execution.
                </p>
              </div>
              <button
                onClick={() => setActiveTab('new_scan')}
                style={styles.heroBtn}
              >
                + New Audit Scan
              </button>
            </div>

            {/* Metric KPI Cards */}
            <div style={styles.kpiGrid}>
              <div style={styles.kpiCard}>
                <div style={styles.kpiHeader}>
                  <span style={styles.kpiLabel}>COMPLIANCE GRADE</span>
                  <span style={{ fontSize: 22 }}>🏆</span>
                </div>
                <div style={{ ...styles.kpiValue, color: stats.avgScore >= 80 ? '#10b981' : stats.avgScore >= 60 ? '#f59e0b' : '#ef4444' }}>
                  {stats.avgScore}%
                </div>
                <div style={styles.kpiFooter}>Across all target infrastructures</div>
              </div>

              <div style={styles.kpiCard}>
                <div style={styles.kpiHeader}>
                  <span style={styles.kpiLabel}>CIS BENCHMARKS INDEXED</span>
                  <span style={{ fontSize: 22 }}>📚</span>
                </div>
                <div style={styles.kpiValue}>{benchmarks.length}</div>
                <div style={styles.kpiFooter}>Operating Systems, Cloud, Databases, Network</div>
              </div>

              <div style={styles.kpiCard}>
                <div style={styles.kpiHeader}>
                  <span style={styles.kpiLabel}>TOTAL CONTROLS AUDITED</span>
                  <span style={{ fontSize: 22 }}>🎯</span>
                </div>
                <div style={styles.kpiValue}>{stats.passCount + stats.failCount}</div>
                <div style={styles.kpiFooter}>
                  <span style={{ color: '#10b981' }}>{stats.passCount} Passed</span> •{' '}
                  <span style={{ color: '#ef4444' }}>{stats.failCount} Failed</span>
                </div>
              </div>

              <div style={styles.kpiCard}>
                <div style={styles.kpiHeader}>
                  <span style={styles.kpiLabel}>SUPPORTED CONNECTORS</span>
                  <span style={{ fontSize: 22 }}>⚡</span>
                </div>
                <div style={styles.kpiValue}>{PROTOCOLS.length}</div>
                <div style={styles.kpiFooter}>SSH, WinRM, Cisco, PAN-OS, Postgres, Mongo</div>
              </div>
            </div>

            {/* Connectors Quick Bar */}
            <div style={styles.sectionCard}>
              <h3 style={styles.cardSectionTitle}>Connected Protocols & Engines</h3>
              <div style={styles.protocolBadgesGrid}>
                {PROTOCOLS.map((p) => (
                  <div key={p.id} style={styles.protocolPillCard}>
                    <span style={{ fontSize: 26 }}>{p.icon}</span>
                    <div>
                      <div style={styles.protocolCardTitle}>{p.name}</div>
                      <div style={styles.protocolCardSub}>{p.label}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Scans Overview */}
            <div style={styles.sectionCard}>
              <div style={styles.cardHeaderRow}>
                <h3 style={styles.cardSectionTitle}>Recent Compliance Scans</h3>
                <button
                  onClick={() => setActiveTab('scans')}
                  style={styles.textLinkBtn}
                >
                  View All Scans →
                </button>
              </div>

              {scans.length === 0 ? (
                <div style={styles.emptyNotice}>
                  No scans executed yet. Click &quot;Launch Audit&quot; to run your first CIS audit.
                </div>
              ) : (
                <div style={styles.tableWrapper}>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>Scan ID</th>
                        <th style={styles.th}>Target Host</th>
                        <th style={styles.th}>Benchmark</th>
                        <th style={styles.th}>Status</th>
                        <th style={styles.th}>Controls</th>
                        <th style={styles.th}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.slice(0, 5).map((scan) => (
                        <tr key={scan.id} style={styles.tr}>
                          <td style={{ ...styles.td, fontFamily: 'monospace', color: '#93c5fd' }}>
                            {scan.id.slice(0, 8)}...
                          </td>
                          <td style={styles.td}>
                            <b>{scan.asset?.host || '127.0.0.1'}</b> ({scan.asset?.protocol?.toUpperCase() || 'SSH'})
                          </td>
                          <td style={styles.td}>{scan.benchmark_id}</td>
                          <td style={styles.td}>
                            <span
                              style={{
                                ...styles.badge,
                                backgroundColor:
                                  scan.status === 'completed'
                                    ? '#064e3b'
                                    : scan.status === 'running'
                                    ? '#78350f'
                                    : '#7f1d1d',
                                color:
                                  scan.status === 'completed'
                                    ? '#34d399'
                                    : scan.status === 'running'
                                    ? '#fde68a'
                                    : '#fca5a5',
                              }}
                            >
                              {scan.status}
                            </span>
                          </td>
                          <td style={styles.td}>{scan.results?.length || 0} checks</td>
                          <td style={styles.td}>
                            <button
                              onClick={() => {
                                setSelectedScan(scan)
                                setActiveTab('scans')
                              }}
                              style={styles.actionBtnSmall}
                            >
                              Inspect →
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

        {/* ============================================================ */}
        {/* MODULE 2: SCANS & AUDITS (Nessus Depth + Vigolium Drawer)   */}
        {/* ============================================================ */}
        {activeTab === 'scans' && (
          <div style={styles.tabContent}>
            {!selectedScan ? (
              <div style={styles.sectionCard}>
                <div style={styles.cardHeaderRow}>
                  <div>
                    <h2 style={styles.cardTitle}>Audit Scans Library</h2>
                    <p style={styles.cardSubtitle}>
                      Review compliance evaluation histories, live job progress, and evidence.
                    </p>
                  </div>
                  <button
                    onClick={() => setActiveTab('new_scan')}
                    style={styles.primaryBtn}
                  >
                    + Launch New Audit
                  </button>
                </div>

                {scans.length === 0 ? (
                  <div style={styles.emptyNotice}>
                    No scans recorded. Launch a new audit to inspect asset compliance.
                  </div>
                ) : (
                  <div style={styles.tableWrapper}>
                    <table style={styles.table}>
                      <thead>
                        <tr>
                          <th style={styles.th}>Scan ID</th>
                          <th style={styles.th}>Target</th>
                          <th style={styles.th}>Benchmark / Profile</th>
                          <th style={styles.th}>Status</th>
                          <th style={styles.th}>Results</th>
                          <th style={styles.th}>Triggered</th>
                          <th style={styles.th}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scans.map((scan) => {
                          const passed = scan.results?.filter((r) => r.status === 'pass').length || 0
                          const failed = scan.results?.filter((r) => r.status === 'fail').length || 0
                          const total = passed + failed
                          const score = total > 0 ? Math.round((passed / total) * 100) : 0

                          return (
                            <tr key={scan.id} style={styles.tr}>
                              <td style={{ ...styles.td, fontFamily: 'monospace', color: '#93c5fd' }}>
                                {scan.id.slice(0, 12)}
                              </td>
                              <td style={styles.td}>
                                <div>
                                  <b>{scan.asset?.host || '127.0.0.1'}</b>
                                </div>
                                <span style={styles.subText}>
                                  {scan.asset?.protocol?.toUpperCase()} • Port {scan.asset?.port}
                                </span>
                              </td>
                              <td style={styles.td}>
                                <div>{scan.benchmark_id}</div>
                                <span style={styles.subText}>Profile: {scan.profile}</span>
                              </td>
                              <td style={styles.td}>
                                <span
                                  style={{
                                    ...styles.badge,
                                    backgroundColor:
                                      scan.status === 'completed'
                                        ? '#064e3b'
                                        : scan.status === 'running'
                                        ? '#78350f'
                                        : '#7f1d1d',
                                    color:
                                      scan.status === 'completed'
                                        ? '#34d399'
                                        : scan.status === 'running'
                                        ? '#fde68a'
                                        : '#fca5a5',
                                  }}
                                >
                                  {scan.status}
                                </span>
                              </td>
                              <td style={styles.td}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                  <span style={{ fontWeight: 600, color: score >= 70 ? '#10b981' : '#ef4444' }}>
                                    {score}%
                                  </span>
                                  <span style={styles.subText}>
                                    ({passed}P / {failed}F)
                                  </span>
                                </div>
                              </td>
                              <td style={styles.td}>
                                {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                              </td>
                              <td style={styles.td}>
                                <button
                                  onClick={() => setSelectedScan(scan)}
                                  style={styles.actionBtnSmall}
                                >
                                  Open Report →
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : (
              /* Selected Scan Detail (Nessus Depth View) */
              <div style={styles.scanDetailContainer}>
                {/* Detail Header & Action Toolbar */}
                <div style={styles.detailHeaderBox}>
                  <div style={styles.detailBreadcrumbRow}>
                    <button
                      onClick={() => {
                        setSelectedScan(null)
                        setSelectedFinding(null)
                      }}
                      style={styles.backBtn}
                    >
                      ← Back to Scans List
                    </button>
                    <span style={styles.separator}>/</span>
                    <span style={{ color: '#93c5fd', fontFamily: 'monospace' }}>{selectedScan.id}</span>
                  </div>

                  <div style={styles.detailTitleRow}>
                    <div>
                      <h2 style={{ margin: '4px 0', fontSize: 24 }}>{selectedScan.benchmark_id}</h2>
                      <div style={styles.targetMetaPillRow}>
                        <span>Target: <b>{selectedScan.asset?.host}:{selectedScan.asset?.port}</b></span>
                        <span>Protocol: <b>{selectedScan.asset?.protocol?.toUpperCase()}</b></span>
                        <span>Profile: <b>{selectedScan.profile}</b></span>
                        <span>Status: <b style={{ textTransform: 'capitalize' }}>{selectedScan.status}</b></span>
                      </div>
                    </div>

                    {/* Vigolium Export Action Buttons */}
                    <div style={styles.exportButtonGroup}>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/report/mci-excel`}
                        download={`MCI_Master_Assessment_${selectedScan.id}.xlsx`}
                        style={{ ...styles.reportExportBtn, backgroundColor: '#15803d', borderColor: '#22c55e', color: '#ffffff', fontWeight: 600 }}
                      >
                        MCI 15-Sheet Excel (.xlsx) ⬇
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/report`}
                        target="_blank"
                        rel="noreferrer"
                        style={styles.reportExportBtn}
                      >
                        Nessus HTML Report ↗
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/remediation/ansible`}
                        download={`remediation_${selectedScan.id}.yml`}
                        style={{ ...styles.reportExportBtn, backgroundColor: '#059669' }}
                      >
                        Ansible Playbook ⬇
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/remediation/powershell`}
                        download={`remediation_${selectedScan.id}.ps1`}
                        style={{ ...styles.reportExportBtn, backgroundColor: '#0284c7' }}
                      >
                        PowerShell Script ⬇
                      </a>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/remediation/bash`}
                        download={`remediation_${selectedScan.id}.sh`}
                        style={{ ...styles.reportExportBtn, backgroundColor: '#7c3aed' }}
                      >
                        Bash Script ⬇
                      </a>
                    </div>
                  </div>

                  {/* Summary Metric Counters */}
                  <div style={styles.statsGaugeRow}>
                    <div style={styles.gaugeCard}>
                      <span style={styles.gaugeLabel}>COMPLIANCE SCORE</span>
                      <span
                        style={{
                          fontSize: 32,
                          fontWeight: 700,
                          color: scanScore >= 70 ? '#10b981' : '#ef4444',
                        }}
                      >
                        {scanScore}%
                      </span>
                    </div>
                    <div style={styles.gaugeCard}>
                      <span style={styles.gaugeLabel}>PASSED CONTROLS</span>
                      <span style={{ fontSize: 32, fontWeight: 700, color: '#10b981' }}>
                        {selectedScan.results?.filter((r) => r.status === 'pass').length || 0}
                      </span>
                    </div>
                    <div style={styles.gaugeCard}>
                      <span style={styles.gaugeLabel}>FAILED CONTROLS</span>
                      <span style={{ fontSize: 32, fontWeight: 700, color: '#ef4444' }}>
                        {selectedScan.results?.filter((r) => r.status === 'fail').length || 0}
                      </span>
                    </div>
                    <div style={styles.gaugeCard}>
                      <span style={styles.gaugeLabel}>TOTAL AUDITED</span>
                      <span style={{ fontSize: 32, fontWeight: 700, color: '#93c5fd' }}>
                        {selectedScan.results?.length || 0}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Filter and Search Bar */}
                <div style={styles.filterBar}>
                  <div style={styles.filterPillsGroup}>
                    {['all', 'fail', 'pass', 'error'].map((st) => (
                      <button
                        key={st}
                        onClick={() => setFilterStatus(st)}
                        style={filterStatus === st ? styles.filterPillActive : styles.filterPill}
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

                  <input
                    type="text"
                    placeholder="Search findings by ID or pattern..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={styles.searchInput}
                  />
                </div>

                {/* Findings Table + Slide-over Drawer */}
                <div style={styles.findingsLayout}>
                  <div style={{ flex: selectedFinding ? '1 1 55%' : '1 1 100%' }}>
                    <div style={styles.tableWrapper}>
                      <table style={styles.table}>
                        <thead>
                          <tr>
                            <th style={styles.th}>Status</th>
                            <th style={styles.th}>Control ID</th>
                            <th style={styles.th}>Check Type</th>
                            <th style={styles.th}>Expected Output</th>
                            <th style={styles.th}>Duration</th>
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
                                backgroundColor:
                                  selectedFinding?.control_id === r.control_id
                                    ? '#1e293b'
                                    : 'transparent',
                                cursor: 'pointer',
                              }}
                            >
                              <td style={styles.td}>
                                <span
                                  style={{
                                    ...styles.statusDotSmall,
                                    backgroundColor:
                                      r.status === 'pass'
                                        ? '#10b981'
                                        : r.status === 'fail'
                                        ? '#ef4444'
                                        : '#f59e0b',
                                  }}
                                />
                                <span
                                  style={{
                                    fontWeight: 600,
                                    textTransform: 'uppercase',
                                    fontSize: 12,
                                    color:
                                      r.status === 'pass'
                                        ? '#34d399'
                                        : r.status === 'fail'
                                        ? '#fca5a5'
                                        : '#fcd34d',
                                  }}
                                >
                                  {r.status === 'pass' ? 'PASSED' : r.status === 'fail' ? 'FAILED' : 'ERROR'}
                                </span>
                              </td>
                              <td style={{ ...styles.td, fontWeight: 600, color: '#f8fafc', fontFamily: 'monospace' }}>
                                {r.control_id}
                              </td>
                              <td style={styles.td}>
                                <span style={styles.checkTypeBadge}>{r.check_type}</span>
                              </td>
                              <td style={{ ...styles.td, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {r.expected || 'Exit Code 0 / Compliance Match'}
                              </td>
                              <td style={styles.td}>{r.duration_ms}ms</td>
                              <td style={styles.td}>
                                <button style={styles.actionBtnSmall}>
                                  View Evidence →
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Interactive Finding Inspector Drawer (Vigolium Slide Panel) */}
                  {selectedFinding && (
                    <div style={styles.inspectorDrawer}>
                      <div style={styles.inspectorHeader}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span
                              style={{
                                ...styles.badge,
                                backgroundColor: selectedFinding.status === 'pass' ? '#064e3b' : '#7f1d1d',
                                color: selectedFinding.status === 'pass' ? '#34d399' : '#fca5a5',
                              }}
                            >
                              {selectedFinding.status.toUpperCase()}
                            </span>
                            <span style={{ fontSize: 18, fontWeight: 700, fontFamily: 'monospace' }}>
                              CIS [{selectedFinding.control_id}]
                            </span>
                          </div>
                        </div>
                        <button
                          onClick={() => setSelectedFinding(null)}
                          style={styles.closeDrawerBtn}
                        >
                          ✕
                        </button>
                      </div>

                      <div style={styles.inspectorBody}>
                        {/* Terminal Evidence Monospace Block */}
                        <div style={styles.inspectorSection}>
                          <div style={styles.boxHeaderRow}>
                            <span style={styles.boxTitle}>AUDIT EVIDENCE & RAW TERMINAL OUTPUT</span>
                            <button
                              onClick={() => handleCopy(selectedFinding.evidence || selectedFinding.actual, 'evidence')}
                              style={styles.copyBtn}
                            >
                              {copiedText === 'evidence' ? 'Copied ✓' : 'Copy Evidence'}
                            </button>
                          </div>
                          <pre style={styles.terminalPre}>
                            {selectedFinding.evidence || selectedFinding.actual || 'No output recorded'}
                          </pre>
                        </div>

                        {/* Expected Criteria Box */}
                        <div style={styles.inspectorSection}>
                          <span style={styles.boxTitle}>EXPECTED COMPLIANCE CRITERIA</span>
                          <div style={styles.criteriaBox}>
                            {selectedFinding.expected || 'Exit Code 0 (Expected zero violations)'}
                          </div>
                        </div>

                        {/* Authoritative Standards Cross-Mapping & Threat Intelligence */}
                        <div style={styles.inspectorSection}>
                          <span style={styles.boxTitle}>AUTHORITATIVE STANDARDS & THREAT INTELLIGENCE</span>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10, marginTop: 8 }}>
                            <div style={{ backgroundColor: '#090d16', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px' }}>
                              <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>CISA KEV STATUS</div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8', marginTop: 4 }}>
                                Indexed in Catalog (1,754 CVEs)
                              </div>
                            </div>
                            <div style={{ backgroundColor: '#090d16', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px' }}>
                              <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>NIST SP 800-53 REV 5</div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: '#a78bfa', marginTop: 4 }}>
                                CM-6 • SC-7 • AC-3 • SI-2
                              </div>
                            </div>
                            <div style={{ backgroundColor: '#090d16', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px' }}>
                              <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>CIS CONTROLS V8</div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: '#34d399', marginTop: 4 }}>
                                Control 4: Secure Configuration
                              </div>
                            </div>
                            <div style={{ backgroundColor: '#090d16', border: '1px solid #1e293b', borderRadius: 6, padding: '10px 12px' }}>
                              <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600 }}>MCI REGULATORY REVIEW</div>
                              <div style={{ fontSize: 13, fontWeight: 700, color: '#f59e0b', marginTop: 4 }}>
                                {selectedFinding.status === 'pass' ? 'Done (Auditor Signed)' : 'Undone (Action Required)'}
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Automated Remediation Quick-Fix Block */}
                        <div style={styles.inspectorSection}>
                          <div style={styles.boxHeaderRow}>
                            <span style={styles.boxTitle}>REMEDIATION SCRIPT</span>
                            <button
                              onClick={() =>
                                handleCopy(
                                  `# Automated HardenX Remediation for CIS ${selectedFinding.control_id}\n# Run on target asset`,
                                  'fix'
                                )
                              }
                              style={styles.copyBtn}
                            >
                              {copiedText === 'fix' ? 'Copied ✓' : 'Copy Fix'}
                            </button>
                          </div>
                          <pre style={{ ...styles.terminalPre, color: '#38bdf8' }}>
                            {`# Step 1: Execute automated compliance fix for CIS ${selectedFinding.control_id}\n# Or download the generated Ansible/PowerShell playbook from the top bar.`}
                          </pre>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ============================================================ */}
        {/* MODULE 3: LAUNCH AUDIT SCAN (Vigolium Protocol Cards)        */}
        {/* ============================================================ */}
        {activeTab === 'new_scan' && (
          <div style={styles.tabContent}>
            <div style={styles.sectionCard}>
              <h2 style={styles.cardTitle}>Configure & Launch Compliance Audit</h2>
              <p style={styles.cardSubtitle}>
                Select the target asset protocol, pick a CIS benchmark, and run agentless remote compliance audits.
              </p>

              <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
                <button
                  type="button"
                  onClick={() => setAuditMode('online')}
                  style={{
                    flex: 1,
                    padding: '12px 16px',
                    borderRadius: 8,
                    border: '1px solid',
                    borderColor: auditMode === 'online' ? '#3b82f6' : '#1e293b',
                    backgroundColor: auditMode === 'online' ? 'rgba(59, 130, 246, 0.15)' : '#0f172a',
                    color: auditMode === 'online' ? '#60a5fa' : '#94a3b8',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  🌐 Online Live Agentless Audit (SSH / WinRM / Network / DB)
                </button>
                <button
                  type="button"
                  onClick={() => setAuditMode('offline')}
                  style={{
                    flex: 1,
                    padding: '12px 16px',
                    borderRadius: 8,
                    border: '1px solid',
                    borderColor: auditMode === 'offline' ? '#3b82f6' : '#1e293b',
                    backgroundColor: auditMode === 'offline' ? 'rgba(59, 130, 246, 0.15)' : '#0f172a',
                    color: auditMode === 'offline' ? '#60a5fa' : '#94a3b8',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  📦 Air-Gapped Offline Evidence Ingestion (&lt;ip&gt;_&lt;host&gt;.txt)
                </button>
              </div>

              {auditMode === 'offline' ? (
                <form onSubmit={handleOfflineUpload} style={styles.formContainer}>
                  <div style={styles.formSectionBox}>
                    <label style={styles.stepLabel}>AIR-GAPPED OFFLINE EVIDENCE UPLOAD</label>
                    <p style={{ color: '#94a3b8', fontSize: 13, margin: '8px 0 16px' }}>
                      Upload raw host evidence files generated by OfflineVA Universal Collector. The engine evaluates epoch-aware packages against authoritative vendor CSAF 2.0 VEX and CIS companion benchmarks.
                    </p>
                    <input
                      type="file"
                      accept=".txt"
                      required
                      onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                      style={{
                        padding: 12,
                        backgroundColor: '#090d16',
                        border: '1px dashed #3b82f6',
                        borderRadius: 8,
                        color: '#f8fafc',
                        width: '100%',
                      }}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={uploading || !uploadFile}
                    style={{ ...styles.submitBtn, opacity: uploading ? 0.6 : 1 }}
                  >
                    {uploading ? 'Analyzing Offline Evidence...' : '⚡ Ingest & Analyze Offline Evidence'}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleLaunchScan} style={styles.formContainer}>
                {/* Step 1: Target Protocol Selector Cards */}
                <div style={styles.formSectionBox}>
                  <label style={styles.stepLabel}>STEP 1: SELECT ASSET TYPE & PROTOCOL</label>
                  <div style={styles.protocolCardGrid}>
                    {PROTOCOLS.map((p) => {
                      const isSelected = selectedProtocol.id === p.id
                      return (
                        <div
                          key={p.id}
                          onClick={() => handleSelectProtocol(p)}
                          style={{
                            ...styles.protocolSelectCard,
                            borderColor: isSelected ? '#3b82f6' : '#1e293b',
                            backgroundColor: isSelected ? 'rgba(59, 130, 246, 0.12)' : '#0f172a',
                          }}
                        >
                          <div style={{ fontSize: 28, marginBottom: 8 }}>{p.icon}</div>
                          <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 14 }}>{p.name}</div>
                          <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>{p.label}</div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Step 2: Connection & Credentials */}
                <div style={styles.formSectionBox}>
                  <label style={styles.stepLabel}>STEP 2: TARGET CONNECTION & CREDENTIALS</label>
                  <div style={styles.inputGrid2}>
                    <div style={styles.fieldGroup}>
                      <label style={styles.fieldLabel}>Host / IP Address</label>
                      <input
                        type="text"
                        required
                        value={targetHost}
                        onChange={(e) => setTargetHost(e.target.value)}
                        style={styles.textInput}
                        placeholder="192.168.1.50 or host.internal"
                      />
                    </div>

                    <div style={styles.fieldGroup}>
                      <label style={styles.fieldLabel}>Port</label>
                      <input
                        type="number"
                        required
                        value={targetPort}
                        onChange={(e) => setTargetPort(e.target.value)}
                        style={styles.textInput}
                      />
                    </div>
                  </div>

                  <div style={styles.inputGrid3}>
                    <div style={styles.fieldGroup}>
                      <label style={styles.fieldLabel}>Username / Account</label>
                      <input
                        type="text"
                        required
                        value={targetUser}
                        onChange={(e) => setTargetUser(e.target.value)}
                        style={styles.textInput}
                      />
                    </div>

                    <div style={styles.fieldGroup}>
                      <label style={styles.fieldLabel}>Password / Secret</label>
                      <input
                        type="password"
                        value={targetPassword}
                        onChange={(e) => setTargetPassword(e.target.value)}
                        style={styles.textInput}
                        placeholder="••••••••••••"
                      />
                    </div>

                    <div style={styles.fieldGroup}>
                      <label style={styles.fieldLabel}>Private Key Path (SSH Only)</label>
                      <input
                        type="text"
                        value={targetKeyPath}
                        onChange={(e) => setTargetKeyPath(e.target.value)}
                        style={styles.textInput}
                        placeholder="~/.ssh/id_rsa"
                      />
                    </div>
                  </div>
                </div>

                {/* Step 3: CIS Benchmark Selection */}
                <div style={styles.formSectionBox}>
                  <div style={styles.stepHeaderRow}>
                    <label style={styles.stepLabel}>
                      STEP 3: SELECT CIS BENCHMARK ({benchmarks.length} AVAILABLE)
                    </label>
                    <div style={styles.profileToggle}>
                      <button
                        type="button"
                        onClick={() => setSelectedProfile('level1')}
                        style={selectedProfile === 'level1' ? styles.profileToggleBtnActive : styles.profileToggleBtn}
                      >
                        Level 1 (Standard)
                      </button>
                      <button
                        type="button"
                        onClick={() => setSelectedProfile('level2')}
                        style={selectedProfile === 'level2' ? styles.profileToggleBtnActive : styles.profileToggleBtn}
                      >
                        Level 2 (Hardened)
                      </button>
                    </div>
                  </div>

                  <input
                    type="text"
                    placeholder="Search CIS benchmarks by OS, Server, Cloud, or keyword..."
                    value={benchmarkFilterText}
                    onChange={(e) => setBenchmarkFilterText(e.target.value)}
                    style={{ ...styles.textInput, marginBottom: 12 }}
                  />

                  <select
                    value={selectedBenchmarkId}
                    onChange={(e) => setSelectedBenchmarkId(e.target.value)}
                    style={styles.selectInput}
                    size={6}
                  >
                    {filteredBenchmarks.slice(0, 100).map((b) => (
                      <option key={b.id} value={b.id} style={styles.selectOption}>
                        {b.title} [{b.category || 'General'}] (v{b.version})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Submit Action */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
                  <button
                    type="submit"
                    disabled={isSubmitting || !selectedBenchmarkId}
                    style={styles.launchSubmitBtn}
                  >
                    {isSubmitting ? 'Connecting & Launching Audit...' : '⚡ Execute Compliance Scan Now'}
                  </button>
                </div>
              </form>
            )}
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* MODULE 4: BENCHMARK CATALOG (All 1,246 Benchmarks)           */}
        {/* ============================================================ */}
        {activeTab === 'benchmarks' && (
          <div style={styles.tabContent}>
            <div style={styles.sectionCard}>
              <div style={styles.cardHeaderRow}>
                <div>
                  <h2 style={styles.cardTitle}>CIS Benchmark Catalog ({benchmarks.length} Total)</h2>
                  <p style={styles.cardSubtitle}>
                    All 1,246 companion benchmarks generated directly from official Center for Internet Security PDFs.
                  </p>
                </div>
                <input
                  type="text"
                  placeholder="Filter by operating system, server, or software..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ ...styles.textInput, maxWidth: 320 }}
                />
              </div>

              <div style={styles.tableWrapper}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Benchmark ID</th>
                      <th style={styles.th}>Title</th>
                      <th style={styles.th}>Version</th>
                      <th style={styles.th}>Category</th>
                      <th style={styles.th}>Technology</th>
                      <th style={styles.th}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchmarks
                      .filter(
                        (b) =>
                          !searchQuery ||
                          b.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          b.category?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          b.technology?.toLowerCase().includes(searchQuery.toLowerCase())
                      )
                      .slice(0, 150)
                      .map((b) => (
                        <tr key={b.id} style={styles.tr}>
                          <td style={{ ...styles.td, fontFamily: 'monospace', color: '#93c5fd' }}>{b.id}</td>
                          <td style={{ ...styles.td, fontWeight: 600 }}>{b.title}</td>
                          <td style={styles.td}>v{b.version}</td>
                          <td style={styles.td}>
                            <span style={styles.categoryBadge}>{b.category || 'General'}</span>
                          </td>
                          <td style={styles.td}>{b.technology || 'Universal'}</td>
                          <td style={styles.td}>
                            <button
                              onClick={() => {
                                setSelectedBenchmarkId(b.id)
                                setActiveTab('new_scan')
                              }}
                              style={styles.actionBtnSmall}
                            >
                              Audit With This →
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* MODULE 5: REMEDIATION HUB                                    */}
        {/* ============================================================ */}
        {activeTab === 'remediation' && (
          <div style={styles.tabContent}>
            <div style={styles.sectionCard}>
              <h2 style={styles.cardTitle}>Automated Remediation Playbooks</h2>
              <p style={styles.cardSubtitle}>
                HardenX automatically generates runnable Ansible playbooks and PowerShell scripts for non-compliant controls.
              </p>

              {scans.length === 0 ? (
                <div style={styles.emptyNotice}>
                  No scan jobs available yet. Run a scan to generate remediation playbooks.
                </div>
              ) : (
                <div style={styles.remediationGrid}>
                  {scans.map((s) => {
                    const failCount = s.results?.filter((r) => r.status === 'fail').length || 0
                    return (
                      <div key={s.id} style={styles.remediationCard}>
                        <div style={styles.remediationCardHeader}>
                          <div>
                            <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: 16 }}>
                              {s.benchmark_id}
                            </div>
                            <div style={styles.subText}>
                              Target: {s.asset?.host} • Failed Controls: <b style={{ color: '#ef4444' }}>{failCount}</b>
                            </div>
                          </div>
                        </div>

                        <div style={styles.downloadRow}>
                          <a
                            href={`/api/v1/scans/${s.id}/remediation/ansible`}
                            download={`remediation_${s.id}.yml`}
                            style={styles.playbookBtnAnsible}
                          >
                            📦 Download Ansible Playbook
                          </a>
                          <a
                            href={`/api/v1/scans/${s.id}/remediation/powershell`}
                            download={`remediation_${s.id}.ps1`}
                            style={styles.playbookBtnPowerShell}
                          >
                            💻 Download PowerShell Script
                          </a>
                          <a
                            href={`/api/v1/scans/${s.id}/remediation/bash`}
                            download={`remediation_${s.id}.sh`}
                            style={styles.playbookBtnBash}
                          >
                            🐧 Download Bash Script
                          </a>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

// --- Vigolium + Nessus Pro Design System (Inline Styles) ---
const styles: { [key: string]: React.CSSProperties } = {
  appContainer: {
    minHeight: '100vh',
    backgroundColor: '#090d16',
    color: '#f1f5f9',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    borderBottom: '1px solid #1e293b',
    backgroundColor: '#0c1222',
    padding: '12px 24px',
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  brandRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  logoPill: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  logoIcon: {
    fontSize: 24,
  },
  brandName: {
    fontSize: 20,
    fontWeight: 700,
    letterSpacing: '-0.5px',
    color: '#ffffff',
  },
  badgePro: {
    fontSize: 10,
    fontWeight: 700,
    padding: '2px 8px',
    borderRadius: 4,
    backgroundColor: '#3b82f6',
    color: '#ffffff',
    letterSpacing: '0.5px',
  },
  statusPill: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    fontSize: 12,
    backgroundColor: '#111827',
    padding: '6px 14px',
    borderRadius: 20,
    border: '1px solid #1f2937',
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: '50%',
  },
  statusDotSmall: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    display: 'inline-block',
    marginRight: 6,
  },
  statusText: {
    color: '#94a3b8',
    fontWeight: 500,
  },
  separator: {
    color: '#374151',
  },
  metaStat: {
    color: '#cbd5e1',
  },
  navTabs: {
    display: 'flex',
    gap: 6,
    borderTop: '1px solid #1e293b',
    paddingTop: 8,
  },
  navTab: {
    backgroundColor: 'transparent',
    border: 'none',
    color: '#94a3b8',
    padding: '8px 16px',
    borderRadius: 6,
    fontSize: 13,
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  navTabActive: {
    backgroundColor: '#1e293b',
    border: 'none',
    color: '#38bdf8',
    padding: '8px 16px',
    borderRadius: 6,
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
  },
  mainCanvas: {
    flex: 1,
    padding: 24,
    maxWidth: 1600,
    margin: '0 auto',
    width: '100%',
  },
  tabContent: {
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
  },
  heroBanner: {
    backgroundColor: '#0f172a',
    borderRadius: 12,
    padding: '28px 32px',
    border: '1px solid #1e293b',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
  },
  heroTitle: {
    margin: 0,
    fontSize: 26,
    fontWeight: 700,
    letterSpacing: '-0.5px',
    color: '#ffffff',
  },
  heroSubtitle: {
    margin: '6px 0 0 0',
    color: '#94a3b8',
    fontSize: 14,
  },
  heroBtn: {
    backgroundColor: '#2563eb',
    color: '#ffffff',
    border: 'none',
    padding: '12px 24px',
    borderRadius: 8,
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
    boxShadow: '0 2px 10px rgba(37, 99, 235, 0.4)',
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
    gap: 16,
  },
  kpiCard: {
    backgroundColor: '#0f172a',
    borderRadius: 10,
    padding: 20,
    border: '1px solid #1e293b',
  },
  kpiHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  kpiLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#64748b',
    letterSpacing: '0.8px',
  },
  kpiValue: {
    fontSize: 32,
    fontWeight: 700,
    color: '#f8fafc',
    margin: '4px 0',
  },
  kpiFooter: {
    fontSize: 12,
    color: '#94a3b8',
  },
  sectionCard: {
    backgroundColor: '#0f172a',
    borderRadius: 12,
    padding: 24,
    border: '1px solid #1e293b',
  },
  cardTitle: {
    margin: 0,
    fontSize: 20,
    fontWeight: 700,
    color: '#ffffff',
  },
  cardSubtitle: {
    margin: '4px 0 16px 0',
    color: '#94a3b8',
    fontSize: 13,
  },
  cardSectionTitle: {
    margin: '0 0 16px 0',
    fontSize: 16,
    fontWeight: 600,
    color: '#e2e8f0',
  },
  cardHeaderRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  protocolBadgesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: 12,
  },
  protocolPillCard: {
    backgroundColor: '#1e293b',
    borderRadius: 8,
    padding: '12px 16px',
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    border: '1px solid #334155',
  },
  protocolCardTitle: {
    fontWeight: 600,
    fontSize: 14,
    color: '#f8fafc',
  },
  protocolCardSub: {
    fontSize: 11,
    color: '#94a3b8',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'left',
    fontSize: 13,
  },
  th: {
    borderBottom: '1px solid #1e293b',
    padding: '10px 14px',
    color: '#64748b',
    fontWeight: 600,
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  },
  tr: {
    borderBottom: '1px solid #1e293b',
    transition: 'background-color 0.15s',
  },
  td: {
    padding: '12px 14px',
    color: '#e2e8f0',
  },
  badge: {
    padding: '3px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 600,
  },
  checkTypeBadge: {
    backgroundColor: '#1e293b',
    color: '#38bdf8',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontFamily: 'monospace',
  },
  categoryBadge: {
    backgroundColor: '#1e293b',
    color: '#a78bfa',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 11,
  },
  actionBtnSmall: {
    backgroundColor: '#1e293b',
    color: '#38bdf8',
    border: '1px solid #334155',
    padding: '6px 12px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 500,
    cursor: 'pointer',
  },
  primaryBtn: {
    backgroundColor: '#2563eb',
    color: '#ffffff',
    border: 'none',
    padding: '8px 16px',
    borderRadius: 6,
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
  },
  textLinkBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    color: '#38bdf8',
    fontSize: 13,
    fontWeight: 500,
    cursor: 'pointer',
  },
  emptyNotice: {
    padding: 32,
    textAlign: 'center',
    color: '#64748b',
    fontSize: 14,
  },
  subText: {
    fontSize: 11,
    color: '#94a3b8',
    display: 'block',
    marginTop: 2,
  },

  // --- Scan Detail ---
  scanDetailContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
  },
  detailHeaderBox: {
    backgroundColor: '#0f172a',
    borderRadius: 12,
    padding: 24,
    border: '1px solid #1e293b',
  },
  detailBreadcrumbRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginBottom: 8,
  },
  backBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    color: '#38bdf8',
    cursor: 'pointer',
    fontSize: 13,
    padding: 0,
  },
  detailTitleRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    flexWrap: 'wrap',
    gap: 16,
  },
  targetMetaPillRow: {
    display: 'flex',
    gap: 14,
    fontSize: 13,
    color: '#94a3b8',
    marginTop: 4,
  },
  exportButtonGroup: {
    display: 'flex',
    gap: 8,
    flexWrap: 'wrap',
  },
  reportExportBtn: {
    backgroundColor: '#2563eb',
    color: '#ffffff',
    textDecoration: 'none',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  statsGaugeRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: 12,
    marginTop: 20,
    borderTop: '1px solid #1e293b',
    paddingTop: 16,
  },
  gaugeCard: {
    backgroundColor: '#1e293b',
    padding: '14px 18px',
    borderRadius: 8,
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  gaugeLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#94a3b8',
    letterSpacing: '0.6px',
  },
  filterBar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 16,
    flexWrap: 'wrap',
  },
  filterPillsGroup: {
    display: 'flex',
    gap: 8,
  },
  filterPill: {
    backgroundColor: '#0f172a',
    border: '1px solid #1e293b',
    color: '#94a3b8',
    padding: '6px 14px',
    borderRadius: 6,
    fontSize: 12,
    cursor: 'pointer',
  },
  filterPillActive: {
    backgroundColor: '#2563eb',
    border: '1px solid #2563eb',
    color: '#ffffff',
    padding: '6px 14px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  searchInput: {
    backgroundColor: '#0f172a',
    border: '1px solid #1e293b',
    color: '#f8fafc',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 13,
    minWidth: 280,
  },
  findingsLayout: {
    display: 'flex',
    gap: 16,
    alignItems: 'flex-start',
  },
  inspectorDrawer: {
    flex: '1 1 45%',
    backgroundColor: '#0f172a',
    border: '1px solid #334155',
    borderRadius: 10,
    padding: 20,
    position: 'sticky',
    top: 20,
  },
  inspectorHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderBottom: '1px solid #1e293b',
    paddingBottom: 14,
  },
  closeDrawerBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    color: '#94a3b8',
    fontSize: 16,
    cursor: 'pointer',
  },
  inspectorBody: {
    marginTop: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 16,
  },
  inspectorSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  boxHeaderRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  boxTitle: {
    fontSize: 11,
    fontWeight: 700,
    color: '#94a3b8',
    letterSpacing: '0.6px',
  },
  copyBtn: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    color: '#38bdf8',
    padding: '3px 8px',
    borderRadius: 4,
    fontSize: 11,
    cursor: 'pointer',
  },
  terminalPre: {
    backgroundColor: '#030712',
    border: '1px solid #1f2937',
    padding: 14,
    borderRadius: 6,
    color: '#a7f3d0',
    fontSize: 12,
    fontFamily: 'monospace',
    overflowX: 'auto',
    maxHeight: 260,
    whiteSpace: 'pre-wrap',
  },
  criteriaBox: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    padding: 12,
    borderRadius: 6,
    color: '#cbd5e1',
    fontSize: 12,
  },

  // --- Form Layout ---
  formContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
    marginTop: 16,
  },
  formSectionBox: {
    backgroundColor: '#111827',
    borderRadius: 10,
    padding: 20,
    border: '1px solid #1f2937',
  },
  stepLabel: {
    fontSize: 11,
    fontWeight: 700,
    color: '#60a5fa',
    letterSpacing: '0.8px',
    display: 'block',
    marginBottom: 12,
  },
  stepHeaderRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
  },
  protocolCardGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: 12,
  },
  protocolSelectCard: {
    borderRadius: 8,
    padding: '16px 14px',
    cursor: 'pointer',
    border: '1px solid #1e293b',
    transition: 'all 0.15s',
    textAlign: 'center',
  },
  inputGrid2: {
    display: 'grid',
    gridTemplateColumns: '1fr 120px',
    gap: 12,
    marginBottom: 12,
  },
  inputGrid3: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr 1fr',
    gap: 12,
  },
  fieldGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  fieldLabel: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: 500,
  },
  textInput: {
    backgroundColor: '#090d16',
    border: '1px solid #334155',
    color: '#f8fafc',
    padding: '10px 14px',
    borderRadius: 6,
    fontSize: 13,
    outline: 'none',
  },
  selectInput: {
    width: '100%',
    backgroundColor: '#090d16',
    border: '1px solid #334155',
    color: '#f8fafc',
    padding: 10,
    borderRadius: 6,
    fontSize: 13,
  },
  selectOption: {
    padding: '8px 12px',
    backgroundColor: '#090d16',
    color: '#f8fafc',
  },
  profileToggle: {
    display: 'flex',
    backgroundColor: '#090d16',
    borderRadius: 6,
    border: '1px solid #334155',
    padding: 2,
  },
  profileToggleBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    color: '#94a3b8',
    padding: '4px 12px',
    borderRadius: 4,
    fontSize: 12,
    cursor: 'pointer',
  },
  profileToggleBtnActive: {
    backgroundColor: '#2563eb',
    border: 'none',
    color: '#ffffff',
    padding: '4px 12px',
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  launchSubmitBtn: {
    backgroundColor: '#10b981',
    color: '#ffffff',
    border: 'none',
    padding: '14px 28px',
    borderRadius: 8,
    fontSize: 15,
    fontWeight: 700,
    cursor: 'pointer',
    boxShadow: '0 4px 14px rgba(16, 185, 129, 0.4)',
  },

  // --- Remediation Grid ---
  remediationGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
    gap: 16,
  },
  remediationCard: {
    backgroundColor: '#111827',
    border: '1px solid #1f2937',
    borderRadius: 10,
    padding: 18,
    display: 'flex',
    flexDirection: 'column',
    gap: 14,
  },
  remediationCardHeader: {
    borderBottom: '1px solid #1e293b',
    paddingBottom: 10,
  },
  downloadRow: {
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
  playbookBtnAnsible: {
    backgroundColor: '#064e3b',
    color: '#34d399',
    textDecoration: 'none',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    textAlign: 'center',
    border: '1px solid #059669',
  },
  playbookBtnPowerShell: {
    backgroundColor: '#0c4a6e',
    color: '#38bdf8',
    textDecoration: 'none',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    textAlign: 'center',
    border: '1px solid #0284c7',
  },
  playbookBtnBash: {
    backgroundColor: '#3b0764',
    color: '#c084fc',
    textDecoration: 'none',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 12,
    fontWeight: 600,
    textAlign: 'center',
    border: '1px solid #7c3aed',
  },
}
