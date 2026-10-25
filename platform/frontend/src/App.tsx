import React, { useEffect, useState } from 'react'

interface Check {
  type: string
  command?: string
  expected?: string
  regex?: string
  path?: string
  severity?: string
  info?: string
}

interface Control {
  id: string
  title: string
  description?: string
  rationale?: string
  remediation?: string
  scoring?: string
  profile?: string[]
  checks?: Check[]
}

interface Benchmark {
  id: string
  title: string
  version: string
  technology: string
  os: string
  controls: Control[]
}

interface ScanResult {
  control_id: string
  check_type: string
  status: 'pass' | 'fail' | 'error' | 'skipped'
  actual: string
  expected: string
  evidence: string
  error?: string
  duration_ms: number
}

interface ScanJob {
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
  }
  results?: ScanResult[]
  created_at: string
  finished_at?: string
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'scans' | 'new_scan' | 'benchmarks' | 'upload'>('scans')
  const [benchmarks, setBenchmarks] = useState<Benchmark[]>([])
  const [scans, setScans] = useState<ScanJob[]>([])
  const [selectedScan, setSelectedScan] = useState<ScanJob | null>(null)
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [backendHealth, setBackendHealth] = useState<boolean>(false)

  // New Scan Form State
  const [targetHost, setTargetHost] = useState('127.0.0.1')
  const [targetPort, setTargetPort] = useState('22')
  const [protocol, setProtocol] = useState<'ssh' | 'winrm'>('ssh')
  const [targetUser, setTargetUser] = useState('root')
  const [targetPassword, setTargetPassword] = useState('')
  const [targetKeyPath, setTargetKeyPath] = useState('')
  const [selectedBenchmarkId, setSelectedBenchmarkId] = useState('')
  const [selectedProfile, setSelectedProfile] = useState('level1')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [uploadMsg, setUploadMsg] = useState('')

  // Fetch initial data
  const fetchData = async () => {
    try {
      const hRes = await fetch('/health')
      if (hRes.ok) setBackendHealth(true)

      const bRes = await fetch('/api/v1/benchmarks')
      if (bRes.ok) {
        const bData = await bRes.json()
        setBenchmarks(bData || [])
        if (!selectedBenchmarkId && bData && bData.length > 0) {
          setSelectedBenchmarkId(bData[0].id)
        }
      }

      const sRes = await fetch('/api/v1/scans')
      if (sRes.ok) {
        const sData = await sRes.json()
        setScans(sData || [])
        // If current selected scan exists, update it
        if (selectedScan) {
          const updated = (sData || []).find((s: ScanJob) => s.id === selectedScan.id)
          if (updated) setSelectedScan(updated)
        }
      }
    } catch (err) {
      setBackendHealth(false)
    }
  }

  useEffect(() => {
    fetchData()
    const timer = setInterval(fetchData, 3000)
    return () => clearInterval(timer)
  }, [selectedScan?.id])

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedBenchmarkId) {
      alert('Please select or upload a CIS benchmark first.')
      return
    }
    setIsSubmitting(true)
    try {
      const payload = {
        benchmark_id: selectedBenchmarkId,
        profile: selectedProfile,
        asset: {
          host: targetHost,
          port: parseInt(targetPort, 10) || (protocol === 'winrm' ? 5985 : 22),
          protocol: protocol,
          type: protocol === 'winrm' ? 'windows' : 'linux',
          user: targetUser,
          password: targetPassword,
          key_path: targetKeyPath,
        },
      }
      const res = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (res.ok) {
        const newJob = await res.json()
        setSelectedScan(newJob)
        setActiveTab('scans')
        fetchData()
      } else {
        const err = await res.json()
        alert(`Error starting scan: ${err.error || 'Unknown error'}`)
      }
    } catch (err: any) {
      alert(`Network error: ${err.message}`)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleUploadBenchmark = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    setUploadMsg('Uploading & transpiling benchmark...')
    try {
      const res = await fetch('/api/v1/benchmarks', {
        method: 'POST',
        body: formData,
      })
      if (res.ok) {
        const data = await res.json()
        setUploadMsg(`Successfully loaded benchmark: "${data.title}" with ${data.controls?.length || 0} controls`)
        fetchData()
      } else {
        const err = await res.json()
        setUploadMsg(`Upload failed: ${err.error || 'Parse error'}`)
      }
    } catch (err: any) {
      setUploadMsg(`Error: ${err.message}`)
    }
  }

  // Calculate scan statistics
  const getStats = (results: ScanResult[] = []) => {
    const total = results.length
    const pass = results.filter((r) => r.status === 'pass').length
    const fail = results.filter((r) => r.status === 'fail').length
    const error = results.filter((r) => r.status === 'error').length
    const score = total > 0 ? Math.round((pass / total) * 100) : 0
    return { total, pass, fail, error, score }
  }

  return (
    <div style={styles.container}>
      {/* Top Header */}
      <header style={styles.header}>
        <div style={styles.logoGroup}>
          <div style={styles.badgeShield}>HX</div>
          <div>
            <h1 style={styles.title}>HardenX</h1>
            <p style={styles.subtitle}>OpenCompliance CIS Benchmark Audit Engine</p>
          </div>
        </div>
        <div style={styles.headerRight}>
          <span style={{ ...styles.healthBadge, backgroundColor: backendHealth ? '#10b981' : '#ef4444' }}>
            {backendHealth ? '● Engine Online' : '● Engine Disconnected'}
          </span>
          <nav style={styles.nav}>
            <button
              style={activeTab === 'scans' ? styles.navActive : styles.navBtn}
              onClick={() => setActiveTab('scans')}
            >
              Audit Scans ({scans.length})
            </button>
            <button
              style={activeTab === 'new_scan' ? styles.navActive : styles.navBtn}
              onClick={() => setActiveTab('new_scan')}
            >
              + New Audit
            </button>
            <button
              style={activeTab === 'benchmarks' ? styles.navActive : styles.navBtn}
              onClick={() => setActiveTab('benchmarks')}
            >
              Benchmarks ({benchmarks.length})
            </button>
            <button
              style={activeTab === 'upload' ? styles.navActive : styles.navBtn}
              onClick={() => setActiveTab('upload')}
            >
              Upload Rule
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={styles.main}>
        {/* TAB 1: SCANS LIST & DETAIL */}
        {activeTab === 'scans' && (
          <div style={styles.scanLayout}>
            {/* Left list of scans */}
            <div style={styles.scanSidebar}>
              <div style={styles.sidebarHeader}>
                <h3 style={{ margin: 0, fontSize: 16 }}>Audit History</h3>
                <button
                  style={styles.refreshBtn}
                  onClick={() => fetchData()}
                >
                  ↻
                </button>
              </div>
              {scans.length === 0 ? (
                <div style={styles.emptyState}>
                  <p>No compliance audits yet.</p>
                  <button
                    style={styles.actionBtn}
                    onClick={() => setActiveTab('new_scan')}
                  >
                    Launch First Audit
                  </button>
                </div>
              ) : (
                <div style={styles.scanList}>
                  {scans.map((s) => {
                    const stats = getStats(s.results)
                    const isSelected = selectedScan?.id === s.id
                    return (
                      <div
                        key={s.id}
                        onClick={() => setSelectedScan(s)}
                        style={{
                          ...styles.scanCard,
                          borderColor: isSelected ? '#3b82f6' : '#27272a',
                          backgroundColor: isSelected ? '#182234' : '#18181b',
                        }}
                      >
                        <div style={styles.cardRow}>
                          <span style={styles.targetHost}>{s.asset?.host || 'Unknown Target'}</span>
                          <span
                            style={{
                              ...styles.statusTag,
                              backgroundColor:
                                s.status === 'completed' ? '#065f46' : s.status === 'running' ? '#1e40af' : '#7f1d1d',
                            }}
                          >
                            {s.status.toUpperCase()}
                          </span>
                        </div>
                        <div style={styles.cardSub}>
                          <span>{s.benchmark_id}</span>
                          <span style={{ fontWeight: 600, color: stats.score > 70 ? '#34d399' : '#f87171' }}>
                            {stats.score}%
                          </span>
                        </div>
                        <div style={styles.cardTime}>{new Date(s.created_at).toLocaleString()}</div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Right details of selected scan */}
            <div style={styles.scanDetail}>
              {selectedScan ? (
                <div>
                  <div style={styles.detailHeader}>
                    <div>
                      <h2 style={{ margin: '0 0 4px 0' }}>Audit Report: {selectedScan.asset?.host}</h2>
                      <div style={styles.metaRow}>
                        <span>Benchmark: <b>{selectedScan.benchmark_id}</b></span>
                        <span>Profile: <b>{selectedScan.profile}</b></span>
                        <span>Protocol: <b>{selectedScan.asset?.protocol?.toUpperCase() || 'SSH'}</b></span>
                        <span>Status: <b style={{ textTransform: 'capitalize' }}>{selectedScan.status}</b></span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 10 }}>
                      <a
                        href={`/api/v1/scans/${selectedScan.id}/report`}
                        target="_blank"
                        rel="noreferrer"
                        style={styles.reportBtn}
                      >
                        Open Nessus HTML Report ↗
                      </a>
                    </div>
                  </div>

                  {/* Summary Metric Counters */}
                  {(() => {
                    const stats = getStats(selectedScan.results)
                    return (
                      <div style={styles.statsGrid}>
                        <div style={{ ...styles.statBox, borderColor: '#3b82f6' }}>
                          <span style={styles.statLabel}>Compliance Score</span>
                          <span style={{ ...styles.statVal, color: stats.score > 70 ? '#34d399' : '#f87171' }}>
                            {stats.score}%
                          </span>
                        </div>
                        <div style={{ ...styles.statBox, borderColor: '#10b981' }}>
                          <span style={styles.statLabel}>Passed Checks</span>
                          <span style={{ ...styles.statVal, color: '#10b981' }}>{stats.pass}</span>
                        </div>
                        <div style={{ ...styles.statBox, borderColor: '#ef4444' }}>
                          <span style={styles.statLabel}>Failed Checks</span>
                          <span style={{ ...styles.statVal, color: '#ef4444' }}>{stats.fail}</span>
                        </div>
                        <div style={{ ...styles.statBox, borderColor: '#f59e0b' }}>
                          <span style={styles.statLabel}>Errors / Skipped</span>
                          <span style={{ ...styles.statVal, color: '#f59e0b' }}>{stats.error}</span>
                        </div>
                      </div>
                    )
                  })()}

                  {/* Filter Toolbar */}
                  <div style={styles.filterBar}>
                    <div style={{ display: 'flex', gap: 8 }}>
                      {['all', 'fail', 'pass', 'error'].map((st) => (
                        <button
                          key={st}
                          onClick={() => setFilterStatus(st)}
                          style={{
                            ...styles.pillBtn,
                            backgroundColor: filterStatus === st ? '#3b82f6' : '#27272a',
                          }}
                        >
                          {st.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <input
                      type="text"
                      placeholder="Search control ID or evidence..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      style={styles.searchInput}
                    />
                  </div>

                  {/* Results List */}
                  <div style={styles.resultsContainer}>
                    {(selectedScan.results || [])
                      .filter((r) => filterStatus === 'all' || r.status === filterStatus)
                      .filter(
                        (r) =>
                          !searchQuery ||
                          r.control_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          r.evidence.toLowerCase().includes(searchQuery.toLowerCase())
                      )
                      .map((r, i) => (
                        <details key={i} style={styles.resultItem}>
                          <summary style={styles.resultSummary}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                              <span
                                style={{
                                  ...styles.badge,
                                  backgroundColor:
                                    r.status === 'pass'
                                      ? '#10b981'
                                      : r.status === 'fail'
                                      ? '#ef4444'
                                      : '#f59e0b',
                                }}
                              >
                                {r.status.toUpperCase()}
                              </span>
                              <span style={{ fontWeight: 600 }}>{r.control_id}</span>
                              <span style={{ color: '#9ca3af', fontSize: 13 }}>[{r.check_type}]</span>
                            </div>
                            <span style={{ fontSize: 12, color: '#6b7280' }}>{r.duration_ms} ms</span>
                          </summary>
                          <div style={styles.evidenceBody}>
                            {r.error && (
                              <div style={styles.errorNotice}>
                                <b>Error:</b> {r.error}
                              </div>
                            )}
                            <div style={styles.codeBlock}>
                              <div style={styles.codeTitle}>Audit Evidence & Execution Log:</div>
                              <pre style={styles.pre}>{r.evidence || 'No output recorded.'}</pre>
                            </div>
                            {r.expected && (
                              <div style={{ marginTop: 8, fontSize: 13 }}>
                                <span style={{ color: '#9ca3af' }}>Expected Match: </span>
                                <code style={styles.inlineCode}>{r.expected}</code>
                              </div>
                            )}
                          </div>
                        </details>
                      ))}
                  </div>
                </div>
              ) : (
                <div style={styles.emptyState}>
                  <h3>Select an audit scan from the left to inspect findings and evidence.</h3>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: NEW SCAN FORM */}
        {activeTab === 'new_scan' && (
          <div style={styles.formContainer}>
            <h2 style={{ marginTop: 0 }}>Launch CIS Compliance Scan</h2>
            <p style={{ color: '#9ca3af', marginBottom: 24 }}>
              Execute agentless remote compliance audits against Linux or Windows assets using SSH or WinRM.
            </p>

            <form onSubmit={handleLaunchScan} style={styles.form}>
              <div style={styles.formSection}>
                <h3 style={styles.sectionHeading}>1. Target Specifications</h3>
                <div style={styles.formRow}>
                  <div style={styles.formField}>
                    <label style={styles.label}>Protocol / Target OS</label>
                    <select
                      value={protocol}
                      onChange={(e) => {
                        const val = e.target.value as 'ssh' | 'winrm'
                        setProtocol(val)
                        setTargetPort(val === 'winrm' ? '5985' : '22')
                        if (val === 'winrm' && targetUser === 'root') setTargetUser('Administrator')
                      }}
                      style={styles.input}
                    >
                      <option value="ssh">Linux / Unix (SSH - Port 22)</option>
                      <option value="winrm">Windows Server (WinRM - Port 5985/5986)</option>
                    </select>
                  </div>
                  <div style={styles.formField}>
                    <label style={styles.label}>Host / IP Address</label>
                    <input
                      type="text"
                      required
                      value={targetHost}
                      onChange={(e) => setTargetHost(e.target.value)}
                      style={styles.input}
                      placeholder="192.168.1.100"
                    />
                  </div>
                  <div style={{ ...styles.formField, maxWidth: 100 }}>
                    <label style={styles.label}>Port</label>
                    <input
                      type="number"
                      required
                      value={targetPort}
                      onChange={(e) => setTargetPort(e.target.value)}
                      style={styles.input}
                    />
                  </div>
                </div>
              </div>

              <div style={styles.formSection}>
                <h3 style={styles.sectionHeading}>2. Authentication Credentials</h3>
                <div style={styles.formRow}>
                  <div style={styles.formField}>
                    <label style={styles.label}>Username</label>
                    <input
                      type="text"
                      required
                      value={targetUser}
                      onChange={(e) => setTargetUser(e.target.value)}
                      style={styles.input}
                    />
                  </div>
                  <div style={styles.formField}>
                    <label style={styles.label}>Password (or WinRM Password)</label>
                    <input
                      type="password"
                      value={targetPassword}
                      onChange={(e) => setTargetPassword(e.target.value)}
                      style={styles.input}
                      placeholder="••••••••"
                    />
                  </div>
                  {protocol === 'ssh' && (
                    <div style={styles.formField}>
                      <label style={styles.label}>Private Key Path (Optional)</label>
                      <input
                        type="text"
                        value={targetKeyPath}
                        onChange={(e) => setTargetKeyPath(e.target.value)}
                        style={styles.input}
                        placeholder="/Users/nestho/.ssh/id_rsa"
                      />
                    </div>
                  )}
                </div>
              </div>

              <div style={styles.formSection}>
                <h3 style={styles.sectionHeading}>3. Benchmark Selection</h3>
                <div style={styles.formRow}>
                  <div style={styles.formField}>
                    <label style={styles.label}>Select CIS Benchmark</label>
                    <select
                      value={selectedBenchmarkId}
                      onChange={(e) => setSelectedBenchmarkId(e.target.value)}
                      style={styles.input}
                    >
                      {benchmarks.map((b) => (
                        <option key={b.id} value={b.id}>
                          {b.title} (v{b.version}) - {b.controls?.length || 0} checks
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={styles.formField}>
                    <label style={styles.label}>Audit Profile</label>
                    <select
                      value={selectedProfile}
                      onChange={(e) => setSelectedProfile(e.target.value)}
                      style={styles.input}
                    >
                      <option value="level1">Level 1 - General Hardening (Recommended)</option>
                      <option value="level2">Level 2 - High Security / Defense-in-Depth</option>
                    </select>
                  </div>
                </div>
              </div>

              <button type="submit" disabled={isSubmitting} style={styles.submitBtn}>
                {isSubmitting ? 'Dispatching Scan...' : '▶ Launch Compliance Scan'}
              </button>
            </form>
          </div>
        )}

        {/* TAB 3: BENCHMARKS LIBRARY */}
        {activeTab === 'benchmarks' && (
          <div>
            <div style={styles.libHeader}>
              <div>
                <h2 style={{ margin: '0 0 6px 0' }}>Loaded Benchmark Profiles</h2>
                <p style={{ color: '#9ca3af', margin: 0 }}>
                  Active CIS & Nessus audit definitions registered in the HardenX engine.
                </p>
              </div>
              <button
                style={styles.actionBtn}
                onClick={() => setActiveTab('upload')}
              >
                + Import Custom Benchmark
              </button>
            </div>

            <div style={styles.benchGrid}>
              {benchmarks.map((b) => (
                <div key={b.id} style={styles.benchCard}>
                  <div style={styles.benchHeader}>
                    <h3 style={{ margin: '0 0 6px 0', fontSize: 18 }}>{b.title}</h3>
                    <span style={styles.techBadge}>{b.technology || 'General'}</span>
                  </div>
                  <p style={{ color: '#9ca3af', fontSize: 14 }}>
                    Version: <b>{b.version}</b> | OS: <b>{b.os || 'Universal'}</b>
                  </p>
                  <p style={{ fontSize: 14, color: '#38bdf8' }}>
                    Controls / Audit Items: <b>{b.controls?.length || 0}</b>
                  </p>
                  <div style={{ marginTop: 12 }}>
                    <button
                      style={styles.smallBtn}
                      onClick={() => {
                        setSelectedBenchmarkId(b.id)
                        setActiveTab('new_scan')
                      }}
                    >
                      Audit With This Benchmark →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: UPLOAD BENCHMARK */}
        {activeTab === 'upload' && (
          <div style={styles.formContainer}>
            <h2 style={{ marginTop: 0 }}>Import Benchmark or Tenable .audit File</h2>
            <p style={{ color: '#9ca3af', marginBottom: 24 }}>
              HardenX natively parses both Tenable Nessus <code>.audit</code> files and Canonical CIS <code>.yaml</code> audit specifications.
            </p>

            <div style={styles.dropZone}>
              <div style={{ fontSize: 36, marginBottom: 12 }}>📄</div>
              <h3>Choose a .audit or .yaml file to import</h3>
              <p style={{ color: '#6b7280', fontSize: 14 }}>Transpiled directly into engine registry.</p>
              <input
                type="file"
                accept=".audit,.yaml,.yml"
                onChange={handleUploadBenchmark}
                style={{ marginTop: 12 }}
              />
              {uploadMsg && (
                <div style={styles.uploadFeedback}>
                  {uploadMsg}
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#09090b',
    color: '#f4f4f5',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    display: 'flex',
    flexDirection: 'column',
  },
  header: {
    padding: '16px 32px',
    borderBottom: '1px solid #27272a',
    backgroundColor: '#111113',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  logoGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: 14,
  },
  badgeShield: {
    width: 40,
    height: 40,
    borderRadius: 8,
    backgroundColor: '#2563eb',
    color: '#fff',
    fontWeight: 800,
    fontSize: 18,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 0 16px rgba(37,99,235,0.4)',
  },
  title: {
    margin: 0,
    fontSize: 20,
    fontWeight: 700,
    letterSpacing: '-0.02em',
  },
  subtitle: {
    margin: 0,
    fontSize: 12,
    color: '#a1a1aa',
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: 20,
  },
  healthBadge: {
    padding: '4px 10px',
    borderRadius: 12,
    fontSize: 12,
    fontWeight: 600,
    color: '#ffffff',
  },
  nav: {
    display: 'flex',
    gap: 6,
    backgroundColor: '#18181b',
    padding: 4,
    borderRadius: 8,
  },
  navBtn: {
    background: 'none',
    border: 'none',
    color: '#a1a1aa',
    padding: '8px 14px',
    borderRadius: 6,
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: 500,
  },
  navActive: {
    backgroundColor: '#27272a',
    border: 'none',
    color: '#ffffff',
    padding: '8px 14px',
    borderRadius: 6,
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: 600,
  },
  main: {
    flex: 1,
    padding: '24px 32px',
  },
  scanLayout: {
    display: 'grid',
    gridTemplateColumns: '320px 1fr',
    gap: 24,
    minHeight: '75vh',
  },
  scanSidebar: {
    backgroundColor: '#111113',
    borderRadius: 8,
    border: '1px solid #27272a',
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
  },
  sidebarHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingBottom: 12,
    borderBottom: '1px solid #27272a',
    marginBottom: 12,
  },
  refreshBtn: {
    background: '#27272a',
    border: 'none',
    color: '#fff',
    borderRadius: 4,
    padding: '4px 8px',
    cursor: 'pointer',
  },
  scanList: {
    overflowY: 'auto',
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
  scanCard: {
    padding: 12,
    borderRadius: 6,
    border: '1px solid #27272a',
    cursor: 'pointer',
    transition: 'border-color 0.2s',
  },
  cardRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  targetHost: {
    fontWeight: 600,
    fontSize: 14,
  },
  statusTag: {
    fontSize: 10,
    fontWeight: 700,
    padding: '2px 6px',
    borderRadius: 4,
    color: '#fff',
  },
  cardSub: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: 12,
    color: '#9ca3af',
  },
  cardTime: {
    fontSize: 11,
    color: '#6b7280',
    marginTop: 4,
  },
  scanDetail: {
    backgroundColor: '#111113',
    borderRadius: 8,
    border: '1px solid #27272a',
    padding: 24,
  },
  detailHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    borderBottom: '1px solid #27272a',
    paddingBottom: 16,
    marginBottom: 20,
  },
  metaRow: {
    display: 'flex',
    gap: 16,
    fontSize: 13,
    color: '#9ca3af',
    marginTop: 6,
  },
  reportBtn: {
    backgroundColor: '#2563eb',
    color: '#fff',
    textDecoration: 'none',
    padding: '8px 14px',
    borderRadius: 6,
    fontSize: 13,
    fontWeight: 600,
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: 12,
    marginBottom: 20,
  },
  statBox: {
    backgroundColor: '#18181b',
    border: '1px solid #27272a',
    borderRadius: 6,
    padding: 14,
    display: 'flex',
    flexDirection: 'column',
  },
  statLabel: {
    fontSize: 12,
    color: '#9ca3af',
    marginBottom: 4,
  },
  statVal: {
    fontSize: 24,
    fontWeight: 800,
  },
  filterBar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  pillBtn: {
    border: 'none',
    color: '#fff',
    padding: '6px 12px',
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  searchInput: {
    backgroundColor: '#18181b',
    border: '1px solid #27272a',
    color: '#fff',
    padding: '6px 12px',
    borderRadius: 6,
    fontSize: 13,
    width: 240,
  },
  resultsContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
    maxHeight: '500px',
    overflowY: 'auto',
  },
  resultItem: {
    backgroundColor: '#18181b',
    borderRadius: 6,
    border: '1px solid #27272a',
    overflow: 'hidden',
  },
  resultSummary: {
    padding: 12,
    cursor: 'pointer',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  badge: {
    padding: '3px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    color: '#fff',
  },
  evidenceBody: {
    padding: '12px 16px',
    borderTop: '1px solid #27272a',
    backgroundColor: '#141416',
  },
  errorNotice: {
    backgroundColor: '#450a0a',
    border: '1px solid #dc2626',
    padding: 8,
    borderRadius: 4,
    color: '#fca5a5',
    marginBottom: 8,
    fontSize: 13,
  },
  codeBlock: {
    backgroundColor: '#09090b',
    borderRadius: 4,
    border: '1px solid #27272a',
    padding: 10,
  },
  codeTitle: {
    fontSize: 11,
    color: '#71717a',
    marginBottom: 4,
  },
  pre: {
    margin: 0,
    fontFamily: 'monospace',
    fontSize: 12,
    color: '#e4e4e7',
    whiteSpace: 'pre-wrap',
  },
  inlineCode: {
    backgroundColor: '#27272a',
    padding: '2px 6px',
    borderRadius: 4,
    fontFamily: 'monospace',
    color: '#38bdf8',
  },
  formContainer: {
    maxWidth: 750,
    margin: '0 auto',
    backgroundColor: '#111113',
    borderRadius: 8,
    border: '1px solid #27272a',
    padding: 32,
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: 24,
  },
  formSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  sectionHeading: {
    margin: 0,
    fontSize: 15,
    color: '#38bdf8',
    borderBottom: '1px solid #27272a',
    paddingBottom: 6,
  },
  formRow: {
    display: 'flex',
    gap: 16,
  },
  formField: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: 6,
  },
  label: {
    fontSize: 13,
    color: '#a1a1aa',
    fontWeight: 500,
  },
  input: {
    backgroundColor: '#18181b',
    border: '1px solid #27272a',
    color: '#fff',
    padding: '10px 12px',
    borderRadius: 6,
    fontSize: 14,
  },
  submitBtn: {
    backgroundColor: '#2563eb',
    color: '#fff',
    border: 'none',
    padding: '12px 20px',
    borderRadius: 6,
    fontSize: 15,
    fontWeight: 700,
    cursor: 'pointer',
    marginTop: 8,
  },
  libHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 24,
  },
  actionBtn: {
    backgroundColor: '#2563eb',
    color: '#fff',
    border: 'none',
    padding: '8px 16px',
    borderRadius: 6,
    fontWeight: 600,
    cursor: 'pointer',
  },
  benchGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
    gap: 16,
  },
  benchCard: {
    backgroundColor: '#111113',
    border: '1px solid #27272a',
    borderRadius: 8,
    padding: 20,
  },
  benchHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  techBadge: {
    backgroundColor: '#1e293b',
    color: '#94a3b8',
    padding: '2px 8px',
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 600,
  },
  smallBtn: {
    backgroundColor: '#27272a',
    color: '#fff',
    border: 'none',
    padding: '6px 12px',
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  dropZone: {
    border: '2px dashed #3f3f46',
    borderRadius: 8,
    padding: 40,
    textAlign: 'center',
  },
  uploadFeedback: {
    marginTop: 16,
    backgroundColor: '#064e3b',
    color: '#6ee7b7',
    padding: 10,
    borderRadius: 6,
    fontSize: 14,
  },
  emptyState: {
    padding: 32,
    textAlign: 'center',
    color: '#71717a',
  },
}
