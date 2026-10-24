import { useEffect, useState } from 'react'

export default function App() {
  const [status, setStatus] = useState<string>('loading...')
  useEffect(() => {
    fetch('/health')
      .then((r) => r.json())
      .then((d) => setStatus(JSON.stringify(d)))
      .catch(() => setStatus('backend unreachable'))
  }, [])
  return (
    <div style={{ fontFamily: 'sans-serif', padding: 24 }}>
      <h1>OpenCompliance</h1>
      <p>Backend: {status}</p>
    </div>
  )
}
