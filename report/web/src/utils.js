export const formatDate = (d) => new Date(d).toLocaleString()

export const formatSize = (s) => {
  if (!s && s !== 0) return '-'
  if (s < 1024) return s + ' B'
  if (s < 1024 * 1024) return (s / 1024).toFixed(2) + ' KB'
  return (s / (1024 * 1024)).toFixed(2) + ' MB'
}

export const badgeClass = (v) => {
  const map = { clean: 'badge-clean', suspicious: 'badge-suspicious', malicious: 'badge-malicious' }
  return map[v] || 'badge-unknown'
}
