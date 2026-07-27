import { Badge } from '@/components/ui/badge'

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

// Infer severity from CWE when CVSS score is unavailable (NVD not yet published)
function inferSeverityFromCWE(cweIds: string[]): SeverityLevel {
  const HIGH_IMPACT = [
    'CWE-89',  // SQL Injection
    'CWE-78',  // OS Command Injection
    'CWE-94',  // Code Injection
    'CWE-77',  // Command Injection
    'CWE-287', // Improper Authentication
    'CWE-306', // Missing Authentication
    'CWE-269', // Privilege Management
    'CWE-862', // Missing Authorization
    'CWE-863', // Incorrect Authorization
    'CWE-502', // Deserialization
    'CWE-94',  // Code Injection
    'CWE-434', // Unrestricted Upload
    'CWE-918', // SSRF
    'CWE-611', // XXE
    'CWE-352', // CSRF
    'CWE-200', // Information Disclosure
    'CWE-22',  // Path Traversal
  ]
  const MEDIUM_IMPACT = [
    'CWE-79',  // Cross-site Scripting (XSS)
    'CWE-190', // Integer Overflow
    'CWE-119', // Buffer Overflow
    'CWE-416', // Use After Free
    'CWE-476', // NULL Pointer Dereference
    'CWE-835', // Infinite Loop
    'CWE-400', // Resource Exhaustion
  ]

  for (const cwe of cweIds) {
    const base = cwe.split(' ')[0].trim()
    if (HIGH_IMPACT.some(h => base.includes(h))) return 'high'
  }
  for (const cwe of cweIds) {
    const base = cwe.split(' ')[0].trim()
    if (MEDIUM_IMPACT.some(m => base.includes(m))) return 'medium'
  }
  return 'low'
}

function getSeverityLevel(score: string | number, cweIds?: string[]): SeverityLevel {
  const s = typeof score === 'string' ? parseFloat(score) : score
  if (isNaN(s) || s === 0) {
    if (cweIds && cweIds.length > 0) {
      return inferSeverityFromCWE(cweIds)
    }
    return 'none'
  }
  if (s >= 9.0) return 'critical'
  if (s >= 7.0) return 'high'
  if (s >= 4.0) return 'medium'
  return 'low'
}

function getSeverityLabel(score: string | number, cweIds?: string[]): string {
  const s = typeof score === 'string' ? parseFloat(score) : score
  if (isNaN(s) || s === 0) {
    if (cweIds && cweIds.length > 0) {
      const level = inferSeverityFromCWE(cweIds)
      const labels: Record<SeverityLevel, string> = {
        critical: 'Critical', high: 'High', medium: 'Medium',
        low: 'Low', none: 'N/A',
      }
      return labels[level] + ' (inferred)'
    }
    return 'N/A'
  }
  if (s >= 9.0) return 'Critical'
  if (s >= 7.0) return 'High'
  if (s >= 4.0) return 'Medium'
  return 'Low'
}

interface SeverityBadgeProps {
  score: string | number
  showScore?: boolean
  cweIds?: string[]
}

export function SeverityBadge({ score, showScore = true, cweIds }: SeverityBadgeProps) {
  const level = getSeverityLevel(score, cweIds)
  const label = showScore
    ? `${getSeverityLabel(score, cweIds)}${score !== 'N/A' && score !== 0 && score !== '0' ? ` (${score})` : ''}`.trim()
    : getSeverityLabel(score, cweIds)
  return <Badge variant={level}>{label}</Badge>
}

export { getSeverityLevel, getSeverityLabel }
