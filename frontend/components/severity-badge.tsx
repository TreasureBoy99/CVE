import { Badge } from '@/components/ui/badge'

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

function getSeverityLevel(score: string | number): SeverityLevel {
  const s = typeof score === 'string' ? parseFloat(score) : score
  if (isNaN(s) || s === 0) return 'none'
  if (s >= 9.0) return 'critical'
  if (s >= 7.0) return 'high'
  if (s >= 4.0) return 'medium'
  return 'low'
}

function getSeverityLabel(score: string | number): string {
  const s = typeof score === 'string' ? parseFloat(score) : score
  if (isNaN(s) || s === 0) return 'N/A'
  if (s >= 9.0) return 'Critical'
  if (s >= 7.0) return 'High'
  if (s >= 4.0) return 'Medium'
  return 'Low'
}

interface SeverityBadgeProps {
  score: string | number
  showScore?: boolean
}

export function SeverityBadge({ score, showScore = true }: SeverityBadgeProps) {
  const level = getSeverityLevel(score)
  const label = showScore ? `${getSeverityLabel(score)} ${score !== 'N/A' && score !== 0 ? `(${score})` : ''}`.trim() : getSeverityLabel(score)
  return <Badge variant={level}>{label}</Badge>
}

export { getSeverityLevel, getSeverityLabel }
