import { Card, CardContent } from '@/components/ui/card'

interface SeverityDistribution {
  critical: number
  high: number
  medium: number
  low: number
  none: number
}

interface HeaderProps {
  totalCount: number
  lastUpdated: string
  distribution: SeverityDistribution
}

export function Header({ totalCount, lastUpdated, distribution }: HeaderProps) {
  const stats = [
    { label: 'Critical', value: distribution.critical, color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900' },
    { label: 'High', value: distribution.high, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-900' },
    { label: 'Medium', value: distribution.medium, color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-900' },
    { label: 'Low', value: distribution.low, color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-900' },
    { label: 'N/A', value: distribution.none, color: 'text-slate-500', bg: 'bg-slate-50 dark:bg-slate-950/30 border-slate-200 dark:border-slate-800' },
  ]

  const updateDate = lastUpdated ? new Date(lastUpdated).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }) : '-'

  return (
    <div className="w-full space-y-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight">CVE 漏洞预警</h1>
        <p className="text-muted-foreground text-sm">
          最近 7 天新增/更新 · 共 <span className="font-semibold text-foreground">{totalCount}</span> 条记录 · 更新于 {updateDate}
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {stats.map(({ label, value, color, bg }) => (
          <Card key={label} className={`${bg} border`}>
            <CardContent className="p-4 flex flex-col gap-1">
              <span className={`text-xs font-medium uppercase tracking-wider ${color}`}>{label}</span>
              <span className={`text-2xl font-bold ${color}`}>{value}</span>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
