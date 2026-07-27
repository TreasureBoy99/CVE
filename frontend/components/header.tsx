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

const SEV_STATS = [
  { key: 'critical', label: 'Critical', icon: '!!', desc: '9.0–10.0' },
  { key: 'high',     label: 'High',     icon: '!',  desc: '7.0–8.9'   },
  { key: 'medium',   label: 'Medium',   icon: '~',  desc: '4.0–6.9'   },
  { key: 'low',      label: 'Low',      icon: '-',  desc: '0.1–3.9'   },
  { key: 'none',     label: 'N/A',      icon: '?',  desc: '无评分'    },
] as const

export function Header({ totalCount, lastUpdated, distribution }: HeaderProps) {
  const updateDate = lastUpdated
    ? new Date(lastUpdated).toLocaleString('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      })
    : '-'

  return (
    <div className="space-y-6">
      {/* Title row */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="space-y-1">
          <h1 className="text-4xl font-black tracking-tight bg-gradient-to-r from-primary to-blue-500 bg-clip-text text-transparent">
            CVE 漏洞情报
          </h1>
          <p className="text-muted-foreground text-sm">
            近 7 天新增 / 更新记录 · 更新于 {updateDate}
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-primary/10 text-primary font-medium text-xs">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            实时监控
          </span>
          <span className="hidden sm:inline">Powered by NVD · CISA KEV · GitHub Advisory</span>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {SEV_STATS.map(({ key, label, icon, desc }) => {
          const value = distribution[key as keyof SeverityDistribution] ?? 0
          const colors: Record<string, string> = {
            critical: 'border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/20 hover:border-red-300',
            high:     'border-orange-200 dark:border-orange-900 bg-orange-50 dark:bg-orange-950/20 hover:border-orange-300',
            medium:   'border-yellow-200 dark:border-yellow-900 bg-yellow-50 dark:bg-yellow-950/20 hover:border-yellow-300',
            low:      'border-green-200 dark:border-green-900 bg-green-50 dark:bg-green-950/20 hover:border-green-300',
            none:     'border-slate-200 dark:border-slate-800 bg-muted/30 hover:border-slate-300',
          }
          const textColors: Record<string, string> = {
            critical: 'text-red-600 dark:text-red-400',
            high:     'text-orange-600 dark:text-orange-400',
            medium:   'text-yellow-600 dark:text-yellow-400',
            low:      'text-green-600 dark:text-green-400',
            none:     'text-slate-500',
          }
          return (
            <Card
              key={key}
              className={`${colors[key]} border cursor-default`}
            >
              <CardContent className="p-4 flex flex-col gap-0.5">
                <div className="flex items-center justify-between">
                  <span className={`text-xs font-bold uppercase tracking-widest ${textColors[key]}`}>
                    {label}
                  </span>
                  <span className={`text-lg font-black ${textColors[key]}`}>{value}</span>
                </div>
                <p className="text-[10px] text-muted-foreground">{desc}</p>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
