import { useState, useEffect, useMemo } from 'react'
import { Header } from '@/components/header'
import { SearchFilter } from '@/components/search-filter'
import { CVECard } from '@/components/cve-card'
import { Skeleton } from '@/components/ui/skeleton'
import { getSeverityLevel } from '@/components/severity-badge'

interface Reference {
  url: string
  type: 'poc' | 'reference'
}

interface CVE {
  id: string
  publishedDate: string
  lastModifiedDate: string
  description: string
  severity: string
  fix_suggestion: string
  references: Reference[]
  problemType: string[]
  affected: {
    vendor: string
    product: string
    repo?: string
    versions: { status: string; version: string; lessThanOrEqual: string; versionType?: string }[]
    defaultStatus: string
  }[]
}

interface CVECache {
  dataType: string
  dataVersion: string
  cveMetadata: {
    total_count: number
    last_updated: string
    severity_distribution: {
      critical: number
      high: number
      medium: number
      low: number
      none: number
    }
  }
  cves: CVE[]
}

type SortKey = 'severity' | 'date'

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <svg
        className="w-16 h-16 text-muted-foreground/30 mb-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        />
      </svg>
      <h3 className="text-lg font-semibold text-foreground mb-1">暂无 CVE 数据</h3>
      <p className="text-sm text-muted-foreground max-w-sm">
        最近 7 天没有新增或更新的 CVE 漏洞记录，请稍后再查看。
      </p>
    </div>
  )
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <svg
        className="w-16 h-16 text-destructive/40 mb-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
      <h3 className="text-lg font-semibold text-destructive mb-1">加载失败</h3>
      <p className="text-sm text-muted-foreground max-w-sm">{message}</p>
    </div>
  )
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="rounded-xl border bg-card p-6 space-y-3">
          <div className="flex items-center gap-3">
            <Skeleton className="h-5 w-36" />
            <Skeleton className="h-5 w-16 rounded-full" />
          </div>
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <div className="flex gap-2">
            <Skeleton className="h-5 w-20 rounded-full" />
            <Skeleton className="h-5 w-28 rounded-full" />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Home() {
  const [data, setData] = useState<CVECache | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [hasPoc, setHasPoc] = useState(false)
  const [sortBy, setSortBy] = useState<SortKey>('severity')

  useEffect(() => {
    fetch('/CVE/cve_cache.json')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json()
      })
      .then((json: CVECache) => {
        setData(json)
        setLoading(false)
      })
      .catch((err) => {
        console.error('Failed to load CVE data:', err)
        setError(`加载数据失败: ${err.message}。请确认后端爬虫已运行并生成了 cve_cache.json。`)
        setLoading(false)
      })
  }, [])

  const filtered = useMemo(() => {
    if (!data?.cves) return []

    let result = data.cves.filter((cve) => {
      // search
      if (search) {
        const q = search.toLowerCase()
        const matchId = cve.id.toLowerCase().includes(q)
        const matchDesc = cve.description?.toLowerCase().includes(q)
        const matchVendor = cve.affected?.some(
          (a) => a.vendor.toLowerCase().includes(q) || a.product.toLowerCase().includes(q)
        )
        if (!matchId && !matchDesc && !matchVendor) return false
      }

      // severity filter
      if (severityFilter !== 'all') {
        const level = getSeverityLevel(cve.severity)
        if (level !== severityFilter) return false
      }

      // poc filter
      if (hasPoc) {
        if (!cve.references.some((r) => r.type === 'poc')) return false
      }

      return true
    })

    // sort
    result.sort((a, b) => {
      if (sortBy === 'severity') {
        const sa = parseFloat(a.severity) || 0
        const sb = parseFloat(b.severity) || 0
        if (sa !== sb) return sb - sa
        const da = new Date(a.publishedDate).getTime()
        const db = new Date(b.publishedDate).getTime()
        return db - da
      } else {
        const da = new Date(a.publishedDate).getTime()
        const db = new Date(b.publishedDate).getTime()
        return db - da
      }
    })

    return result
  }, [data, search, severityFilter, hasPoc, sortBy])

  if (loading) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-6xl">
        <div className="space-y-6 mb-8">
          <Skeleton className="h-9 w-48" />
          <Skeleton className="h-4 w-72" />
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
        <LoadingSkeleton />
      </div>
    )
  }

  if (error) {
    return (
      <div className="container mx-auto py-8 px-4 max-w-6xl">
        <ErrorState message={error} />
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8 px-4 max-w-6xl">
      <Header
        totalCount={data?.cveMetadata.total_count ?? 0}
        lastUpdated={data?.cveMetadata.last_updated ?? ''}
        distribution={data?.cveMetadata.severity_distribution ?? { critical: 0, high: 0, medium: 0, low: 0, none: 0 }}
      />

      <div className="mt-8">
        <SearchFilter
          search={search}
          onSearchChange={setSearch}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          hasPoc={hasPoc}
          onPocChange={setHasPoc}
          sortBy={sortBy}
          onSortChange={(v) => setSortBy(v as SortKey)}
        />
      </div>

      <div className="mt-6 space-y-4">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <p className="text-muted-foreground">
              {data?.cves.length === 0
                ? '暂无 CVE 数据'
                : '没有匹配的 CVE 记录，试试调整筛选条件'}
            </p>
          </div>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              共找到 <span className="font-semibold text-foreground">{filtered.length}</span> 条记录
            </p>
            {filtered.map((cve) => (
              <CVECard key={cve.id} cve={cve} />
            ))}
          </>
        )}
      </div>
    </div>
  )
}
