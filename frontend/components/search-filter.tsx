import { Input } from '@/components/ui/input'

interface SearchFilterProps {
  search: string
  onSearchChange: (v: string) => void
  severityFilter: string
  onSeverityChange: (v: string) => void
  hasPoc: boolean
  onPocChange: (v: boolean) => void
  sortBy: string
  onSortChange: (v: string) => void
}

const SELECT_CLASS =
  "h-9 rounded-lg border border-input bg-background px-3 py-1.5 text-sm " +
  "focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary " +
  "transition-colors cursor-pointer hover:border-primary/50"

export function SearchFilter({
  search,
  onSearchChange,
  severityFilter,
  onSeverityChange,
  hasPoc,
  onPocChange,
  sortBy,
  onSortChange,
}: SearchFilterProps) {
  return (
    <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">

      {/* Search */}
      <div className="relative flex-1 w-full">
        <svg
          className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none"
          fill="none" stroke="currentColor" viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <Input
          placeholder="搜索 CVE ID / 描述 / 厂商 / 产品…"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-10 pr-4 h-10 rounded-xl border-muted-foreground/20 focus:border-primary/50 shadow-sm"
        />
        {search && (
          <button
            onClick={() => onSearchChange('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-2 items-center flex-wrap shrink-0">

        <select
          value={severityFilter}
          onChange={(e) => onSeverityChange(e.target.value)}
          className={SELECT_CLASS}
        >
          <option value="all">全部严重性</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🟢 Low</option>
          <option value="none">⚪ N/A</option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => onSortChange(e.target.value)}
          className={SELECT_CLASS}
        >
          <option value="severity">🔺 严重性</option>
          <option value="date">📅 发布日期</option>
        </select>

        <label className="flex items-center gap-2 text-sm cursor-pointer select-none whitespace-nowrap px-2 py-1.5 rounded-lg border border-transparent hover:bg-muted/50 transition-colors">
          <input
            type="checkbox"
            checked={hasPoc}
            onChange={(e) => onPocChange(e.target.checked)}
            className="h-4 w-4 rounded border-input text-red-500 focus:ring-red-500/30 cursor-pointer"
          />
          <span className="text-muted-foreground text-sm">有 PoC</span>
        </label>

      </div>
    </div>
  )
}
