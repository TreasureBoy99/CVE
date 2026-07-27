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
      <div className="relative flex-1 w-full">
        <svg
          className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground pointer-events-none"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <Input
          placeholder="搜索 CVE ID 或描述..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-9 w-full"
        />
      </div>

      <div className="flex gap-2 items-center flex-wrap">
        <select
          value={severityFilter}
          onChange={(e) => onSeverityChange(e.target.value)}
          className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        >
          <option value="all">全部严重性</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="none">N/A</option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => onSortChange(e.target.value)}
          className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
        >
          <option value="severity">按严重性</option>
          <option value="date">按发布日期</option>
        </select>

        <label className="flex items-center gap-2 text-sm cursor-pointer select-none whitespace-nowrap">
          <input
            type="checkbox"
            checked={hasPoc}
            onChange={(e) => onPocChange(e.target.checked)}
            className="h-4 w-4 rounded border-input text-primary focus:ring-primary"
          />
          <span className="text-muted-foreground">有 PoC</span>
        </label>
      </div>
    </div>
  )
}
