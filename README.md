# 🛡️ CVE Monitor

> 自动化 CVE 漏洞情报采集与可视化监控平台

**自动追踪 CVE 漏洞库，每日增量更新，支持 NVD / CISA KEV / GitHub Advisory 数据源，纯 Python 无付费依赖。**

---

## ✨ 功能特性

- 📡 **自动数据采集** — 每 5 分钟增量拉取 CVEProject delta 列表
- 🎨 **可视化前端** — 深/浅色主题、严重性分级统计、CVSS 评分、关键词搜索 + 过滤
- 🔗 **多数据源 Enrichment**
  - [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — 已知被利用漏洞标记
  - [NVD](https://nvd.nist.gov/) — CVSS 3.1 评分与向量
  - [GitHub Advisory Database](https://github.com/advisories) — PoC / Exploit 可用性
- 📝 **多模式 CLI**
  - `daily` — 近 N 天全量 CVE
  - `weekly` — 本周摘要报告（周一）
  - `poc` — PoC / CISA KEV 专项（周五）
  - `scan` — 按年份 / 关键词扫描
  - `diff` — 增量对比
- ⏰ **定时调度** — GitHub Actions 自动运行（周一/周三/周五/每 5 分钟）
- 🔄 **自动 Release** — 数据更新达到阈值时自动发布 GitHub Release

---

## 🗂️ 项目结构

```
CVE/
├── backend/
│   ├── cve_crawler.py      # CVEProject delta 爬虫
│   ├── analyzer.py          # NVD / CISA KEV / GitHub Advisory enrichment
│   └── utils/
│       └── logger.py        # 日志工具
├── frontend/               # Next.js 14 静态导出（SPA）
│   ├── pages/
│   │   └── index.tsx       # 主页面
│   ├── components/
│   │   ├── header.tsx       # 标题 + 严重性统计卡片
│   │   ├── cve-card.tsx     # CVE 单条展示卡片
│   │   ├── search-filter.tsx # 搜索 + 过滤工具栏
│   │   ├── severity-badge.tsx # 严重性徽章
│   │   └── theme-toggle.tsx  # 暗色模式切换
│   ├── styles/
│   │   └── globals.css      # Tailwind 主题 + 自定义样式
│   └── public/
│       └── cve_cache.json   # 静态 JSON（构建时生成）
├── scripts/
│   └── update_cves.py      # 统一 CLI 入口
├── data/
│   ├── cves.json            # 全量 CVE 数据
│   └── deltaLog.json        # 更新历史
├── .github/
│   ├── workflows/
│   │   ├── schedule.yml     # 定时调度（daily/weekly/poc/scan）
│   │   └── deploy-frontend.yml # 构建 + 部署 GitHub Pages
│   └── workflows/
│       └── release.yml      # 自动 Release
└── requirements.txt
```

---

## 🚀 快速开始

### 本地运行

```bash
# 克隆
git clone https://github.com/anonymous99-Rise/CVE.git
cd CVE

# 安装依赖
pip install -r requirements.txt

# 查看 CLI 帮助
python scripts/update_cves.py --help

# 获取近 7 天全量 CVE
python scripts/update_cves.py daily --days 7

# 只获取有 PoC 的 CVE
python scripts/update_cves.py poc --days 30

# 扫描 2026 年相关漏洞
python scripts/update_cves.py scan --year 2026 --keyword "remote code execution"
```

### 前端预览

```bash
cd frontend
npm install
npm run dev
# 访问 http://localhost:3000
```

---

## 🔧 配置

### GitHub Secrets（可选）

| Secret | 说明 |
|--------|------|
| `GITHUB_TOKEN` | 提升 GitHub API 速率限制（默认 60 req/h，开启后 5000 req/h） |
| `DEEPSEEK_API_KEY` | （已废弃，使用 NVD/CISA KEV 替代，无需配置） |

### GitHub Pages

仓库 Settings → Pages → Source: **Deploy from a branch** → Branch: **gh-pages / (root)**

---

## ⏰ 调度说明

| 时间 (UTC) | 任务 | 说明 |
|-----------|------|------|
| `*/5 * * * *` | `daily --no-enrich` | 每 5 分钟快速增量刷新 |
| `0 9 * * 1` | `weekly` | 周一完整周报 |
| `0 9 * * 3` | `scan --year 2026` | 周三扫描本年漏洞 |
| `0 9 * * 5` | `poc --days 30` | 周五 PoC 专项报告 |

> GitHub Actions 调度基于 UTC，与北京时间相差 8 小时。

---

## 📊 数据源

| 源 | 内容 | 限制 |
|----|------|------|
| CVEProject/delta.json | 新增/更新的 CVE 列表 | 无认证 60 req/h |
| NVD API 2.0 | CVSS 3.1、CWE | 无认证 50 req/10s |
| CISA KEV JSON | 已知被利用漏洞 | 无认证，文件约 3MB |
| GitHub Advisory | PoC/Exploit 标记 | 需 GITHUB_TOKEN |

---

## 📄 License

MIT — 欢迎 Fork / Star / PR
