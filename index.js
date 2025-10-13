#!/usr/bin/env node

const core = require('@actions/core');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { glob } = require('glob');

class SBOMUIGenerator {
  constructor() {
    this.sbomFiles = core.getInput('sbom-files') || process.env.INPUT_SBOM_FILES || '**/*.json';
    this.outputDir = core.getInput('output-dir') || process.env.INPUT_OUTPUT_DIR || 'sbom-ui';
    this.title = core.getInput('title') || process.env.INPUT_TITLE || 'SBOM Explorer';
    this.theme = core.getInput('theme') || process.env.INPUT_THEME || 'dark';
    
    // Debug logging
    core.info(`SBOM Files: ${this.sbomFiles}`);
    core.info(`Output Dir: ${this.outputDir}`);
    core.info(`Title: ${this.title}`);
    core.info(`Theme: ${this.theme}`);
  }

  async run() {
    try {
      core.info('Starting SBOM UI Generation...');

      // Create output directory
      await this.createOutputDir();

      // Find and process SBOM files
      const sbomFiles = await this.findSBOMFiles();
      core.info(`Found ${sbomFiles.length} SBOM files`);

      if (sbomFiles.length === 0) {
        core.warning('No SBOM files found. Creating example with sample data.');
        await this.createSampleData();
      } else {
        // Parse SBOM files
        const parsedData = await this.parseSBOMFiles(sbomFiles);
        await this.writeParsedData(parsedData);
      }

      // Generate HTML UI
      await this.generateHTML();

      // Copy static assets
      await this.copyStaticAssets();

      // Set output
      core.setOutput('output-path', this.outputDir);
      core.info(`SBOM UI generated in: ${this.outputDir}`);

      core.info('SBOM UI generation completed successfully!');

    } catch (error) {
      core.setFailed(`Error: ${error.message}`);
    }
  }

  async createOutputDir() {
    if (!this.outputDir) {
      throw new Error('Output directory is not specified. Please provide output-dir input.');
    }
    
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true });
    }
  }

  async findSBOMFiles() {
    const patterns = this.sbomFiles.split(',').map(p => p.trim());
    const files = [];
    
    for (const pattern of patterns) {
      const matches = await glob(pattern, { 
        cwd: process.cwd(),
        absolute: true,
        nodir: true 
      });
      files.push(...matches);
    }
    
    return files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.json', '.xml', '.yaml', '.yml'].includes(ext);
    });
  }

  async parseSBOMFiles(sbomFiles) {
    const datasets = [];
    const allItems = [];
    
    for (const file of sbomFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const datasetId = this.extractDatasetId(file);
        const parsed = await this.parseSBOM(content, file, datasetId);
        
        if (parsed && parsed.items && parsed.items.length > 0) {
          datasets.push({
            id: datasetId,
            created: parsed.created,
            components: parsed.components,
            vulnerabilities: parsed.vulnerabilities,
            severityCounts: this.countSeverities(parsed.items)
          });
          allItems.push(...parsed.items);
        }
      } catch (error) {
        core.warning(`Failed to parse ${file}: ${error.message}`);
      }
    }
    
    const overallSeverity = this.countSeverities(allItems);
    const fixAvailRate = allItems.length ? 
      Math.round(100 * (allItems.filter(it => (it.fixedVersions || []).length > 0).length / allItems.length)) : 0;
    const topCVEs = this.buildTopCVEs(allItems);
    
    return {
      generatedAt: new Date().toISOString(),
      datasets: datasets.sort((a, b) => String(a.id).localeCompare(String(b.id))),
      items: allItems,
      overall: {
        total: allItems.length,
        severityCounts: overallSeverity
      },
      metrics: {
        fixAvailabilityRate: fixAvailRate,
        topCVEs
      }
    };
  }

  extractDatasetId(filePath) {
    const relativePath = path.relative(process.cwd(), filePath);
    const parts = relativePath.split(path.sep);
    return parts[0] || 'default';
  }

  async parseSBOM(content, filePath, datasetId) {
    const ext = path.extname(filePath).toLowerCase();
    
    try {
      if (ext === '.json') {
        return this.parseCycloneDX(JSON.parse(content), datasetId);
      } else if (['.yaml', '.yml'].includes(ext)) {
        const yaml = require('js-yaml');
        return this.parseCycloneDX(yaml.load(content), datasetId);
      } else if (ext === '.xml') {
        return this.parseSPDXXML(content, datasetId);
      }
    } catch (error) {
      core.warning(`Failed to parse ${filePath}: ${error.message}`);
      return null;
    }
    
    return null;
  }

  parseCycloneDX(json, datasetId) {
    const componentMap = new Map();
    (json.components || []).forEach(c => {
      const key = c['bom-ref'] || c['bomRef'] || c.purl || `${c.name || 'component'}@${c.version || ''}`;
      componentMap.set(key, c);
    });

    const vuls = [];
    for (const v of json.vulnerabilities || []) {
      const affects = (v.affects || []).map(a => a.ref).filter(Boolean);
      const rating = this.pickCVSS(v.ratings || v.cvss || []);
      const sev = (v.severity || rating?.severity || 'UNKNOWN').toUpperCase();

      const targets = affects.length ? affects : [null];
      for (const ref of targets) {
        const c = ref ? (componentMap.get(ref) || {}) : {};
        const lic = this.licenseNames(c.licenses);
        vuls.push({
          dataset: datasetId,
          id: v.id || null,
          title: v.description?.slice(0, 200) || 'Vulnerability',
          severity: sev,
          severityRank: this.severityOrder(sev),
          cvss: rating?.score ?? null,
          component: c.name || null,
          version: c.version || null,
          purl: c.purl || null,
          licenses: lic,
          direct: (c.scope || '').toLowerCase() !== 'optional' && (c.scope || '').toLowerCase() !== 'transitive',
          cwes: (v.cwes || []).map(x => x.id || x).filter(Boolean),
          urls: (v.references || []).map(r => r.url).filter(Boolean),
          fixedVersions: (v.analysis?.response || []).includes('update') ? ['*'] : []
        });
      }
    }

    return {
      dataset: datasetId,
      created: json.metadata?.timestamp || null,
      components: (json.components || []).length,
      vulnerabilities: vuls.length,
      items: vuls
    };
  }

  parseSPDXXML(content, datasetId) {
    // Basic SPDX XML parsing - can be enhanced
    const vulnerabilities = [];
    // This is a simplified parser - in production, use a proper XML parser
    return {
      dataset: datasetId,
      created: null,
      components: 0,
      vulnerabilities: 0,
      items: vulnerabilities
    };
  }

  severityOrder(s) {
    const map = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: 0, unknown: 0 };
    return map[String(s || '').toLowerCase()] ?? 0;
  }

  pickCVSS(scores = []) {
    let best = null;
    for (const r of scores) {
      const score = r.score ?? r.baseScore;
      const severity = r.severity || r.baseSeverity;
      if (score == null && !severity) continue;
      const obj = { score: score ?? null, severity: (severity || '').toUpperCase(), method: r.method || r.source || null };
      if (!best || (obj.score ?? 0) > (best.score ?? 0)) best = obj;
    }
    return best;
  }

  licenseNames(licenses) {
    if (!Array.isArray(licenses)) return [];
    const out = [];
    for (const l of licenses) {
      if (l.license?.id) out.push(l.license.id);
      else if (l.license?.name) out.push(l.license.name);
      else if (l.expression) out.push(l.expression);
    }
    return out;
  }

  countSeverities(items) {
    const init = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
    return items.reduce((acc, it) => {
      const s = (it.severity || 'UNKNOWN').toUpperCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, init);
  }

  buildTopCVEs(items) {
    const map = new Map();
    for (const it of items) {
      const id = it.id || '';
      if (!/^CVE-\d{4}-\d{4,}$/.test(id)) continue;
      const cur = map.get(id) || { id, count: 0, datasets: new Set(), maxCVSS: null, worstSeverityRank: -1 };
      cur.count += 1;
      cur.datasets.add(it.dataset);
      if (it.cvss != null) cur.maxCVSS = Math.max(cur.maxCVSS ?? -Infinity, it.cvss);
      if ((it.severityRank ?? -1) > cur.worstSeverityRank) cur.worstSeverityRank = it.severityRank ?? -1;
      map.set(id, cur);
    }
    return [...map.values()]
      .map(x => ({ id: x.id, count: x.count, datasets: [...x.datasets].sort(), maxCVSS: x.maxCVSS, worstSeverityRank: x.worstSeverityRank }))
      .sort((a, b) => (b.worstSeverityRank - a.worstSeverityRank) || (b.count - a.count) || (b.maxCVSS ?? 0) - (a.maxCVSS ?? 0))
      .slice(0, 10);
  }

  async writeParsedData(data) {
    const outputFile = path.join(this.outputDir, 'parse-sboms.json');
    fs.writeFileSync(outputFile, JSON.stringify(data, null, 2));
    core.info(`Parsed data written to ${outputFile}`);
  }

  async createSampleData() {
    const sampleData = {
      generatedAt: new Date().toISOString(),
      datasets: [{
        id: 'sample',
        created: new Date().toISOString(),
        components: 5,
        vulnerabilities: 3,
        severityCounts: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 }
      }],
      items: [
        {
          dataset: 'sample',
          id: 'CVE-2024-12345',
          title: 'Sample Critical Vulnerability',
          severity: 'CRITICAL',
          severityRank: 4,
          cvss: 9.8,
          component: 'sample-library',
          version: '1.0.0',
          purl: 'pkg:npm/sample-library@1.0.0',
          licenses: ['MIT'],
          direct: true,
          cwes: [],
          urls: [],
          fixedVersions: []
        },
        {
          dataset: 'sample',
          id: 'CVE-2024-12346',
          title: 'Sample High Vulnerability',
          severity: 'HIGH',
          severityRank: 3,
          cvss: 7.5,
          component: 'another-library',
          version: '2.1.0',
          purl: 'pkg:npm/another-library@2.1.0',
          licenses: ['Apache-2.0'],
          direct: true,
          cwes: [],
          urls: [],
          fixedVersions: ['2.2.0']
        }
      ],
      overall: {
        total: 3,
        severityCounts: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 }
      },
      metrics: {
        fixAvailabilityRate: 33,
        topCVEs: [
          { id: 'CVE-2024-12345', count: 1, datasets: ['sample'], maxCVSS: 9.8, worstSeverityRank: 4 },
          { id: 'CVE-2024-12346', count: 1, datasets: ['sample'], maxCVSS: 7.5, worstSeverityRank: 3 }
        ]
      }
    };
    
    await this.writeParsedData(sampleData);
  }

  async generateHTML() {
    const htmlContent = this.getHTMLTemplate();
    const outputFile = path.join(this.outputDir, 'index.html');
    fs.writeFileSync(outputFile, htmlContent);
    core.info(`HTML UI generated at ${outputFile}`);
  }

  getHTMLTemplate() {
    return `<!doctype html>
<html lang="en" x-data="app()" x-init="init()" class="h-full bg-[#0a0e14] antialiased">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>${this.title}</title>
  <meta name="color-scheme" content="light dark" />
    <script src="https://cdn.tailwindcss.com/3.4.0"></script>
    <script>
      // Suppress Tailwind CDN warning
      if (typeof window !== 'undefined' && window.tailwind) {
        console.log('Tailwind CSS loaded successfully');
      }
    </script>
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.1/dist/cdn.min.js"></script>
  <style>
    .card {
      @apply bg-[#1a1f2e] border border-[#2d3748] rounded-2xl shadow-sm p-4;
    }
    .muted {
      @apply text-xs text-[#94a3b8];
    }
    .bar {
      @apply h-2 w-full bg-[#2d3748] rounded;
    }
    .bar-fill {
      @apply h-2 rounded;
      background: linear-gradient(90deg, #ef4444, #f59e0b, #10b981);
    }
    [x-cloak] {
      display: none !important;
    }
    :root {
      --primary: #7395AE;
      --accent: #A1D6E2;
      --bg: #0a0e14;
      --surface: #1a1f2e;
      --border: #2d3748;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
    }
    html, body {
      background-color: var(--bg);
    }
    body {
      font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji";
    }
    code, pre, kbd, samp {
      font-family: 'Source Code Pro', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    a {
      color: var(--primary);
    }
    .btn-primary {
      background: var(--primary);
      color: white;
    }
    .btn-accent {
      background: var(--accent);
      color: #0a0e14;
    }
    @media (prefers-reduced-motion: reduce) {
      * {
        animation: none !important;
        transition: none !important;
      }
    }
    @media (max-width: 768px) {
      table.responsive {
        display: block;
        border: 0;
      }
      table.responsive thead {
        display: none;
      }
      table.responsive tbody {
        display: grid;
        grid-template-columns: 1fr;
        gap: .75rem;
        padding: .75rem;
      }
      table.responsive tr {
        display: grid;
        border: 1px solid #2d3748;
        border-radius: .75rem;
        padding: .75rem;
        background: #1a1f2e;
      }
      table.responsive td {
        display: grid;
        grid-template-columns: 7rem 1fr;
        gap: .25rem;
        padding: .25rem 0;
      }
      table.responsive td::before {
        content: attr(data-label);
        @apply text-[11px] text-[#94a3b8];
      }
      .sticky-actions {
        position: sticky;
        bottom: 0;
        padding-bottom: max(env(safe-area-inset-bottom), .5rem);
        background: linear-gradient(to top, rgba(26, 31, 46, .95), rgba(26, 31, 46, .6) 60%, transparent);
        backdrop-filter: blur(6px);
      }
      .btn {
        @apply h-11 px-4 rounded-xl border text-sm;
      }
    }
    @media (min-width: 640px) {
      .sidebar-open {
        margin-left: 28rem;
      }
    }
    @media (min-width: 1280px) {
      .sidebar-open {
        margin-left: 32rem;
      }
    }
    .adaptive-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    }
    @media (max-width: 1024px) {
      .adaptive-grid {
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      }
    }
    @media (max-width: 768px) {
      .adaptive-grid {
        grid-template-columns: 1fr;
      }
    }
    .compact-layout .grid {
      gap: 0.75rem;
    }
    .compact-layout .card {
      padding: 0.75rem;
    }
    .fluid-container {
      width: 100%;
      max-width: none;
      margin: 0;
    }
    .sidebar-open .overflow-x-auto {
      max-width: none;
      width: 100%;
    }
    .sidebar-open table {
      table-layout: auto;
    }
    .sidebar-open table th:nth-child(1),
    .sidebar-open table td:nth-child(1) {
      min-width: 80px;
    }
    .sidebar-open table th:nth-child(2),
    .sidebar-open table td:nth-child(2) {
      min-width: 60px;
    }
    .sidebar-open table th:nth-child(3),
    .sidebar-open table td:nth-child(3) {
      min-width: 120px;
    }
    .sidebar-open table th:nth-child(4),
    .sidebar-open table td:nth-child(4) {
      min-width: 80px;
    }
    .sidebar-open table th:nth-child(5),
    .sidebar-open table td:nth-child(5) {
      min-width: 100px;
    }
    .sidebar-open table th:nth-child(6),
    .sidebar-open table td:nth-child(6) {
      min-width: 120px;
    }
    .sidebar-open table th:nth-child(7),
    .sidebar-open table td:nth-child(7) {
      min-width: 100px;
    }
    .compact-table th,
    .compact-table td {
      padding-left: 0.5rem !important;
      padding-right: 0.5rem !important;
      font-size: 0.875rem;
    }
    .compact-table th:nth-child(1),
    .compact-table td:nth-child(1) {
      min-width: 70px;
    }
    .compact-table th:nth-child(2),
    .compact-table td:nth-child(2) {
      min-width: 50px;
    }
    .compact-table th:nth-child(3),
    .compact-table td:nth-child(3) {
      min-width: 100px;
    }
    .compact-table th:nth-child(4),
    .compact-table td:nth-child(4) {
      min-width: 70px;
    }
    .compact-table th:nth-child(5),
    .compact-table td:nth-child(5) {
      min-width: 80px;
    }
    .compact-table th:nth-child(6),
    .compact-table td:nth-child(6) {
      min-width: 100px;
    }
    .compact-table th:nth-child(7),
    .compact-table td:nth-child(7) {
      min-width: 80px;
    }
    .mobile-sidebar-handle {
      background: #4a5568;
      opacity: 0.6;
      border-radius: 9999px;
      height: 4px;
      width: 32px;
    }
    .btn {
      color: #e2e8f0;
    }
    .btn:not([class*="bg-[#A1D6E2]"]) {
      color: #e2e8f0 !important;
    }
    @media (max-width: 640px) {
      .sticky-actions .btn {
        font-weight: 500;
        color: #e2e8f0;
      }
    }
    @media (max-width: 640px) {
      .mobile-sidebar input,
      .mobile-sidebar select {
        height: 44px !important;
        padding: 12px 16px !important;
        font-size: 14px !important;
        line-height: 1.2 !important;
        border-radius: 12px !important;
        border: 1px solid #2d3748 !important;
        background-color: #1a1f2e !important;
        color: #e2e8f0 !important;
        width: 100% !important;
        box-sizing: border-box !important;
      }
      .mobile-sidebar label {
        margin-bottom: 8px !important;
        display: block !important;
      }
      .mobile-sidebar .space-y-3>* {
        margin-bottom: 16px !important;
      }
      .mobile-sidebar .space-y-3>*:last-child {
        margin-bottom: 0 !important;
      }
      .mobile-sidebar input[type="search"],
      .mobile-sidebar input[type="text"] {
        height: 44px !important;
        padding: 12px 16px !important;
      }
      .mobile-sidebar input[type="number"] {
        height: 44px !important;
        padding: 12px 16px !important;
      }
      .mobile-sidebar select {
        height: 44px !important;
        padding: 12px 16px !important;
        appearance: none !important;
        background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%2394a3b8' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='m6 8 4 4 4-4'/%3e%3c/svg%3e") !important;
        background-position: right 12px center !important;
        background-repeat: no-repeat !important;
        background-size: 16px !important;
        padding-right: 40px !important;
      }
    }
  </style>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Code+Pro:wght@400;600&display=swap" rel="stylesheet">
</head>
<body class="h-full text-gray-100 bg-[#0a0e14]">
  <header class="sticky top-0 z-40 bg-[#1a1f2e]/90 backdrop-blur border-b border-[#2d3748] transition-all duration-300 ease-in-out" :class="mobileFilters ? 'sm:ml-[28rem] xl:ml-[32rem]' : ''">
    <div class="px-3 sm:px-4 py-2 sm:py-3 flex items-center gap-2 sm:gap-3">
      <button class="sm:hidden p-2 rounded-xl border border-[#2d3748]" @click="toggleSidebar()" aria-label="Toggle filters">
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M3 5h18M6 12h12M10 19h4" />
        </svg>
      </button>
      <button
        class="hidden sm:inline-flex items-center gap-2 px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
        @click="toggleSidebar()" aria-label="Toggle filters">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8">
          <path d="M3 5h18M6 12h12M10 19h4" />
        </svg>
        Filters
      </button>
      <h1 class="text-base sm:text-xl font-semibold">SBOM Explorer</h1>
      <span class="text-xs text-[#94a3b8] ml-2" x-text="metaText" aria-live="polite"></span>

      <div class="ml-auto flex items-center gap-1 sm:gap-2">
        <button
          class="hidden sm:inline px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
          @click="exportCSV()">Export CSV</button>
        <button
          class="hidden sm:inline px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
          @click="saveView()">Save View</button>
        <button
          class="hidden sm:inline px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
          @click="loadView()">Load View</button>

        <div class="sm:hidden relative" x-data="{open:false}" @keydown.escape.window="open=false">
          <button class="p-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e]" @click="open=!open"
            :aria-expanded="open.toString()" aria-haspopup="menu" aria-label="Actions">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8">
              <circle cx="12" cy="12" r="1.5" />
              <circle cx="5" cy="12" r="1.5" />
              <circle cx="19" cy="12" r="1.5" />
            </svg>
          </button>
          <div x-cloak x-show="open" @click.outside="open=false"
            class="absolute right-0 mt-2 w-44 bg-[#1a1f2e] border border-[#2d3748] rounded-xl shadow-lg overflow-hidden">
            <button class="w-full text-left px-3 py-2 text-sm hover:bg-[#2d3748]"
              @click="exportCSV(); open=false">Export CSV</button>
            <button class="w-full text-left px-3 py-2 text-sm hover:bg-[#2d3748]" @click="saveView(); open=false">Save
              View</button>
            <button class="w-full text-left px-3 py-2 text-sm hover:bg-[#2d3748]" @click="loadView(); open=false">Load
              View</button>
          </div>
        </div>
      </div>
    </div>
  </header>

  <div x-cloak x-show="mobileFilters" class="fixed inset-0 z-50" aria-modal="true" role="dialog">
    <div class="absolute inset-0 bg-black/30" @click="mobileFilters=false"></div>
    <section
      class="hidden sm:flex absolute left-0 top-0 bottom-0 w-full sm:w-[28rem] xl:w-[32rem] max-w-full sm:max-w-[28rem] xl:max-w-[32rem] bg-[#1a1f2e] border-r border-[#2d3748] shadow-lg flex-col">
      <header class="p-3 flex items-center gap-2 border-b border-[#2d3748]">
        <div class="font-medium">Filters</div>
        <button class="ml-auto p-2 rounded-xl border border-[#2d3748] bg-[#1a1f2e]" @click="toggleSidebar()"
          aria-label="Close filters">✕</button>
      </header>
      <div class="p-3 space-y-3 overflow-auto">
        <label class="text-xs text-[#94a3b8]">Search
          <div class="relative mt-1" x-ref="searchWrap">
            <input id="q-d" x-ref="search" x-model="q" @input="onInput" @keydown.down.prevent="moveSel(1)"
              @keydown.up.prevent="moveSel(-1)" @keydown.enter.prevent="applySel()"
              @keydown.escape.prevent="hideSuggest()" placeholder="Search (component, purl, vuln id, license)"
              class="w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0] placeholder-[#94a3b8]"
              inputmode="search" autocomplete="off" />
            <div x-ref="suggest" x-show="showSuggest && suggestions.length" @pointerdown.prevent
              class="absolute z-50 mt-1 w-full bg-[#1a1f2e] border border-[#2d3748] rounded-xl shadow-lg max-h-72 overflow-auto"
              role="listbox">
              <template x-for="(s, i) in suggestions" :key="s.key">
                <button type="button" @pointerdown.prevent @click="pick(s)"
                  :class="['w-full text-left px-3 py-2 flex items-center gap-2', i===selIdx ? 'bg-[#2d3748]' : 'hover:bg-[#2d3748]']"
                  :aria-selected="i===selIdx" role="option" style="min-height:44px">
                  <span class="text-[11px] px-1.5 py-0.5 rounded bg-[#2d3748]" x-text="s.group"></span>
                  <span class="truncate flex-1" x-text="s.label"></span>
                  <span class="text-xs text-[#94a3b8]" x-text="s.meta"></span>
                </button>
              </template>
            </div>
          </div>
        </label>
        <div class="grid grid-cols-1 gap-3">
          <label class="text-xs text-[#94a3b8]">Dataset
            <select x-model="dataset"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">All datasets</option>
              <template x-for="(d, idx) in datasetsSafe" :key="'ds-select-' + idx">
                <option :value="d.id" x-text="\`\${d.id} (\${d.vulnerabilities})\`"></option>
              </template>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">Severity
            <select x-model="severity"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">All severities</option>
              <template x-for="s in sevOpts" :key="s">
                <option :value="s" x-text="s"></option>
              </template>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">Fix status
            <select x-model="fix"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">Has fix?</option>
              <option value="has">Has fix</option>
              <option value="none">No fix</option>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">CVSS minimum
            <input type="number" min="0" max="10" step="0.1" x-model.number="cvssMin"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0] placeholder-[#94a3b8]" />
          </label>
        </div>
      </div>
      <div class="p-3 grid grid-cols-2 gap-2 border-t border-[#2d3748]">
        <button class="btn"
          :class="lastAction === 'apply' ? 'bg-[#A1D6E2] text-[#0a0e14] border-[#A1D6E2]' : 'bg-[#1a1f2e] border-[#2d3748] text-[#e2e8f0]'"
          @click="applyFilters(true); toggleSidebar(); lastAction='apply'">Apply</button>
        <button class="btn"
          :class="lastAction === 'reset' ? 'bg-[#A1D6E2] text-[#0a0e14] border-[#A1D6E2]' : 'bg-[#1a1f2e] border-[#2d3748] text-[#e2e8f0]'"
          @click="resetFilters(); toggleSidebar(); lastAction='reset'">Reset</button>
      </div>
    </section>
    <section
      class="absolute inset-x-0 bottom-0 max-h-[85vh] bg-[#1a1f2e] border-t border-[#2d3748] rounded-t-2xl shadow-lg flex sm:hidden flex-col mobile-sidebar">
      <header class="p-3 flex items-center gap-2">
        <div class="mobile-sidebar-handle"></div>
        <button class="ml-auto p-2 rounded-xl border border-[#2d3748] bg-[#1a1f2e]" @click="toggleSidebar()"
          aria-label="Close filters">✕</button>
      </header>
      <div class="p-3 space-y-3 overflow-auto">
        <label class="text-xs text-[#94a3b8]">Search
          <div class="relative mt-1" x-ref="searchWrap">
            <input id="q-m" x-ref="search" x-model="q" @input="onInput" @keydown.down.prevent="moveSel(1)"
              @keydown.up.prevent="moveSel(-1)" @keydown.enter.prevent="applySel()"
              @keydown.escape.prevent="hideSuggest()" placeholder="Search (component, purl, vuln id, license)"
              class="w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0] placeholder-[#94a3b8]"
              inputmode="search" autocomplete="off" />
            <div x-ref="suggest" x-show="showSuggest && suggestions.length" @pointerdown.prevent
              class="absolute z-50 mt-1 w-full bg-[#1a1f2e] border border-[#2d3748] rounded-xl shadow-lg max-h-72 overflow-auto"
              role="listbox">
              <template x-for="(s, i) in suggestions" :key="s.key">
                <button type="button" @pointerdown.prevent @click="pick(s)"
                  :class="['w-full text-left px-3 py-2 flex items-center gap-2', i===selIdx ? 'bg-[#2d3748]' : 'hover:bg-[#2d3748]']"
                  :aria-selected="i===selIdx" role="option" style="min-height:44px">
                  <span class="text-[11px] px-1.5 py-0.5 rounded bg-[#2d3748]" x-text="s.group"></span>
                  <span class="truncate flex-1" x-text="s.label"></span>
                  <span class="text-xs text-[#94a3b8]" x-text="s.meta"></span>
                </button>
              </template>
            </div>
          </div>
        </label>
        <div class="grid grid-cols-1 gap-3">
          <label class="text-xs text-[#94a3b8]">Dataset
            <select x-model="dataset"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">All datasets</option>
              <template x-for="(d, idx) in datasetsSafe" :key="'ds-select-' + idx">
                <option :value="d.id" x-text="\`\${d.id} (\${d.vulnerabilities})\`"></option>
              </template>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">Severity
            <select x-model="severity"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">All severities</option>
              <template x-for="s in sevOpts" :key="s">
                <option :value="s" x-text="s"></option>
              </template>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">Fix status
            <select x-model="fix"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="">Has fix?</option>
              <option value="has">Has fix</option>
              <option value="none">No fix</option>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">CVSS minimum
            <input type="number" min="0" max="10" step="0.1" x-model.number="cvssMin"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0] placeholder-[#94a3b8]" />
          </label>
        </div>
      </div>
      <div class="sticky-actions p-3 grid grid-cols-2 gap-2">
        <button class="btn"
          :class="lastAction === 'apply' ? 'bg-[#A1D6E2] text-[#0a0e14] border-[#A1D6E2]' : 'bg-[#1a1f2e] border-[#2d3748] text-[#e2e8f0]'"
          @click="applyFilters(true); toggleSidebar(); lastAction='apply'">Apply</button>
        <button class="btn"
          :class="lastAction === 'reset' ? 'bg-[#A1D6E2] text-[#0a0e14] border-[#A1D6E2]' : 'bg-[#1a1f2e] border-[#2d3748] text-[#e2e8f0]'"
          @click="resetFilters(); toggleSidebar(); lastAction='reset'">Reset</button>
      </div>
    </section>
  </div>

  <main class="px-3 sm:px-4 py-4 sm:py-6 transition-all duration-300 ease-in-out" x-cloak
    :class="mobileFilters ? 'sm:ml-[28rem] xl:ml-[32rem] sidebar-open' : ''">
    <div class="space-y-6 w-full" :class="mobileFilters ? 'sm:ml-0 xl:ml-0' : ''">
      <section class="grid grid-cols-1 xl:grid-cols-12 gap-3 sm:gap-4 mb-4 sm:mb-6" aria-live="polite">
        <div class="xl:col-span-8 grid grid-cols-2 md:grid-cols-6 gap-3">
          <div class="card col-span-2">
            <div class="text-xs text-[#94a3b8]">Total vulnerabilities</div>
            <div class="text-2xl font-semibold" x-text="filtered.length"></div>
            <div class="muted mt-1" x-text="filterSummary"></div>
          </div>
          <template x-for="sev in ['CRITICAL','HIGH','MEDIUM','LOW']" :key="'sev-'+sev">
            <div class="card">
              <div class="text-xs text-[#94a3b8]" x-text="sev"></div>
              <div class="text-xl font-semibold" x-text="sevCountsFiltered[sev] || 0"></div>
            </div>
          </template>
        </div>

        <div class="card xl:col-span-4">
          <div class="text-sm font-medium mb-3">Datasets in view</div>
          <template x-if="Object.keys(perDatasetSev).length === 0">
            <div class="muted">No datasets in the current view.</div>
          </template>
          <div class="space-y-3 max-h-60 overflow-auto">
            <template x-for="(v, name) in perDatasetSev" :key="'ds-'+name">
              <div>
                <div class="flex items-center justify-between text-sm">
                  <div class="font-medium truncate" x-text="name"></div>
                  <div class="text-xs text-[#94a3b8]" x-text="\`\${v.total} vulns\`"></div>
                </div>
                <div class="bar">
                  <div class="bar-fill" :style="\`width:\${Math.min(100, (v.total/Math.max(1, filtered.length))*100)}%\`">
                  </div>
                </div>
                <div class="mt-1 flex flex-wrap gap-2 text-[11px] text-[#94a3b8]">
                  <span>CRIT: <b x-text="v.CRITICAL||0"></b></span>
                  <span>HIGH: <b x-text="v.HIGH||0"></b></span>
                  <span>MED: <b x-text="v.MEDIUM||0"></b></span>
                  <span>LOW: <b x-text="v.LOW||0"></b></span>
                </div>
              </div>
            </template>
          </div>
        </div>
      </section>

      <section class="grid grid-cols-1 xl:grid-cols-12 gap-3 sm:gap-4 mb-4 sm:mb-6">
        <div class="xl:col-span-8 grid gap-4 items-stretch [grid-template-columns:repeat(auto-fit,minmax(140px,1fr))]">
          <div class="card h-full flex items-start gap-3" x-show="fixRateFiltered > 0">
            <div class="shrink-0">
              <svg viewBox="0 0 44 44" width="64" height="64" aria-label="Fix availability">
                <circle cx="22" cy="22" r="18" fill="none" stroke="#e5e7eb" stroke-width="6" />
                <circle cx="22" cy="22" r="18" fill="none" :stroke-dasharray="ringCircumference"
                  :stroke-dashoffset="ringOffsetFix" :stroke="fixRateFiltered ? ringColor : '#e5e7eb'"
                  stroke-linecap="round" stroke-width="6" style="transform: rotate(-90deg); transform-origin: 50% 50%;" />
              </svg>
            </div>
            <div>
              <div class="text-xs text-[#94a3b8]">Fix availability</div>
              <div class="text-2xl font-semibold" x-text="fixRateFiltered + '%' "></div>
              <div class="muted mt-1"
                x-text="fixRateFiltered ? '% of vulnerabilities with known fixes' : 'No known fixes in this view'">
              </div>
            </div>
          </div>

          <div class="card h-full md:col-span-1 flex items-start gap-4">
            <div class="shrink-0">
              <svg viewBox="0 0 44 44" width="88" height="88" aria-label="Severity mix">
                <circle cx="22" cy="22" r="16" fill="none" class="text-[#2d3748]" stroke="currentColor"
                  stroke-width="8" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.CRITICAL.color"
                  :stroke-dasharray="donutSegs.CRITICAL.dash" :stroke-dashoffset="donutSegs.CRITICAL.offset"
                  stroke-width="8" style="transform: rotate(-90deg); transform-origin: 50% 50%;"
                  x-show="donutSegs.CRITICAL.count > 0" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.HIGH.color"
                  :stroke-dasharray="donutSegs.HIGH.dash" :stroke-dashoffset="donutSegs.HIGH.offset" stroke-width="8"
                  style="transform: rotate(-90deg); transform-origin: 50% 50%;" x-show="donutSegs.HIGH.count > 0" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.MEDIUM.color"
                  :stroke-dasharray="donutSegs.MEDIUM.dash" :stroke-dashoffset="donutSegs.MEDIUM.offset" stroke-width="8"
                  style="transform: rotate(-90deg); transform-origin: 50% 50%;" x-show="donutSegs.MEDIUM.count > 0" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.LOW.color"
                  :stroke-dasharray="donutSegs.LOW.dash" :stroke-dashoffset="donutSegs.LOW.offset" stroke-width="8"
                  style="transform: rotate(-90deg); transform-origin: 50% 50%;" x-show="donutSegs.LOW.count > 0" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.INFO.color"
                  :stroke-dasharray="donutSegs.INFO.dash" :stroke-dashoffset="donutSegs.INFO.offset" stroke-width="8"
                  style="transform: rotate(-90deg); transform-origin: 50% 50%;" x-show="donutSegs.INFO.count > 0" />
                <circle cx="22" cy="22" r="16" fill="none" :stroke="donutSegs.UNKNOWN.color"
                  :stroke-dasharray="donutSegs.UNKNOWN.dash" :stroke-dashoffset="donutSegs.UNKNOWN.offset"
                  stroke-width="8" style="transform: rotate(-90deg); transform-origin: 50% 50%;"
                  x-show="donutSegs.UNKNOWN.count > 0" />
              </svg>
            </div>
            <div>
              <div class="text-sm font-medium mb-2">Severity mix</div>
              <div class="text-xs space-y-1">
                <template x-for="seg in donutLegend" :key="'leg-'+seg.label">
                  <div class="flex items-center gap-2">
                    <span class="inline-block w-3 h-3 rounded" :style="\`background:\${seg.color}\`"></span>
                    <span class="text-[#94a3b8]" x-text="\`\${seg.label}: \${seg.count}\`"></span>
                  </div>
                </template>
                <div class="muted mt-2" x-text="filterSummary"></div>
              </div>
            </div>
          </div>

          <div class="card h-full">
            <div class="text-sm font-medium mb-2">Top components by vulnerabilities</div>
            <div class="space-y-2">
              <template x-for="row in topComponents" :key="'tc-'+row.name">
                <div class="flex items-center gap-3">
                  <div class="w-36 truncate text-xs text-[#e2e8f0]" :title="row.name" x-text="row.name"></div>
                  <div class="flex-1 h-2 bg-[#2d3748] rounded">
                    <div class="h-2 rounded" :style="\`width:\${row.pct}%; background:#10b981\`"></div>
                  </div>
                  <div class="w-8 text-right text-xs text-[#94a3b8]" x-text="row.count"></div>
                </div>
              </template>
            </div>
          </div>
        </div>

        <div class="card xl:col-span-4 h-full">
          <div class="flex items-center justify-between mb-2">
            <div class="text-sm font-medium">Top CVEs</div>
            <button class="text-xs underline" @click="applyTopCVE()">Clear filter</button>
          </div>
          <template x-if="!(metrics.topCVEs||[]).length">
            <div class="muted">No CVE IDs found.</div>
          </template>
          <ul class="text-sm grid grid-cols-1 gap-3 max-h-80 overflow-auto">
            <template x-for="cve in (metrics.topCVEs || [])" :key="'cve-'+cve.id">
              <li class="border rounded-xl p-3">
                <div class="font-medium">
                  <button class="text-blue-600 underline" @click="applyTopCVE(cve.id)" x-text="cve.id"></button>
                </div>
                <div class="muted mt-1">
                  <span x-text="\`Count: \${cve.count}\`"></span>
                  · <span x-text="\`Max CVSS: \${cve.maxCVSS ?? '-'}\`"></span>
                  <template x-if="(cve.datasets||[]).length">· <span
                      x-text="\`Datasets: \${cve.datasets.join(', ')}\`"></span></template>
                </div>
              </li>
            </template>
          </ul>
        </div>
      </section>

      <section class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 mb-4 sm:mb-6">
        <div class="card h-full">
          <div class="text-sm font-medium mb-2">CVSS distribution</div>
          <svg :viewBox="\`0 0 \${sparkW} \${sparkH}\`" :width="sparkW" :height="sparkH" role="img"
            aria-label="CVSS sparkline">
            <polyline :points="sparkGrid" fill="none" stroke="#e5e7eb" stroke-width="1" />
            <polyline :points="cvssPath" fill="none" stroke="#2563eb" stroke-width="2" />
          </svg>
          <div class="muted mt-2" x-text="cvssStatsText"></div>
        </div>

        <div class="card">
          <div class="text-sm font-medium mb-2">Top licenses by vulnerabilities</div>
          <div class="space-y-2">
            <template x-for="row in topLicenses" :key="'tl-'+row.name">
              <div class="flex items-center gap-3">
                <div class="w-36 truncate text-xs text-[#e2e8f0]" :title="row.name" x-text="row.name"></div>
                <div class="flex-1 h-2 bg-[#2d3748] rounded">
                  <div class="h-2 rounded" :style="\`width:\${row.pct}%; background:#6366f1\`"></div>
                </div>
                <div class="w-8 text-right text-xs text-[#94a3b8]" x-text="row.count"></div>
              </div>
            </template>
            <template x-if="!topLicenses.length">
              <div class="muted">No license data</div>
            </template>
          </div>
        </div>

        <div class="card">
          <div class="text-sm font-medium mb-2">Fix availability by dataset</div>
          <div class="space-y-2">
            <template x-for="row in dsFixRates" :key="'dsfr-'+row.name">
              <div class="flex items-center gap-3">
                <div class="w-32 truncate text-xs text-[#e2e8f0]" :title="row.name" x-text="row.name"></div>
                <div class="flex-1 h-2 bg-[#2d3748] rounded">
                  <div class="h-2 rounded"
                    :style="\`width:\${row.rate}%; background:\${row.rate>=67?'#10b981':row.rate>=33?'#f59e0b':'#ef4444'}\`">
                  </div>
                </div>
                <div class="w-10 text-right text-xs text-[#94a3b8]" x-text="row.rate + '%' "></div>
              </div>
            </template>
          </div>
        </div>
      </section>

      <section class="w-full">
        <div class="mb-2 text-sm text-[#94a3b8]">
          <span x-text="\`Showing \${filtered.length} of \${items.length} vulnerabilities\`"></span>
        </div>
        <div class="overflow-x-auto bg-[#1a1f2e] border border-[#2d3748] rounded-2xl shadow-sm w-full"
          :class="mobileFilters ? 'sm:max-w-none' : ''">
          <table class="min-w-full text-sm responsive">
            <thead class="bg-[#2d3748]/60">
              <tr class="text-left">
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">CVSS</th>
                <th class="px-4 py-3">Component</th>
                <th class="px-4 py-3">Version</th>
                <th class="px-4 py-3">License</th>
                <th class="px-4 py-3">Vuln ID</th>
                <th class="px-4 py-3 w-40">Dataset</th>
              </tr>
            </thead>
            <tbody>
              <template x-for="row in paged" :key="row._key">
                <tr class="border-t border-[#2d3748] hover:bg-[#2d3748]/60">
                  <td class="px-4 py-2" :data-label="'Severity'">
                    <span class="px-2 py-0.5 rounded-lg text-xs font-semibold" :class="badge(row.severity)"
                      x-text="row.severity || 'UNKNOWN'"></span>
                  </td>
                  <td class="px-4 py-2" :data-label="'CVSS'" x-text="row.cvss ?? '-' "></td>
                  <td class="px-4 py-2" :data-label="'Component'">
                    <div class="font-medium flex items-center gap-1">
                      <svg aria-hidden="true" viewBox="0 0 24 24" width="14" height="14" class="text-[#94a3b8]">
                        <path fill="currentColor" d="M4 4h6l2 2h8v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" />
                      </svg>
                      <span x-text="row.component || '-' "></span>
                    </div>
                    <div class="text-xs text-[#94a3b8] truncate max-w-[28rem]" x-text="row.purl"></div>
                  </td>
                  <td class="px-4 py-2" :data-label="'Version'" x-text="row.version || '-' "></td>
                  <td class="px-4 py-2" :data-label="'License'">
                    <template x-for="(l,i) in (row.licenses || [])" :key="row._key+'-lic-'+i">
                      <span class="mr-1 px-1.5 py-0.5 bg-[#2d3748] rounded" x-text="l"></span>
                    </template>
                  </td>
                  <td class="px-4 py-2" :data-label="'Vuln ID'">
                    <template x-if="row.id">
                      <button class="underline text-[color:var(--primary)]" @click="applyTopCVE(row.id)"
                        x-text="row.id"></button>
                    </template>
                    <template x-if="!row.id">
                      <span>-</span>
                    </template>
                  </td>
                  <td class="px-4 py-2" :data-label="'Dataset'">
                    <span class="text-xs px-2 py-1 bg-[#2d3748] rounded inline-flex items-center gap-1">
                      <svg aria-hidden="true" viewBox="0 0 24 24" width="12" height="12" class="text-[#94a3b8]">
                        <path fill="currentColor"
                          d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6V4zm2 0v16h8a2 2 0 0 0 2-2V8l-6-4h-4z" />
                      </svg>
                      <span x-text="row.dataset"></span>
                    </span>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>

        <div class="mt-4 flex items-center justify-between">
          <div class="text-sm text-[#94a3b8]">Page <span x-text="page+1"></span> / <span x-text="pages"></span></div>
          <div class="flex gap-2">
            <button
              class="px-4 py-2 border border-[#2d3748] rounded-lg disabled:opacity-50 bg-[#1a1f2e] text-[#e2e8f0] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
              :disabled="page===0" @click="prev()" aria-label="Previous page">Prev</button>
            <button
              class="px-4 py-2 border border-[#2d3748] rounded-lg disabled:opacity-50 bg-[#1a1f2e] text-[#e2e8f0] hover:bg-[#A1D6E2] hover:text-[#0a0e14] hover:border-[#A1D6E2]"
              :disabled="page+1>=pages" @click="next()" aria-label="Next page">Next</button>
          </div>
        </div>

        <div class="sm:hidden sticky-actions mt-3">
          <div class="grid grid-cols-3 gap-2 p-2">
            <button class="btn" @click="exportCSV()">Export</button>
            <button class="btn" @click="saveView()">Save</button>
            <button class="btn" @click="loadView()">Load</button>
          </div>
        </div>
      </section>
    </div>
  </main>

  <script>
    function app() {
      return {
        items: [],
        filtered: [],
        paged: [],
        datasets: [],
        get datasetsSafe() {
          return Array.isArray(this.datasets) ? this.datasets.filter(d => d && d._key) : [];
        },
        overall: { total: 0, severityCounts: {} },
        metrics: { fixAvailabilityRate: 0, topCVEs: [] },
        dataset: "",
        q: "",
        severity: "",
        fix: "",
        cvssMin: 0,
        mobileFilters: false,
        lastAction: "apply",
        sevBaseOrder: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'],
        sevOpts: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        sevCountsFiltered: {},
        fixRateFiltered: 0,
        filterSummary: "",
        perDatasetSev: {},
        sortKey: "severityRank",
        sortDir: "desc",
        page: 0,
        perPage: (matchMedia('(max-width: 640px)').matches ? 20 : 50),
        pages: 0,
        metaText: "",

        suggestions: [],
        showSuggest: false,
        selIdx: -1,
        _suggestTimer: null,

        hideSuggest() { this.showSuggest = false; this.selIdx = -1; },
        moveSel(step) {
          if (!this.suggestions.length) return;
          const n = this.suggestions.length;
          this.selIdx = ((this.selIdx + step + n) % n);
        },
        applySel() {
          if (this.selIdx < 0 || this.selIdx >= this.suggestions.length) { this.hideSuggest(); return; }
          this.pick(this.suggestions[this.selIdx]);
        },
        pick(s) {
          this.q = s.query;
          this.applyFilters(true);
          this.hideSuggest();
          this.$nextTick(() => this.$refs.search?.focus());
        },
        onInput(e) {
          this.q = e.target.value;
          this.applyFilters(true);
          clearTimeout(this._suggestTimer);
          const val = this.q.trim();
          if (!val) { this.suggestions = []; this.hideSuggest(); return; }
          this._suggestTimer = setTimeout(() => this.updateSuggestions(val), 120);
        },
        updateSuggestions(val) {
          const q = val.toLowerCase();
          const cand = [];
          const seen = new Set();
          const push = (group, label, query, meta = '') => {
            const key = group + '|' + label;
            if (seen.has(key)) return;
            seen.add(key);
            cand.push({ key, group, label, query, meta });
          };

          for (const r of this.items) {
            if (r.component && r.component.toLowerCase().includes(q))
              push('component', r.component, r.component, r.version || '');
            if (r.id && r.id.toLowerCase().includes(q))
              push('vuln id', r.id, r.id, r.severity || '');
            if (r.purl && r.purl.toLowerCase().includes(q))
              push('purl', r.purl, r.purl.split('@')[0] || r.purl, r.version || '');
            for (const L of (r.licenses || [])) {
              if (L && L.toLowerCase().includes(q)) push('license', L, L, '');
            }
            if (r.dataset && r.dataset.toLowerCase().includes(q))
              push('dataset', r.dataset, r.dataset, '');
          }

          const starts = [], contains = [];
          for (const s of cand) { (s.label.toLowerCase().startsWith(q) ? starts : contains).push(s); }
          const byLen = a => a.sort((x, y) => x.label.length - y.label.length);
          this.suggestions = [...byLen(starts), ...byLen(contains)].slice(0, 12);
          this.showSuggest = this.suggestions.length > 0;
          this.selIdx = this.suggestions.length ? 0 : -1;
        },

        ringCircumference: 2 * Math.PI * 18, // r=18
        get ringOffsetFix() {
          const pct = Math.max(0, Math.min(100, this.fixRateFiltered)) / 100;
          return this.ringCircumference * (1 - pct);
        },
        get ringColor() {
          const p = this.fixRateFiltered;
          if (p >= 67) return '#10b981';
          if (p >= 33) return '#f59e0b';
          return '#ef4444';
        },

        donutSegs: {
          CRITICAL: { dash: '0 1000', offset: 0, color: '#dc2626', count: 0 },
          HIGH: { dash: '0 1000', offset: 0, color: '#f87171', count: 0 },
          MEDIUM: { dash: '0 1000', offset: 0, color: '#f59e0b', count: 0 },
          LOW: { dash: '0 1000', offset: 0, color: '#10b981', count: 0 },
          INFO: { dash: '0 1000', offset: 0, color: '#9ca3af', count: 0 },
          UNKNOWN: { dash: '0 1000', offset: 0, color: '#d1d5db', count: 0 },
        },
        donutLegend: [],
        buildSeverityDonut() {
          const order = this.sevBaseOrder;
          const counts = this.sevCountsFiltered || {};
          const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0) || 0;
          const r = 16, C = 2 * Math.PI * r;
          let acc = 0;
          this.donutLegend = [];
          for (const k of order) {
            this.donutSegs[k].dash = \`0 \${C.toFixed(2)}\`;
            this.donutSegs[k].offset = 0;
            this.donutSegs[k].count = 0;
          }
          for (const label of order) {
            const count = counts[label] || 0;
            if (!count) continue;
            const pct = count / Math.max(1, total);
            const segLen = pct * C;
            this.donutSegs[label].dash = \`\${segLen.toFixed(2)} \${(C - segLen).toFixed(2)}\`;
            this.donutSegs[label].offset = (C * (1 - acc)).toFixed(2);
            this.donutSegs[label].count = count;
            acc += pct;
            this.donutLegend.push({ label, color: this.donutSegs[label].color, count });
          }
        },

        sparkW: 360,
        sparkH: 64,
        cvssPath: "",
        sparkGrid: "",
        cvssStatsText: "",
        buildCvssSpark() {
          const w = this.sparkW, h = this.sparkH, pad = 6;
          const xs = this.filtered.map(r => typeof r.cvss === 'number' ? r.cvss : null).filter(v => v != null);
          const n = xs.length;
          this.sparkGrid = \`0,\${h - 1} \${w},\${h - 1} 0,\${Math.round(h / 2)} \${w},\${Math.round(h / 2)} 0,1 \${w},1\`;
          if (!n) { this.cvssPath = ""; this.cvssStatsText = "no scores"; return; }
          const sorted = [...xs].sort((a, b) => a - b);
          const min = sorted[0];
          const q = (p) => sorted[Math.floor((sorted.length - 1) * p)];
          const med = q(0.5).toFixed(1);
          const step = Math.max(1, Math.floor(n / 80));
          const vals = xs.filter((_, i) => i % step === 0);
          const m = vals.length;
          const scaleX = (i) => pad + (i / (m - 1)) * (w - 2 * pad);
          const scaleY = (v) => pad + (1 - ((v - 0) / 10)) * (h - 2 * pad);
          this.cvssPath = vals.map((v, i) => \`\${scaleX(i)},\${scaleY(v)}\`).join(' ');
          this.cvssStatsText = \`n=\${n} · min=\${min?.toFixed(1)} · med=\${med} · p90=\${q(0.9).toFixed(1)}\`;
        },

        topComponents: [],
        buildTopComponents() {
          const counts = {};
          for (const r of this.filtered) {
            const name = r.component || 'unknown';
            counts[name] = (counts[name] || 0) + 1;
          }
          const arr = Object.entries(counts).map(([name, count]) => ({ name, count }));
          arr.sort((a, b) => b.count - a.count);
          const top = arr.slice(0, 6);
          const max = top[0]?.count || 1;
          this.topComponents = top.map(x => ({ ...x, pct: Math.round(100 * x.count / max) }));
        },

        topLicenses: [],
        buildTopLicenses() {
          const counts = {};
          for (const r of this.filtered) {
            const ls = Array.isArray(r.licenses) ? r.licenses : [];
            if (!ls.length) continue;
            for (const L of ls) {
              const name = (L || 'unknown').trim() || 'unknown';
              counts[name] = (counts[name] || 0) + 1;
            }
          }
          const arr = Object.entries(counts).map(([name, count]) => ({ name, count }));
          arr.sort((a, b) => b.count - a.count);
          const top = arr.slice(0, 6);
          const max = top[0]?.count || 1;
          this.topLicenses = top.map(x => ({ ...x, pct: Math.round(100 * x.count / max) }));
        },

        dsFixRates: [],
        buildDsFixRates() {
          const map = {};
          if (!Array.isArray(this.filtered)) {
            this.dsFixRates = [];
            return;
          }
          for (const r of this.filtered) {
            const d = r.dataset || 'unknown';
            if (!map[d]) map[d] = { name: d, total: 0, fix: 0 };
            map[d].total++;
            if ((r.fixedVersions || []).length) map[d].fix++;
          }
          const rows = Object.values(map).map(x => ({ name: x.name, rate: x.total ? Math.round(100 * x.fix / x.total) : 0 }));
          rows.sort((a, b) => b.rate - a.rate);
          this.dsFixRates = rows.slice(0, 6);
        },

        noFixSevBars: [],
        buildNoFixBars() {
          const nf = this.filtered.filter(r => !(r.fixedVersions || []).length);
          const counts = this.countSev(nf);
          const total = nf.length || 1;
          const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
          this.noFixSevBars = order
            .filter(s => counts[s])
            .map(s => ({ label: s, count: counts[s], pct: Math.round(100 * counts[s] / total), color: this.donutSegs[s].color }));
        },

        updateSeverityOptions() {
          const q = this.q.trim().toLowerCase();
          const ds = this.dataset, fix = this.fix, cv = Number(this.cvssMin) || 0;
          const base = this.items.filter(r => {
            if (ds && r.dataset !== ds) return false;
            if (cv && (r.cvss ?? -1) < cv) return false;
            if (fix === 'has' && !(r.fixedVersions || []).length) return false;
            if (fix === 'none' && (r.fixedVersions || []).length) return false;
            if (q) {
              const t = [r.component, r.purl, r.id, (r.licenses || []).join(' '), (r.dataset || '')].join(' ').toLowerCase();
              if (!t.includes(q)) return false;
            }
            return true;
          });
          const c = this.countSev(base);
          const out = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
          if ((c.INFO || 0) > 0) out.push('INFO');
          if ((c.UNKNOWN || 0) > 0) out.push('UNKNOWN');
          this.sevOpts = out;
        },

        async init() {
          try {
            const snap = await fetch("./parse-sboms.json?_=" + Date.now()).then(r => r.json());
            this.items = (snap.items || []).map((r, idx) => ({ ...r, _key: (r.dataset || 'ds') + '::' + (r.id || (r.component || 'comp') + '@' + (r.version || '')) + '::' + idx }));
            this.datasets = (snap.datasets || [])
              .map((d, i) => ({ 
                ...d, 
                _key: 'ds-' + (d.id || i),
                id: d.id || 'dataset-' + i,
                vulnerabilities: d.vulnerabilities || 0
              }))
              .filter(d => d && d._key) // Ensure all items have _key
              .sort((a, b) => String(a.id).localeCompare(String(b.id)));
            this.overall = snap.overall || this.overall;
            this.metrics = snap.metrics || this.metrics;
            this.metaText = snap.generatedAt ? 'updated ' + new Date(snap.generatedAt).toLocaleString() : '';
          } catch (error) {
            console.error('Failed to load SBOM data:', error);
            // Initialize with empty data to prevent Alpine.js errors
            this.items = [];
            this.datasets = [];
            this.overall = { total: 0, severityCounts: {} };
            this.metrics = { fixAvailabilityRate: 0, topCVEs: [] };
            this.metaText = 'Failed to load data';
            
            // Force update to ensure Alpine.js sees the changes
            this.$nextTick(() => {
              this.applyFilters(true);
            });
          }

          this.restoreFromHash();
          this.updateSeverityOptions();
          this.applyFilters(true);

          document.addEventListener('click', (e) => {
            const wrap = this.$refs.searchWrap;
            const panel = this.$refs.suggest;
            if (!wrap) return;
            const t = e.target;
            const insideWrap = wrap.contains(t);
            const insidePanel = panel ? panel.contains(t) : false;
            if (!insideWrap && !insidePanel) this.hideSuggest();
          }, { capture: true });

          this.handleResize = this.debounce(() => {
            if (window.innerWidth < 640 && this.mobileFilters) {
              this.mobileFilters = false;
            }
            this.adjustLayoutForScreenSize();
            document.body.offsetHeight;
          }, 250);
          window.addEventListener('resize', this.handleResize);

          const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 120));
          idle(() => { this.buildTopComponents(); this.buildTopLicenses(); this.buildDsFixRates(); });

          this.adjustLayoutForScreenSize();

          setTimeout(() => {
            this.adjustLayoutForScreenSize();
          }, 100);
        },

        badge(sev) {
          const s = (sev || "").toUpperCase();
          const base = "px-2 py-0.5 rounded-lg text-xs font-semibold";
          if (s === "CRITICAL") return base + " bg-red-600 text-white";
          if (s === "HIGH") return base + " bg-red-900 text-red-200";
          if (s === "MEDIUM") return base + " bg-amber-900 text-amber-200";
          if (s === "LOW") return base + " bg-green-900 text-green-200";
          return base + " bg-[#2d3748] text-[#94a3b8]";
        },

        applyFilters(buildGroup = false) {
          const q = this.q.trim().toLowerCase();
          const sev = this.severity, fix = this.fix, cv = Number(this.cvssMin) || 0, ds = this.dataset;
          this.filtered = this.items.filter(r => {
            if (ds && r.dataset !== ds) return false;
            if (sev && (r.severity || "").toUpperCase() !== sev) return false;
            if (cv && (r.cvss ?? -1) < cv) return false;
            if (fix === "has" && !(r.fixedVersions || []).length) return false;
            if (fix === "none" && (r.fixedVersions || []).length) return false;
            if (q) {
              const t = [r.component, r.purl, r.id, (r.licenses || []).join(" "), (r.dataset || "")].join(" ").toLowerCase();
              if (!t.includes(q)) return false;
            }
            return true;
          });

          // sorting
          const key = this.sortKey;
          const dir = this.sortDir === "desc" ? -1 : 1;
          this.filtered.sort((a, b) => {
            const A = (a[key] ?? ""), B = (b[key] ?? "");
            if (typeof A === "number" && typeof B === "number") return (A - B) * dir;
            return String(A).localeCompare(String(B)) * dir;
          });

          this.page = 0;
          this.paginate();

          this.sevCountsFiltered = this.countSev(this.filtered);
          const hasFix = this.filtered.filter(r => (r.fixedVersions || []).length).length;
          this.fixRateFiltered = this.filtered.length ? Math.round(100 * (hasFix / this.filtered.length)) : 0;
          this.perDatasetSev = this.groupByDatasetSev(this.filtered);
          this.filterSummary = this.buildFilterSummary();

          this.buildSeverityDonut();
          this.buildCvssSpark();
          this.buildTopComponents();
          this.buildTopLicenses();
          this.buildDsFixRates();
          this.buildNoFixBars();

          this.updateSeverityOptions();
          this.persistToHash();

          this.adjustLayoutForScreenSize();

          setTimeout(() => {
            document.body.offsetHeight;
          }, 50);
        },

        buildLicensesIfNeeded() { this.buildTopLicenses(); },

        paginate() {
          this.pages = Math.max(1, Math.ceil(this.filtered.length / this.perPage));
          const start = this.page * this.perPage;
          this.paged = this.filtered.slice(start, start + this.perPage);
        },
        next() { if (this.page + 1 < this.pages) { this.page++; this.paginate(); this.persistToHash(); } },
        prev() { if (this.page > 0) { this.page--; this.paginate(); this.persistToHash(); } },

        countSev(list) {
          const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
          for (const r of list) {
            const s = (r.severity || 'UNKNOWN').toUpperCase();
            out[s] = (out[s] || 0) + 1;
          }
          return out;
        },
        groupByDatasetSev(list) {
          const map = {};
          if (!Array.isArray(list)) return map;
          for (const r of list) {
            const ds = r.dataset || 'unknown';
            if (!map[ds]) map[ds] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0, total: 0 };
            const s = (r.severity || 'UNKNOWN').toUpperCase();
            map[ds][s] = (map[ds][s] || 0) + 1;
            map[ds].total++;
          }
          return map;
        },
        buildFilterSummary() {
          const bits = [];
          if (this.dataset) bits.push(\`dataset=\${this.dataset}\`);
          if (this.severity) bits.push(\`severity=\${this.severity}\`);
          if (this.fix) bits.push(\`fix=\${this.fix}\`);
          if (this.cvssMin) bits.push(\`cvss≥\${this.cvssMin}\`);
          if (this.q) bits.push(\`q="\${this.q}"\`);
          return bits.length ? \`Active: \${bits.join(' · ')}\` : 'No active filters';
        },

        exportCSV() {
          const rows = this.filtered;
          if (!rows.length) { alert("No rows to export."); return; }
          const header = ["severity", "cvss", "component", "version", "purl", "licenses", "id", "dataset"];
          const lines = [header.join(",")];
          for (const r of rows) {
            const csv = [
              r.severity ?? "",
              r.cvss ?? "",
              r.component ?? "",
              r.version ?? "",
              r.purl ?? "",
              (r.licenses || []).join("|"),
              r.id ?? "",
              r.dataset ?? ""
            ].map(x => \`"\${String(x).replace(/"/g, '""')}"\`).join(",");
            lines.push(csv);
          }
          const blob = new Blob([lines.join("\\n")], { type: "text/csv;charset=utf-8;" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "sbom-filtered.csv";
          a.click();
          URL.revokeObjectURL(url);
        },

        persistToHash() {
          const h = new URLSearchParams({
            q: this.q || "",
            ds: this.dataset || "",
            sev: this.severity || "",
            fix: this.fix || "",
            cvss: String(this.cvssMin || 0),
            dir: this.sortDir,
            key: this.sortKey,
            p: String(this.page)
          }).toString();
          location.hash = h;
        },
        restoreFromHash() {
          const s = new URLSearchParams(location.hash.replace(/^#/, ""));
          this.q = s.get("q") || this.q;
          this.dataset = s.get("ds") || this.dataset;
          this.severity = s.get("sev") || this.severity;
          this.fix = s.get("fix") || this.fix;
          this.cvssMin = Number(s.get("cvss") || this.cvssMin || 0);
          this.sortDir = s.get("dir") || this.sortDir;
          this.sortKey = s.get("key") || this.sortKey;
          this.page = Number(s.get("p") || this.page || 0);
        },

        applyTopCVE(id) { this.q = id || ""; this.applyFilters(true); },

        resetFilters() {
          this.q = "";
          this.dataset = "";
          this.severity = "";
          this.fix = "";
          this.cvssMin = 0;
          this.sortKey = "severityRank";
          this.sortDir = "desc";
          this.page = 0;
          this.lastAction = "reset";
          this.updateSeverityOptions();
          this.applyFilters(true);
        },

        toggleSidebar() {
          this.mobileFilters = !this.mobileFilters;
          setTimeout(() => {
            this.adjustLayoutForScreenSize();
            document.body.offsetHeight;
          }, 100);
        },

        saveView() { try { localStorage.setItem('sbom_view', location.hash); alert('View saved.'); } catch { } },
        loadView() { try { const h = localStorage.getItem('sbom_view'); if (h) { location.hash = h; this.restoreFromHash(); this.applyFilters(true); } } catch { } },

        debounce(func, wait) {
          let timeout;
          return function executedFunction(...args) {
            const later = () => {
              clearTimeout(timeout);
              func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
          };
        },

        adjustLayoutForScreenSize() {
          const width = window.innerWidth;
          const isSidebarOpen = this.mobileFilters;

          let availableWidth = width;
          if (isSidebarOpen && width >= 640) {
            availableWidth = width - (width >= 1280 ? 512 : 448);
          }

          if (width < 640) {
            this.perPage = 20;
          } else if (width < 1024) {
            this.perPage = isSidebarOpen ? 30 : 40;
          } else if (width < 1280) {
            this.perPage = isSidebarOpen ? 40 : 50;
          } else {
            this.perPage = isSidebarOpen ? 45 : 60;
          }

          this.updateGridLayout(availableWidth);

          if (this.filtered.length > 0) {
            this.paginate();
          }
        },

        updateGridLayout(availableWidth) {
          const mainContent = document.querySelector('main');
          if (mainContent) {
            if (availableWidth < 768) {
              mainContent.classList.add('compact-layout');
            } else {
              mainContent.classList.remove('compact-layout');
            }
          }

          this.adjustTableLayout(availableWidth);
        },

        adjustTableLayout(availableWidth) {
          const table = document.querySelector('table');
          if (!table) return;

          if (availableWidth < 768) {
            table.classList.add('compact-table');
          } else {
            table.classList.remove('compact-table');
          }
        }
      }
    }
  </script>
</body>
</html>`;
  }

  async copyStaticAssets() {
    // Copy any additional static assets if needed
    core.info('Static assets copied');
  }

}

// Run the action
if (require.main === module) {
  const generator = new SBOMUIGenerator();
  generator.run().catch(error => {
    core.setFailed(`Action failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = SBOMUIGenerator;
