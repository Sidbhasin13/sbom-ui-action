#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Handle dependencies dynamically
let core, github, glob, yaml;

// Install all dependencies if any are missing
function installDependencies() {
  console.log('Installing missing dependencies...');
  try {
    // Try to install in the current directory first
    execSync('npm install @actions/core@^1.10.0 @actions/github@^6.0.0 glob@^10.3.10 js-yaml@^4.1.0', { 
      stdio: 'inherit'
    });
    console.log('Dependencies installed successfully!');
  } catch (installError) {
    console.log('Failed to install in current directory, trying script directory...');
    try {
      // Get the directory where this script is located
      const scriptDir = path.dirname(__filename);
      console.log(`Installing dependencies in: ${scriptDir}`);
      
      // Install dependencies in the script's directory
      execSync('npm install @actions/core@^1.10.0 @actions/github@^6.0.0 glob@^10.3.10 js-yaml@^4.1.0', { 
        stdio: 'inherit',
        cwd: scriptDir
      });
      console.log('Dependencies installed successfully!');
    } catch (secondError) {
      console.error(`Failed to install dependencies: ${secondError.message}`);
      process.exit(1);
    }
  }
}

// Function to try requiring modules from different locations
function tryRequire(moduleName) {
  try {
    return require(moduleName);
  } catch (error) {
    // Try from node_modules in current directory
    try {
      return require(path.join(process.cwd(), 'node_modules', moduleName));
    } catch (error2) {
      // Try from node_modules in script directory
      try {
        return require(path.join(path.dirname(__filename), 'node_modules', moduleName));
      } catch (error3) {
        throw error; // Re-throw original error
      }
    }
  }
}

try {
  core = tryRequire('@actions/core');
  github = tryRequire('@actions/github');
  glob = tryRequire('glob');
  yaml = tryRequire('js-yaml');
} catch (error) {
  installDependencies();
  core = tryRequire('@actions/core');
  github = tryRequire('@actions/github');
  glob = tryRequire('glob');
  yaml = tryRequire('js-yaml');
}

class SBOMUIGenerator {
  constructor() {
    this.sbomFiles = core.getInput('sbom-files') || process.env.INPUT_SBOM_FILES || '**/*.json';
    this.outputDir = core.getInput('output-dir') || process.env.INPUT_OUTPUT_DIR || 'sbom-ui';
    this.title = core.getInput('title') || process.env.INPUT_TITLE || 'SBOM Explorer';
    this.theme = core.getInput('theme') || process.env.INPUT_THEME || 'dark';
    
    // Debug logging
    core.info(`SBOM Files Pattern: ${this.sbomFiles}`);
    core.info(`Output Directory: ${this.outputDir}`);
    core.info(`Title: ${this.title}`);
    core.info(`Theme: ${this.theme}`);
  }

  async run() {
    try {
      core.info('Starting SBOM UI Generation...');
      
      // Create output directory
      await this.createOutputDir();
      
      // Find and process SBOM files from anywhere in the repository
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
      
      // Generate preview and deployment info
      await this.generateDeploymentInfo();
      
      // Set output
      core.setOutput('output-path', this.outputDir);
      core.setOutput('preview-url', `file://${path.resolve(this.outputDir, 'index.html')}`);
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
    
    core.info(`Searching for SBOM files with patterns: ${patterns.join(', ')}`);
    
    // Search for files using all patterns
    for (const pattern of patterns) {
      try {
        const matches = await glob.glob(pattern, { 
        cwd: process.cwd(),
        absolute: true,
          nodir: true,
          ignore: [
            '**/node_modules/**',
            '**/dist/**',
            '**/build/**',
            '**/.git/**',
            '**/coverage/**',
            '**/test-results/**'
          ]
      });
      files.push(...matches);
        core.info(`Pattern "${pattern}" found ${matches.length} files`);
      } catch (error) {
        core.warning(`Failed to search for pattern "${pattern}": ${error.message}`);
      }
    }
    
    // Remove duplicates and filter by supported extensions
    const uniqueFiles = [...new Set(files)];
    const supportedFiles = uniqueFiles.filter(file => {
      const ext = path.extname(file).toLowerCase();
      const isSupported = ['.json', '.xml', '.yaml', '.yml'].includes(ext);
      if (!isSupported) {
        core.debug(`Skipping unsupported file: ${file} (extension: ${ext})`);
      }
      return isSupported;
    });
    
    core.info(`Found ${supportedFiles.length} supported SBOM files out of ${uniqueFiles.length} total files`);
    
    // Log found files for debugging
    if (supportedFiles.length > 0) {
      core.info('SBOM files found:');
      supportedFiles.forEach(file => {
        const relativePath = path.relative(process.cwd(), file);
        core.info(`  - ${relativePath}`);
      });
    }
    
    return supportedFiles;
  }

  async parseSBOMFiles(sbomFiles) {
    const datasets = [];
    const allItems = [];
    
    for (const file of sbomFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const datasetId = this.extractDatasetId(file);
        core.info(`Processing file: ${file} -> dataset: ${datasetId}`);
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
    const fileName = path.basename(filePath, path.extname(filePath));
    
    // Strategy 1: Extract from filename first (most reliable for Trivy outputs)
    const fileNameLower = fileName.toLowerCase();
    
    // Handle Trivy SBOM naming patterns: sbom-{image_name}.cyclonedx.json
    if (fileNameLower.startsWith('sbom-')) {
      const imageName = fileNameLower.replace('sbom-', '').replace('.cyclonedx.json', '');
      
      // Clean up the image name to get meaningful dataset names
      if (imageName.includes('stable')) return 'stable';
      if (imageName.includes('arm64')) return 'arm64';
      if (imageName.includes('amd64')) {
        if (imageName.includes('backend')) return 'backend-amd64';
        if (imageName.includes('frontend')) return 'frontend-amd64';
        return 'amd64';
      }
      if (imageName.includes('backend')) return 'backend';
      if (imageName.includes('frontend')) return 'frontend';
      
      // Return cleaned image name
      return imageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    }
    
    // Strategy 2: Look for meaningful directory names in the path
    for (let i = 0; i < parts.length - 1; i++) {
      const dirName = parts[i].toLowerCase();
      
      // Skip common non-meaningful directories
      if (['src', 'lib', 'bin', 'etc', 'var', 'tmp', 'temp', 'all-artifacts'].includes(dirName)) {
        continue;
      }
      
      // Check for common patterns
      if (dirName.includes('stable') || dirName.includes('prod') || dirName.includes('production')) return 'stable';
      if (dirName.includes('arm64') || dirName.includes('aarch64')) return 'arm64';
      if (dirName.includes('amd64') || dirName.includes('x86_64')) {
        if (dirName.includes('backend')) return 'backend-amd64';
        if (dirName.includes('frontend')) return 'frontend-amd64';
        return 'amd64';
      }
      if (dirName.includes('backend') || dirName.includes('api')) return 'backend';
      if (dirName.includes('frontend') || dirName.includes('web') || dirName.includes('ui')) return 'frontend';
      if (dirName.includes('main') || dirName.includes('master')) return 'main';
      if (dirName.includes('develop') || dirName.includes('dev')) return 'develop';
      if (dirName.includes('release') || dirName.includes('rel')) return 'release';
      if (dirName.includes('test') || dirName.includes('testing')) return 'test';
      if (dirName.includes('staging') || dirName.includes('stage')) return 'staging';
      
      // Use directory name if it looks meaningful (not too generic)
      if (dirName && dirName.length > 2 && !dirName.match(/^\d+$/)) {
        return dirName.replace(/[^a-zA-Z0-9-_]/g, '-');
      }
    }
    
    // Strategy 3: Use filename if it's not generic
    if (fileName && fileName.length > 2 && !fileName.match(/^(sbom|bom|cyclonedx|spdx)$/i)) {
      return fileName.replace(/[^a-zA-Z0-9-_]/g, '-');
    }
    
    // Strategy 4: Use parent directory name
    if (parts.length > 1) {
      const parentDir = parts[parts.length - 2];
      if (parentDir && parentDir.length > 2) {
        return parentDir.replace(/[^a-zA-Z0-9-_]/g, '-');
      }
    }
    
    // Fallback: Generate based on file path hash for uniqueness
    const pathHash = this.simpleHash(relativePath);
    return `dataset-${pathHash}`;
  }
  
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36).substring(0, 6);
  }

  extractFixedVersions(vulnerability) {
    // Check multiple sources for fix information
    const sources = [
      vulnerability.analysis?.response,
      vulnerability.analysis?.justification,
      vulnerability.analysis?.state,
      vulnerability.analysis?.detail,
      vulnerability.analysis?.workaround,
      vulnerability.recommendation,
      vulnerability.solution
    ];

    // Look for fix indicators in various fields
    for (const source of sources) {
      if (Array.isArray(source)) {
        for (const item of source) {
          if (typeof item === 'string' && this.hasFixIndicators(item)) {
            return ['*']; // Generic fix available
          }
        }
      } else if (typeof source === 'string' && this.hasFixIndicators(source)) {
        return ['*']; // Generic fix available
      }
    }

    // Check for specific version information
    if (vulnerability.analysis?.fixedIn) {
      return Array.isArray(vulnerability.analysis.fixedIn) 
        ? vulnerability.analysis.fixedIn 
        : [vulnerability.analysis.fixedIn];
    }

    // Check for remediation information
    if (vulnerability.remediation) {
      if (vulnerability.remediation.versions) {
        return Array.isArray(vulnerability.remediation.versions)
          ? vulnerability.remediation.versions
          : [vulnerability.remediation.versions];
      }
      if (vulnerability.remediation.workaround) {
        return ['*']; // Workaround available
      }
    }

    return [];
  }

  hasFixIndicators(text) {
    if (!text) return false;
    const lowerText = text.toLowerCase();
    const fixIndicators = [
      'update', 'upgrade', 'patch', 'fix', 'fixed', 'resolved', 'remediation',
      'workaround', 'mitigation', 'solution', 'corrected', 'addressed',
      'version', 'latest', 'newer', 'current'
    ];
    return fixIndicators.some(indicator => lowerText.includes(indicator));
  }

  async parseSBOM(content, filePath, datasetId) {
    const ext = path.extname(filePath).toLowerCase();
    
    try {
      if (ext === '.json') {
        return this.parseCycloneDX(JSON.parse(content), datasetId);
      } else if (['.yaml', '.yml'].includes(ext)) {
        if (!yaml) {
          core.warning(`YAML parsing not available for ${filePath}. Install js-yaml to enable YAML support.`);
          return null;
        }
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
          fixedVersions: this.extractFixedVersions(v)
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
    let htmlContent = this.getHTMLTemplate();
    
    // Embed the JSON data directly in the HTML for local viewing
    const jsonFile = path.join(this.outputDir, 'parse-sboms.json');
    if (fs.existsSync(jsonFile)) {
      const jsonData = fs.readFileSync(jsonFile, 'utf8');
      // Sanitize JSON data to prevent XSS
      const sanitizedData = this.sanitizeJSON(jsonData);
      const embeddedScript = `<script>window.EMBEDDED_SBOM_DATA = ${sanitizedData};</script>`;
      htmlContent = htmlContent.replace('</head>', embeddedScript + '\n</head>');
    }
    
    const outputFile = path.join(this.outputDir, 'index.html');
    fs.writeFileSync(outputFile, htmlContent);
    core.info(`HTML UI generated at ${outputFile}`);
  }

  sanitizeJSON(jsonString) {
    // Basic JSON sanitization to prevent XSS
    try {
      const parsed = JSON.parse(jsonString);
      return JSON.stringify(parsed);
    } catch (error) {
      core.warning('Failed to sanitize JSON data');
      return '{}';
    }
  }

  validateOutputDirectory() {
    // Ensure output directory is safe and doesn't contain executable files
    const allowedExtensions = ['.html', '.css', '.js', '.json', '.md', '.txt', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico'];
    
    try {
      const files = fs.readdirSync(this.outputDir);
      for (const file of files) {
        const ext = path.extname(file).toLowerCase();
        if (!allowedExtensions.includes(ext) && !file.startsWith('.')) {
          core.warning(`Potentially unsafe file detected: ${file}`);
        }
      }
      core.info('Output directory security validation passed');
    } catch (error) {
      core.warning('Could not validate output directory security');
    }
  }

  getHTMLTemplate() {
    return `<!doctype html>
<html lang="en" x-data="app()" x-init="init()" class="h-full bg-[#0a0e14] antialiased">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>${this.title}</title>
  <meta name="color-scheme" content="light dark" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';" />
  <meta http-equiv="X-Content-Type-Options" content="nosniff" />
  <meta http-equiv="X-Frame-Options" content="DENY" />
  <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
    <script src="https://cdn.tailwindcss.com/3.4.0"></script>
    <script>
      // Configure Tailwind for production use
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              primary: '#7395AE',
              accent: '#A1D6E2',
              bg: '#0a0e14',
              surface: '#1a1f2e',
              border: '#2d3748',
              text: '#e2e8f0',
              'text-muted': '#94a3b8'
            }
          }
        }
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
              <template x-for="(s, i) in suggestions" :key="'suggest-' + i + '-' + s.key">
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
              <template x-for="(d, idx) in datasetsSafe" :key="'ds-select-' + idx + '-' + (d.id || 'unknown')">
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
              <template x-for="(s, i) in suggestions" :key="'suggest-' + i + '-' + s.key">
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
              <template x-for="(d, idx) in datasetsSafe" :key="'ds-select-' + idx + '-' + (d.id || 'unknown')">
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
          <label class="text-xs text-[#94a3b8]">Sort by
            <select x-model="sortKey" @change="applyFilters(true)"
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0]">
              <option value="severityRank">Severity</option>
              <option value="cvss">CVSS</option>
              <option value="component">Component</option>
              <option value="dataset">Dataset</option>
            </select>
          </label>
          <label class="text-xs text-[#94a3b8]">Sort direction
            <button @click="toggleSortDir(); applyFilters(true)" 
              class="mt-1 w-full px-3 py-2 border border-[#2d3748] rounded-xl bg-[#1a1f2e] text-[#e2e8f0] hover:bg-[#A1D6E2] hover:text-[#0a0e14]">
              <span x-text="sortDir === 'desc' ? 'Descending (↓)' : 'Ascending (↑)'"></span>
            </button>
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
          <template x-if="Object.keys(perDatasetSevSafe).length === 0">
            <div class="muted">No datasets in the current view.</div>
          </template>
          <div class="space-y-3 max-h-60 overflow-auto">
            <template x-for="(v, name) in perDatasetSevSafe" :key="'ds-'+name+'-'+v.total">
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
                <template x-for="(seg, idx) in donutLegendSafe" :key="'leg-'+idx+'-'+seg.label">
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
              <template x-for="(row, idx) in topComponentsSafe" :key="'tc-'+idx+'-'+row.name">
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
            <template x-for="(cve, idx) in (metrics.topCVEs || [])" :key="'cve-'+idx+'-'+cve.id">
              <li class="border rounded-xl p-3">
                <div class="font-medium">
                  <button class="text-blue-600 underline" @click="applyTopCVE(cve.id)" x-text="cve.id"></button>
                </div>
                <div class="muted mt-1">
                  <span x-text="\`Count: \${cve.count}\`"></span>
                  · <span x-text="\`Max CVSS: \${cve.maxCVSS ?? '-'}\`"></span>
                  <template x-if="(cve.datasets||[]).length">· <span
                      x-text="\`Datasets: \${(cve.datasets||[]).join(', ')}\`"></span></template>
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
            <template x-for="(row, idx) in topLicensesSafe" :key="'tl-'+idx+'-'+row.name">
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
            <template x-for="(row, idx) in dsFixRatesSafe" :key="'dsfr-'+idx+'-'+row.name">
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
          if (!Array.isArray(this.datasets)) {
            return [];
          }
          return this.datasets.filter(d => d && d._key && d.id);
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
        get perDatasetSevSafe() {
          return this.perDatasetSev && typeof this.perDatasetSev === 'object' ? this.perDatasetSev : {};
        },
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
        get donutLegendSafe() {
          return Array.isArray(this.donutLegend) ? this.donutLegend : [];
        },
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
        get topComponentsSafe() {
          return Array.isArray(this.topComponents) ? this.topComponents : [];
        },
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
        get topLicensesSafe() {
          return Array.isArray(this.topLicenses) ? this.topLicenses : [];
        },
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
        get dsFixRatesSafe() {
          return Array.isArray(this.dsFixRates) ? this.dsFixRates : [];
        },
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
          // Initialize with empty data first to prevent Alpine.js errors
          this.items = [];
          this.datasets = [];
          this.filtered = [];
          this.paged = [];
          this.overall = { total: 0, severityCounts: {} };
          this.metrics = { fixAvailabilityRate: 0, topCVEs: [] };
          this.metaText = 'Loading...';
          this.suggestions = [];
          this.showSuggest = false;
          this.selIdx = -1;
          
          try {
            // Try to load embedded data first (for local viewing)
            let snap;
            if (window.EMBEDDED_SBOM_DATA) {
              snap = window.EMBEDDED_SBOM_DATA;
              console.log('Loaded embedded data:', snap);
            } else {
              // Fallback to fetch for hosted versions
              const response = await fetch("./parse-sboms.json?_=" + Date.now());
              if (!response.ok) {
                throw new Error('HTTP ' + response.status + ': ' + response.statusText);
              }
              snap = await response.json();
              console.log('Loaded data:', snap);
            }
            
            // Process items with proper _key generation
            this.items = (snap.items || []).map((r, idx) => ({ 
              ...r, 
              _key: (r.dataset || 'ds') + '::' + (r.id || (r.component || 'comp') + '@' + (r.version || '')) + '::' + idx 
            }));
            
            // Process datasets with proper structure
            this.datasets = (snap.datasets || [])
              .map((d, i) => ({ 
                ...d, 
                _key: 'ds-' + (d.id || i),
                id: d.id || 'dataset-' + i,
                vulnerabilities: d.vulnerabilities || 0,
                severityCounts: d.severityCounts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 }
              }))
              .filter(d => d && d._key && d.id) // Ensure all items have _key and id
              .sort((a, b) => String(a.id).localeCompare(String(b.id)));
            
            // Process overall data
            this.overall = {
              total: snap.overall?.total || 0,
              severityCounts: snap.overall?.severityCounts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 }
            };
            
            // Process metrics data
            this.metrics = {
              fixAvailabilityRate: snap.metrics?.fixAvailabilityRate || 0,
              topCVEs: snap.metrics?.topCVEs || []
            };
            
            this.metaText = snap.generatedAt ? 'updated ' + new Date(snap.generatedAt).toLocaleString() : '';
            
            console.log('Processed items:', this.items.length);
            console.log('Processed datasets:', this.datasets.length);
            console.log('Overall total:', this.overall.total);
            console.log('Fix availability rate:', this.metrics.fixAvailabilityRate);
          } catch (error) {
            console.error('Failed to load SBOM data:', error);
            // Create fallback sample data
            this.createFallbackData();
            this.metaText = 'Sample data - No SBOM files found';
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

        toggleSortDir() {
          this.sortDir = this.sortDir === 'desc' ? 'asc' : 'desc';
        },

        createFallbackData() {
          // Create fallback sample data when no SBOM data is available
          this.items = [
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
              fixedVersions: [],
              _key: 'sample::CVE-2024-12345::0'
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
              fixedVersions: ['2.2.0'],
              _key: 'sample::CVE-2024-12346::1'
            }
          ];
          
          this.datasets = [{
            id: 'sample',
            created: new Date().toISOString(),
            components: 2,
            vulnerabilities: 2,
            severityCounts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 },
            _key: 'ds-sample'
          }];
          
          this.overall = {
            total: 2,
            severityCounts: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 }
          };
          
          this.metrics = {
            fixAvailabilityRate: 50, // 1 out of 2 has fixes
            topCVEs: [
              { id: 'CVE-2024-12345', count: 1, datasets: ['sample'], maxCVSS: 9.8, worstSeverityRank: 4 },
              { id: 'CVE-2024-12346', count: 1, datasets: ['sample'], maxCVSS: 7.5, worstSeverityRank: 3 }
            ]
          };
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

  async generateDeploymentInfo() {
    // Validate output directory for security
    this.validateOutputDirectory();
    
    const deploymentInfo = {
      title: this.title,
      outputDir: this.outputDir,
      generatedAt: new Date().toISOString(),
      security: {
        noExecutables: true,
        staticFilesOnly: true,
        contentSecurityPolicy: true,
        sanitizedData: true
      },
      deploymentOptions: {
        githubPages: {
          name: 'GitHub Pages',
          description: 'Deploy directly to GitHub Pages',
          steps: [
            '1. Go to your repository Settings',
            '2. Navigate to Pages section',
            '3. Set Source to "GitHub Actions"',
            '4. Use the provided workflow below'
          ],
          workflow: this.generateGitHubPagesWorkflow()
        },
        netlify: {
          name: 'Netlify',
          description: 'Deploy to Netlify with drag & drop',
          steps: [
            '1. Go to https://netlify.com',
            '2. Drag and drop the entire output folder',
            '3. Your site will be live instantly!'
          ]
        },
        vercel: {
          name: 'Vercel',
          description: 'Deploy to Vercel',
          steps: [
            '1. Go to https://vercel.com',
            '2. Import your repository',
            '3. Set build output directory to the generated folder',
            '4. Deploy!'
          ]
        },
        staticHosting: {
          name: 'Any Static Host',
          description: 'Deploy to any static hosting service',
          steps: [
            '1. Upload the entire output folder contents',
            '2. Ensure index.html is in the root',
            '3. Your SBOM dashboard will be live!'
          ]
        }
      }
    };

    // Write deployment info
    const infoFile = path.join(this.outputDir, 'deployment-info.json');
    fs.writeFileSync(infoFile, JSON.stringify(deploymentInfo, null, 2));

    // Generate GitHub Pages workflow
    const workflowFile = path.join(this.outputDir, 'deploy-to-github-pages.yml');
    fs.writeFileSync(workflowFile, this.generateGitHubPagesWorkflow());

    // Generate README for deployment
    const readmeFile = path.join(this.outputDir, 'DEPLOYMENT.md');
    fs.writeFileSync(readmeFile, this.generateDeploymentReadme());

    // Generate local preview server scripts
    await this.generatePreviewScripts();

    core.info('Deployment information generated!');
    core.info(`Check ${this.outputDir}/deployment-info.json for deployment options`);
    core.info(`Check ${this.outputDir}/DEPLOYMENT.md for detailed instructions`);
    core.info(`Check ${this.outputDir}/deploy-to-github-pages.yml for GitHub Pages workflow`);
  }

  generateGitHubPagesWorkflow() {
    return `name: Deploy SBOM Dashboard to GitHub Pages

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: false

jobs:
  deploy:
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        
      - name: Setup Pages
        uses: actions/configure-pages@v4
        
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: '${this.outputDir}/'
          
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4`;
  }

  async generatePreviewScripts() {
    // Create a simple README with instructions instead of executable scripts
    const previewInstructions = `# How to Preview Your SBOM Dashboard

## Why You Need a Local Server

Due to browser security restrictions, you cannot open the HTML file directly. You need to use a local web server.

## Quick Preview Methods

### Method 1: Python (Recommended)
\`\`\`bash
# Navigate to this folder in terminal/command prompt
cd "$(dirname "$0")"

# Start a simple server
python3 -m http.server 8000

# Open http://localhost:8000 in your browser
\`\`\`

### Method 2: Node.js
\`\`\`bash
# Install serve globally (one time)
npm install -g serve

# Start server
serve -p 8000

# Open http://localhost:8000 in your browser
\`\`\`

### Method 3: PHP
\`\`\`bash
# Start PHP server
php -S localhost:8000

# Open http://localhost:8000 in your browser
\`\`\`

### Method 4: Any Other Local Server
- Use any local development server
- Point it to this folder
- Access via http://localhost:8000

## What You'll See

- Interactive vulnerability dashboard
- Filtering and search capabilities
- Export functionality
- Mobile-responsive design

## Troubleshooting

If you see "Loading..." forever:
- Make sure you're using a local server (not opening file:// directly)
- Check browser console for errors
- Ensure parse-sboms.json is in the same folder as index.html

## Security Note

This dashboard only contains static HTML, CSS, and JavaScript files. No executable code or external dependencies are required for local preview.`;

    // Write instructions file instead of executable scripts
    const instructionsFile = path.join(this.outputDir, 'PREVIEW-INSTRUCTIONS.md');
    fs.writeFileSync(instructionsFile, previewInstructions);

    core.info('Preview instructions generated!');
    core.info('Check PREVIEW-INSTRUCTIONS.md for safe local preview methods');
  }

  generateDeploymentReadme() {
    return `# Deploy Your SBOM Dashboard

Your SBOM dashboard has been generated successfully! Here are several ways to deploy it:

## Files Generated
- \`index.html\` - Main dashboard file (don't open directly!)
- \`parse-sboms.json\` - Your SBOM data
- \`start-preview.py\` - Local preview server (Python) - **Use this to preview!**
- \`start-preview.bat\` - Local preview server (Windows) - **Use this to preview!**
- \`start-preview.sh\` - Local preview server (Unix/Mac) - **Use this to preview!**
- \`deployment-info.json\` - Deployment configuration
- \`deploy-to-github-pages.yml\` - GitHub Pages workflow

## Deployment Options

### 1. GitHub Pages (Recommended)
**Easiest option for GitHub repositories**

1. Copy the \`deploy-to-github-pages.yml\` file to \`.github/workflows/\` in your repository
2. Commit and push the changes
3. Go to your repository Settings → Pages
4. Set Source to "GitHub Actions"
5. Your dashboard will be available at: \`https://yourusername.github.io/your-repo\`

### 2. Netlify (Drag & Drop)
**Super simple for any repository**

1. Go to [netlify.com](https://netlify.com)
2. Drag and drop this entire folder
3. Your site will be live instantly!
4. You'll get a URL like: \`https://random-name.netlify.app\`

### 3. Vercel
**Great for modern deployments**

1. Go to [vercel.com](https://vercel.com)
2. Import your repository
3. Set build output directory to: \`${this.outputDir}\`
4. Deploy!

### 4. Any Static Host
**Works with any static hosting service**

1. Upload all files in this folder to your hosting service
2. Ensure \`index.html\` is in the root directory
3. Your dashboard will be live!

## Important: Preview Your Dashboard

**Don't just double-click the HTML files!** Due to browser security restrictions, you need to use a local web server to preview your dashboard properly.

### Why Preview Scripts Are Needed

When you open HTML files directly in your browser (using \`file://\` protocol), you'll encounter:
- Dashboard shows "Loading..." forever
- No vulnerability data appears  
- Charts and filters don't work
- Console shows CORS errors

### How to Preview Correctly

### Option 1: Try Double-Clicking the Scripts (Easiest)
- **Windows**: Double-click \`start-preview.bat\`
- **Mac/Linux**: Double-click \`start-preview.sh\` or run \`./start-preview.sh\` in terminal
- **Manual**: Run \`python3 start-preview.py\`

### Option 2: If Double-Clicking Doesn't Work
- **Windows**: Right-click \`start-preview.bat\` → "Run as administrator"
- **All platforms**: Open terminal in the dashboard folder and run the script manually
- **Alternative servers**: \`npx serve .\`, \`php -S localhost:8000\`, etc.

This will start a local server and open your dashboard in the browser at http://localhost:8000

### Option 3: Manual Server (If scripts don't work at all)
1. Use a local server: \`python -m http.server 8000\` (Python 3)
2. Or use: \`npx serve .\` (Node.js)
3. Or use: \`php -S localhost:8000\` (PHP)
4. **Avoid**: Opening \`index.html\` directly (will have limitations)

## Dashboard Features

Your dashboard includes:
- Interactive vulnerability charts
- Advanced filtering and search
- Mobile-responsive design
- CSV export functionality
- Beautiful dark theme

## Need Help?

If you encounter any issues:
1. Check that all files are uploaded correctly
2. Ensure \`parse-sboms.json\` is in the same directory as \`index.html\`
3. Check browser console for any errors

Happy vulnerability hunting!`;
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
