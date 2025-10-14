# SBOM UI Action

A **completely flexible** GitHub Action that automatically finds and parses Software Bill of Materials (SBOM) files from anywhere in your repository and generates interactive vulnerability dashboards. No configuration files needed - just point it to your SBOM files and it works! Supports multiple SBOM formats including CycloneDX, SPDX, and more, providing a beautiful, responsive web interface for analyzing security vulnerabilities.

## Live Demo

**See the SBOM UI in action with sample data:**
- **Demo URL**: [https://sidbhasin13.github.io/sbom-ui-action/](https://sidbhasin13.github.io/sbom-ui-action/)
- **Features**: Interactive filtering, vulnerability analysis, mobile-responsive design
- **Data**: Sample SBOM data with realistic vulnerabilities and components

## Key Features

- **Zero Configuration**: Works out of the box - no artifacts.json or config files needed
- **Smart Discovery**: Automatically finds SBOM files anywhere in your repository
- **Flexible Locations**: Works with files in any directory structure
- **Beautiful UI**: Modern, responsive dashboard with dark theme
- **Interactive Charts**: Donut charts, sparklines, and bar charts for data visualization
- **Advanced Filtering**: Search, filter by severity, dataset, CVSS score, and fix availability
- **Mobile Responsive**: Optimized for desktop, tablet, and mobile devices
- **Real-time Analytics**: Live vulnerability statistics and trends
- **Export Capabilities**: CSV export functionality
- **Format Support**: CycloneDX JSON, SPDX JSON/XML, YAML formats
- **High Performance**: Optimized for large datasets with pagination

## Important: Previewing Your Dashboard

**Don't just double-click the HTML files!** Due to browser security restrictions, you need to use a local web server to preview your dashboard properly.

### Why Preview Scripts Are Needed

When you open HTML files directly in your browser (using `file://` protocol), you'll encounter:
- Dashboard shows "Loading..." forever
- No vulnerability data appears  
- Charts and filters don't work
- Console shows CORS errors

### How to Preview Correctly

**Option 1: Try Double-Clicking the Scripts (Easiest)**
- **Windows**: Double-click `start-preview.bat`
- **Mac/Linux**: Double-click `start-preview.sh` or run `./start-preview.sh` in terminal
- **Manual**: Run `python3 start-preview.py`

**Option 2: If Double-Clicking Doesn't Work**
- **Windows**: Right-click `start-preview.bat` → "Run as administrator"
- **All platforms**: Open terminal in the dashboard folder and run the script manually
- **Alternative servers**: `npx serve .`, `php -S localhost:8000`, etc.

**Option 3: Manual Server (If scripts don't work at all)**
```bash
# Navigate to your dashboard folder
cd sbom-dashboard

# Start a local server
python3 -m http.server 8000

# Open http://localhost:8000 in your browser
```

This will start a local web server and open your dashboard at `http://localhost:8000` with full functionality!

## Quick Start

### Super Simple - Just Works!

```yaml
name: Generate SBOM Dashboard
on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  sbom-dashboard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM UI
        uses: sidbhasin13/sbom-ui-action@v1
        # That's it! The action will find all SBOM files automatically
```

### With Custom File Patterns

```yaml
name: Generate SBOM Dashboard
on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  sbom-dashboard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM UI
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: '**/*.json,**/*.xml,**/*.yaml'  # Find all SBOM formats
          output-dir: 'sbom-dashboard'
          title: 'My Project Security Dashboard'
```

### With Custom Configuration

```yaml
name: Advanced SBOM Dashboard
on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  sbom-dashboard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM UI
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: 'sboms/**/*.json,reports/**/*.cyclonedx.json'
          output-dir: 'sbom-dashboard'
          title: 'My Project SBOM Dashboard'
          theme: 'dark'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `sbom-files` | Path pattern to SBOM files (supports glob patterns) | No | `**/*.json` |
| `output-dir` | Directory to output generated UI files | No | `sbom-ui` |
| `title` | Custom title for the SBOM dashboard | No | `SBOM Explorer` |
| `theme` | UI theme (dark/light) | No | `dark` |

## Outputs

| Output | Description |
|--------|-------------|
| `output-path` | Path where the SBOM UI files were generated |

## Supported SBOM Formats

### CycloneDX
- JSON format (`.cyclonedx.json`)
- YAML format (`.cyclonedx.yaml`)

### SPDX
- JSON format (`.spdx.json`)
- XML format (`.spdx.xml`)

### Generic
- Any JSON file with vulnerability data
- YAML files with structured data

## Use Cases

### 1. CI/CD Pipeline Integration

```yaml
name: Security Scan with SBOM Dashboard
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM
        run: |
          # Your SBOM generation commands here
          syft packages . -o cyclonedx-json > sbom.cyclonedx.json
      
      - name: Generate SBOM Dashboard
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: '*.cyclonedx.json'
```

### 2. Release Management

```yaml
name: Release with SBOM Dashboard
on:
  release:
    types: [ published ]

jobs:
  release-dashboard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM for Release
        run: |
          # Generate SBOM for the release
          syft packages . -o cyclonedx-json > release-sbom.cyclonedx.json
      
      - name: Generate Release SBOM Dashboard
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: 'release-sbom.cyclonedx.json'
          title: 'Release ${{ github.event.release.tag_name }} SBOM'
```

### 3. Multi-Repository SBOM Aggregation

```yaml
name: Aggregate SBOMs from Multiple Repos
on:
  schedule:
    - cron: '0 2 * * 1' # Weekly on Monday at 2 AM
  workflow_dispatch:

jobs:
  aggregate-sboms:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download SBOMs from Multiple Repos
        run: |
          # Download SBOMs from different repositories
          curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
            -o frontend-sbom.json \
            https://api.github.com/repos/yourorg/frontend/contents/sbom.cyclonedx.json
          curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
            -o backend-sbom.json \
            https://api.github.com/repos/yourorg/backend/contents/sbom.cyclonedx.json
      
      - name: Generate Aggregated Dashboard
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: '*-sbom.json'
          title: 'Multi-Repository SBOM Dashboard'
```

### 4. Local Development

```yaml
name: Local SBOM Analysis
on:
  workflow_dispatch:

jobs:
  local-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate Local SBOM Dashboard
        uses: sidbhasin13/sbom-ui-action@v1
        with:
          sbom-files: 'sboms/**/*.json'
          output-dir: 'local-sbom-ui'
```

## Dashboard Features

### Interactive Filtering
- **Search**: Find vulnerabilities by component name, PURL, CVE ID, or license
- **Severity Filter**: Filter by CRITICAL, HIGH, MEDIUM, LOW severity levels
- **Dataset Filter**: Filter by specific datasets or components
- **CVSS Score**: Filter by minimum CVSS score
- **Fix Availability**: Show only vulnerabilities with or without fixes

### Visualizations
- **Severity Distribution**: Donut chart showing vulnerability severity breakdown
- **Top Components**: Bar chart of components with most vulnerabilities
- **Top CVEs**: List of most common CVE IDs
- **CVSS Distribution**: Sparkline showing CVSS score distribution
- **License Analysis**: Top licenses by vulnerability count
- **Fix Availability**: Percentage of vulnerabilities with known fixes

### Data Export
- **CSV Export**: Export filtered results to CSV format
- **View Saving**: Save and load custom filter configurations
- **URL Sharing**: Shareable URLs with filter state

## Customization

### Custom Styling
The dashboard uses Tailwind CSS and can be customized by modifying the CSS variables in the generated HTML:

```css
:root {
  --primary: #7395AE;    /* Primary color */
  --accent: #A1D6E2;     /* Accent color */
  --bg: #0a0e14;         /* Background color */
  --surface: #1a1f2e;    /* Surface color */
  --border: #2d3748;     /* Border color */
  --text: #e2e8f0;       /* Text color */
  --text-muted: #94a3b8; /* Muted text color */
}
```

### Custom Domain
To use a custom domain with GitHub Pages:

1. Set the `custom-domain` input
2. Configure your DNS to point to your GitHub Pages URL
3. The action will automatically create a `CNAME` file

## Troubleshooting

### Common Issues

**No SBOM files found**
- Check that your `sbom-files` pattern matches your actual file locations
- Ensure files have the correct extensions (`.json`, `.xml`, `.yaml`, `.yml`)

**Large datasets performance**
- The dashboard is optimized for datasets up to 10,000 vulnerabilities
- For larger datasets, consider filtering or splitting the data

### Debug Mode

Enable debug logging by setting the `ACTIONS_STEP_DEBUG` environment variable:

```yaml
- name: Generate SBOM UI
  uses: your-username/sbom-ui-action@v1
  env:
    ACTIONS_STEP_DEBUG: true
  with:
    # ... your inputs
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the action: `npm run build`
4. Test locally with `act` or in a GitHub repository

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- [Documentation](https://github.com/sidbhasin13/sbom-ui-action/wiki)
- [Issue Tracker](https://github.com/sidbhasin13/sbom-ui-action/issues)
- [Discussions](https://github.com/sidbhasin13/sbom-ui-action/discussions)

## Changelog

### v1.0.0
- Initial release
- Support for CycloneDX and SPDX formats
- Interactive dashboard with filtering and visualization
- Mobile responsive design
- CSV export functionality

---

Made with love for the Open source Community