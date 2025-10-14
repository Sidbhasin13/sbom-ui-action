#!/usr/bin/env node

const fs = require('fs');
const { execSync } = require('child_process');

const version = process.argv[2];

if (!version) {
  console.error('Usage: node scripts/release.js <version>');
  console.error('Example: node scripts/release.js v1.0.1');
  process.exit(1);
}

if (!version.startsWith('v')) {
  console.error('Version must start with "v" (e.g., v1.0.1)');
  process.exit(1);
}

console.log(`Creating release for version: ${version}`);

try {
  // Update package.json
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const versionNumber = version.substring(1); // Remove 'v' prefix
  packageJson.version = versionNumber;
  fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));
  console.log(`Updated package.json to version ${versionNumber}`);

  // Create and push tag
  execSync(`git add package.json`);
  execSync(`git commit -m "chore: bump version to ${version}"`);
  execSync(`git tag ${version}`);
  execSync(`git push origin main`);
  execSync(`git push origin ${version}`);
  
  console.log(`Successfully created and pushed tag ${version}`);
  console.log('The release workflow will now run automatically.');
  
} catch (error) {
  console.error('Error creating release:', error.message);
  process.exit(1);
}
