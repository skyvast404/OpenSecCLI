const fs = require('fs')
const path = require('path')

function copyYaml(srcDir, destDir) {
  if (!fs.existsSync(srcDir)) return

  const entries = fs.readdirSync(srcDir, { withFileTypes: true })
  for (const entry of entries) {
    const srcPath = path.join(srcDir, entry.name)
    const destPath = path.join(destDir, entry.name)

    if (entry.isDirectory()) {
      fs.mkdirSync(destPath, { recursive: true })
      copyYaml(srcPath, destPath)
    } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
      fs.copyFileSync(srcPath, destPath)
    }
  }
}

// Copy all YAML files from src/adapters to dist/adapters (recursive).
// This includes adapter config YAML files AND custom semgrep rules
// located at src/adapters/scan/rules/*.yaml.
const src = path.join(__dirname, '..', 'src', 'adapters')
const dest = path.join(__dirname, '..', 'dist', 'adapters')
fs.mkdirSync(dest, { recursive: true })
copyYaml(src, dest)

// Verify scan rules were copied
const scanRulesDest = path.join(dest, 'scan', 'rules')
if (fs.existsSync(scanRulesDest)) {
  const ruleFiles = fs.readdirSync(scanRulesDest).filter(f => f.endsWith('.yaml'))
  console.log(`Copied ${ruleFiles.length} custom semgrep rule files to dist/adapters/scan/rules/`)
}
