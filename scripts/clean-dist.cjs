const fs = require('fs')
const path = require('path')

const distDir = path.join(__dirname, '..', 'dist')
if (fs.existsSync(distDir)) {
  fs.rmSync(distDir, { recursive: true, force: true })
}

const tsBuildInfo = path.join(__dirname, '..', 'tsconfig.tsbuildinfo')
if (fs.existsSync(tsBuildInfo)) {
  fs.rmSync(tsBuildInfo)
}
