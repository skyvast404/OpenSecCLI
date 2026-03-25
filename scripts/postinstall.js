import { mkdirSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'

const configDir = join(homedir(), '.openseccli')
const dirs = [configDir, join(configDir, 'auth'), join(configDir, 'plugins'), join(configDir, 'clis')]

for (const dir of dirs) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
}
