// 前端 SFC 静态验证：用 @vue/compiler-sfc 编译所有 .vue 文件，捕获语法错误
// 用法: node scripts/check_sfc.mjs
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { createRequire } from 'node:module'

// 从 frontend 目录解析依赖（@vue/compiler-sfc 位于 frontend/node_modules）
const require = createRequire(join(process.cwd(), 'frontend', 'package.json'))
const { parse, compileScript } = require('@vue/compiler-sfc')
const { compile } = require('@vue/compiler-dom')

const root = 'frontend/src'
const files = []
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p)
    else if (p.endsWith('.vue')) files.push(p)
  }
}
walk(root)

let failed = 0
for (const f of files) {
  try {
    const source = readFileSync(f, 'utf-8')
    const { descriptor, errors } = parse(source, { filename: f })
    if (errors.length) throw new Error(errors.map(e => e.message).join('; '))
    if (descriptor.script || descriptor.scriptSetup) {
      compileScript(descriptor, { id: f })
    }
    if (descriptor.template) {
      const errs = []
      compile(descriptor.template.content, {
        mode: 'module',
        onError: (e) => errs.push(e.message || String(e)),
      })
      if (errs.length) throw new Error(errs.join('; '))
    }
    console.log('OK  ' + relative(root, f))
  } catch (e) {
    failed++
    console.log('FAIL ' + relative(root, f) + ' -> ' + e.message)
  }
}
console.log(`\n${files.length - failed}/${files.length} SFC compiled OK`)
process.exit(failed ? 1 : 0)
