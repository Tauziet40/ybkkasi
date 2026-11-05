// Validation syntaxique temporaire (0904) : oauth.js / login.js sont des ES Modules navigateur, analyse déclenchée par import dynamique.
// Une SyntaxError à l'analyse = erreur de syntaxe ; l'absence de globales navigateur à l'exécution (ReferenceError etc.) est attendue, compte comme réussite.
const base = 'file:///' + process.cwd().replace(/\\/g, '/') + '/packages/plugin-console/public/js/pages/'
for (const name of ['oauth.js', 'login.js']) {
  try {
    await import(base + name)
    console.log('[IMPORT_OK]', name)
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.log('[SYNTAX_FAIL]', name, error.message)
      process.exitCode = 1
    } else {
      console.log('[PARSE_OK]', name, '-', error.constructor.name + ':', String(error.message).slice(0, 120))
    }
  }
}
