/** scan_html (jsdom has no innerText): a page with no <html lang> still gets its real language from the content. */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { fastScanHtml } from '../src/fastScan.ts'

// Long English script/style INSIDE <body>: if the script/style exclusion is removed, this outweighs the German text and lang flips to en.
const EN_SCRIPT = 'var t = "the and of to in is for with that this are was be on at by from you your we our have has will can not but all more"; '.repeat(10)
const EN_STYLE = '.the-and-of-to-in-is-for-with-that-this-are-was { color: red } '.repeat(10)

const DE =
  '<!doctype html><html><head><title>Willkommen</title><style>.a{color:red}</style><script>var for_in_is_to = "the and of to in is for"</script></head><body><main><script>' + EN_SCRIPT + '</script><style>' + EN_STYLE + '</style><h1>Willkommen auf unserer Seite</h1>' +
  '<p>Wir sind ein kleines Unternehmen und bieten Ihnen alle Dienstleistungen, die Sie für Ihr Zuhause brauchen. Das ist eine Seite mit deutschem Text, der nicht englisch ist.</p>' +
  '<p>Bitte kontaktieren Sie uns, wenn Sie Fragen haben, und wir werden uns so schnell wie möglich bei Ihnen melden.</p></main></body></html>'

test('German page without lang: suggestedValue is de', async () => {
  const r = await fastScanHtml(DE)
  const lang = r.issues.find((i) => JSON.stringify(i).includes('"lang"') && /lang/i.test(i.type))
  assert.ok(lang, `no lang issue in ${r.issues.map((i) => i.type)}`)
  assert.equal((lang as any).fix?.suggestedValue ?? (lang as any).suggestedValue, 'de', JSON.stringify(lang))
})
