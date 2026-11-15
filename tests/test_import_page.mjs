// Run with Node.js: node tests/test_import_page.mjs
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import assert from 'node:assert/strict';

const source = await readFile(new URL('../backend/web/vpn-import.js', import.meta.url), 'utf8');
let count = 0;
for (const href of ['/connect-config/test-capability', 'https://other.example/connect-config/test-capability', '/other/test']) {
  const launch = {href:null, removeAttribute() {this.ready = true;}};
  const message = {textContent:''};
  const document = {getElementById(id) {
    return id === 'openvpn-launch' ? launch : id === 'openvpn-download' ? {getAttribute() {return href;}} : message;
  }};
  const window = {location:{href:'https://app.example/connect-import/test-capability', origin:'https://app.example'}};
  runInNewContext(source, {document, window, URL});
  if (href === '/connect-config/test-capability') {
    assert.equal(launch.href, 'openvpn://import-profile/https://app.example/connect-config/test-capability');
    assert.equal(typeof launch.onclick, 'function');
    launch.onclick(); assert.match(message.textContent, /Подтвердите/);
    count += 3;
  } else {
    assert.equal(launch.href, null); assert.equal(launch.ready, undefined);
    count += 2;
  }
  // Preparing the page must not trigger native navigation without a user tap.
  assert.equal(window.location.href, 'https://app.example/connect-import/test-capability');
  count++;
}
console.log('Safari import page checks: ' + count + ' passed');
