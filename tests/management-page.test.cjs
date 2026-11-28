const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const pageHtml = fs.readFileSync(path.join(__dirname, '..', 'src', 'GameshowPro.TlsCa', 'wwwroot', 'management.html'), 'utf8');
let source = pageHtml.split('<script>')[1].split('</script>')[0];
source = source.replace('  fetch(P + "info.json", { cache: "no-store" })', '  globalThis.page = { safeReturnTo, secureDestination, sameHostHttpDestination, sameHostHttpsDestination, sameHostHttpsSetupDestination, render, renderUnavailable, probe };\n  fetch(P + "info.json", { cache: "no-store" })');
const nodes = new Map();
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.hidden = true; this.style = {}; this.textContent = ''; this.listeners = {}; this.firstChild = null; }
  set innerHTML(value) { this._innerHTML = value; this.textContent = String(value).replace(/<[^>]*>/g, ' '); }
  get innerHTML() { return this._innerHTML || ''; }
  appendChild(child) { this.children.push(child); this.firstChild = this.children[0]; this.lastChild = child; return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); this.firstChild = this.children[0] || null; }
  insertBefore(child) { this.children.unshift(child); this.firstChild = child; }
  setAttribute() {}
  addEventListener(name, handler) { this.listeners[name] = handler; }
  getContext() { return { fillRect() {}, set fillStyle(value) {} }; }
}
const document = { title: '', cookie: '', createElement: tag => new Element(tag), getElementById: id => { if (!nodes.has(id)) nodes.set(id, new Element(id)); return nodes.get(id); } };
let calls = [], replaced = null, assigned = null, copied = null;
const info = { product:'App', mdnsName:'show.local', httpsPort:9443, caFingerprintSha256:'AA:BB', caNotAfter:4102444800, leafNotBefore:1700000000, leafNotAfter:4102444800, gate:'loopback', secureAddress:'https://show.local:9443/', setupAddress:'http://show.local:8080/', fallbackAddress:'http://192.168.1.5:8080/', allowHttpFallback:true, allowHttpsFallback:true };
const location = { protocol:'http:', hostname:'show.local', host:'show.local:9090', origin:'http://show.local:9090', port:'9090', search:'?returnTo=%2Fshows%2F1%3Fview%3Dlive', replace: value => { replaced = value; }, assign: value => { assigned = value; } };
const context = { document, location, navigator:{userAgent:'Windows',clipboard:{writeText:async(value)=>{copied=value;}}}, URL, URLSearchParams, AbortController, Date, console, confirm:()=>true, setTimeout:()=>1, clearTimeout:()=>{}, setInterval:()=>1, clearInterval:()=>{}, fetch: async (url)=> { calls.push(url); return {ok:true,json:async()=>info}; } };
vm.runInNewContext(source, context);
(async()=>{
  for(let i=0;i<8;i++) await Promise.resolve(); await Promise.resolve();
  assert.equal(context.page.safeReturnTo(),'/shows/1?view=live');
  assert.equal(context.page.secureDestination(info),'https://show.local:9443/shows/1?view=live');
  assert.equal(context.page.sameHostHttpDestination(info),'http://show.local:9090/shows/1?view=live');
  for (const path of ['//evil.example/','/\\evil.example/','/%2fevil','/%252fevil','/../admin','https://evil.example/']) {
    location.search = '?returnTo='+encodeURIComponent(path);
    assert.equal(context.page.safeReturnTo(),'/', path);
    assert.equal(context.page.secureDestination(info),info.secureAddress,path);
  }
  location.search = '?returnTo=%2Fshows%2F1%3Fview%3Dlive';
  location.protocol='https:'; location.hostname='other.local'; location.origin='https://other.local:9443'; location.port='9443';
  assert.equal(context.page.sameHostHttpDestination(info),'http://other.local:8080/shows/1?view=live');
  assert.equal(context.page.sameHostHttpsDestination(info),'https://other.local:9443/shows/1?view=live');
  context.page.render(info);
  assert.equal(nodes.get('other-computers').hidden,true);
  location.protocol='http:';location.hostname='localhost';location.origin='http://localhost:8080';location.port='8080';
  context.page.render(info);
  assert.equal(nodes.get('other-computers').hidden,false);
  assert.equal(nodes.get('share-address').textContent,info.secureAddress);
  assert.equal(nodes.get('setup-address').textContent,info.setupAddress);
  assert.equal(nodes.get('fallback-block').hidden,false);
  assert.match(nodes.get('fallback-help').textContent,/plain HTTP addresses/);
  assert.match(nodes.get('fallback-note').textContent,/still needs .local name resolution/);
  const secureFallback = {...info,allowHttpFallback:false,fallbackAddress:'https://192.168.1.5:9443/',fallbackAddresses:['https://192.168.1.5:9443/','https://10.0.0.5:9443/']};
  context.page.render(secureFallback);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),secureFallback.fallbackAddresses);
  assert.match(nodes.get('fallback-help').textContent,/HTTPS addresses/);
  assert.match(nodes.get('fallback-help').textContent,/certificate warning/);
  assert.match(nodes.get('fallback-note').textContent,/Continue on this address/);
  context.page.render({...secureFallback,allowHttpsFallback:false});
  assert.doesNotMatch(nodes.get('fallback-note').textContent,/Continue on this address/);
  context.page.render(info);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),[info.fallbackAddress]);
  const multiple = {...info,fallbackAddresses:['http://192.168.1.5:8080/','http://10.0.0.5:8080/']};
  context.page.render(multiple);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),multiple.fallbackAddresses);
  assert.equal(nodes.get('fallback-block').hidden,false);
  context.page.render({...info,fallbackAddresses:[]});
  assert.equal(nodes.get('fallback-addresses').children.length,0);
  assert.equal(nodes.get('fallback-block').hidden,true);
  context.page.render(info);
  location.protocol='http:'; location.hostname='192.168.1.5'; location.origin='http://192.168.1.5:8080'; location.port='8080';
  const withoutHttp = {...info,allowHttpFallback:false};
  assert.equal(context.page.sameHostHttpsSetupDestination(withoutHttp),'https://192.168.1.5:9443/.well-known/gameshowpro/?returnTo=%2Fshows%2F1%3Fview%3Dlive');
  context.fetch = async () => { throw new Error('DNS unavailable'); };
  context.page.render(withoutHttp);
  context.page.probe(withoutHttp);
  assert.equal(nodes.get('http-to-https').hidden,true,'the HTTPS-by-IP link waits for the probe to fail');
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,false);
  assert.equal(nodes.get('open-this-https').href,'https://192.168.1.5:9443/.well-known/gameshowpro/?returnTo=%2Fshows%2F1%3Fview%3Dlive');
  assert.equal(nodes.get('this-https-address').textContent,'https://192.168.1.5:9443/');
  assert.equal(document.cookie,'','crossing to HTTPS does not create a bypass cookie');
  context.page.renderUnavailable({product:'App',gate:'loopback'});
  assert.equal(nodes.get('http-to-https').hidden,true,'unavailable identity hides the link');
  assert.equal(nodes.get('this-https-address').textContent,'');
  assert.equal(nodes.get('open-this-https').href,'#');
  location.search = '?returnTo='+encodeURIComponent('//evil.example/admin');
  assert.equal(context.page.sameHostHttpsSetupDestination(withoutHttp),'https://192.168.1.5:9443/.well-known/gameshowpro/?returnTo=%2F');
  location.search = '?returnTo=%2Fshows%2F1%3Fview%3Dlive';
  context.page.render({...withoutHttp,allowHttpsFallback:false});
  context.page.probe({...withoutHttp,allowHttpsFallback:false});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'the link requires the HTTPS session escape');
  context.page.render({...withoutHttp,allowHttpsFallback:undefined});
  context.page.probe({...withoutHttp,allowHttpsFallback:undefined});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'missing HTTPS support cannot promise this path');
  context.page.render({...withoutHttp,allowHttpFallback:undefined});
  context.page.probe({...withoutHttp,allowHttpFallback:undefined});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'an unknown HTTP fallback setting cannot promise this path');
  context.page.render(info);
  context.page.probe(info);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'the existing plain HTTP fallback keeps its behavior');
  for (const httpsPort of [undefined,0,-1,65536,'9443']) {
    context.page.render({...withoutHttp,httpsPort});
    context.page.probe({...withoutHttp,httpsPort});
    for(let i=0;i<8;i++) await Promise.resolve();
    assert.equal(nodes.get('http-to-https').hidden,true,'an invalid HTTPS port cannot create a link');
  }
  assert.equal(context.page.sameHostHttpsSetupDestination({...withoutHttp,httpsPort:443}),'https://192.168.1.5/.well-known/gameshowpro/?returnTo=%2Fshows%2F1%3Fview%3Dlive');
  location.hostname='localhost'; location.origin='http://localhost:8080';
  context.page.render(withoutHttp);
  context.page.probe(withoutHttp);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'localhost does not offer this address');
  location.hostname='[2001:db8::1]'; location.origin='http://[2001:db8::1]:8080';
  assert.equal(context.page.sameHostHttpsSetupDestination(withoutHttp),'https://[2001:db8::1]:9443/.well-known/gameshowpro/?returnTo=%2Fshows%2F1%3Fview%3Dlive');
  context.page.render(withoutHttp);
  context.page.probe(withoutHttp);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('this-https-address').textContent,'https://[2001:db8::1]:9443/');
  location.hostname='192.168.1.5'; location.origin='http://192.168.1.5:8080';
  context.fetch = async () => ({ok:true,json:async()=>withoutHttp});
  context.page.render(withoutHttp);
  context.page.probe(withoutHttp);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'a successful probe keeps the new link hidden');
  location.hostname='localhost'; location.origin='http://localhost:8080';
  context.page.render(info);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),[info.fallbackAddress]);
  assert.equal(nodes.get('qr').width, nodes.get('qr').height);
  assert.equal(nodes.get('facts').children[1].children[0].tagName,'code');
  nodes.get('copy-address').listeners.click();
  await Promise.resolve();
  assert.equal(copied,info.secureAddress);
  const oldInfo = {...info,secureAddress:undefined,setupAddress:undefined,fallbackAddress:undefined,allowHttpFallback:undefined};
  context.page.render(oldInfo);
  assert.equal(nodes.get('share-address').textContent,'https://show.local:9443/');
  assert.equal(nodes.get('setup-address').textContent,'http://show.local:8080/.well-known/gameshowpro/');
  assert.equal(nodes.get('fallback-block').hidden,true);
  context.page.render(info);
  location.protocol='https:'; location.hostname='other.local'; location.origin='https://other.local:9443'; location.port='9443';
  context.fetch = async () => { throw new Error('DNS unavailable'); };
  const soundlingInfo = {...info,allowHttpFallback:false};
  context.page.render(soundlingInfo);
  context.page.probe(soundlingInfo);
  assert.equal(nodes.get('https-fallback').hidden,true,'never offered before the probe fails');
  nodes.get('continue-https').listeners.click({preventDefault(){}});
  assert.equal(assigned,null,'the HTTPS action cannot run before the failed probe');
  assert.equal(document.cookie,'');
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-to-https').hidden,true,'HTTPS pages use the existing session escape');
  assert.equal(nodes.get('http-fallback').hidden,true,'the HTTPS escape is independent of HTTP fallback');
  assert.equal(nodes.get('https-fallback').hidden,false);
  nodes.get('continue-https').listeners.click({preventDefault(){}});
  assert.equal(document.cookie,'gsp-tlsca-https=1; Path=/; SameSite=Lax; Secure');
  assert.equal(assigned,'https://other.local:9443/shows/1?view=live');
  assert.doesNotMatch(document.cookie,/Max-Age|Expires/,'the HTTPS exception ends with this browser session');
  location.search = '?returnTo='+encodeURIComponent('//evil.example/');
  assigned = null;
  nodes.get('continue-https').listeners.click({preventDefault(){}});
  assert.equal(assigned,'https://other.local:9443/','an unsafe returnTo cannot change hosts');
  location.search = '?returnTo=%2Fshows%2F1%3Fview%3Dlive';
  context.page.probe({...soundlingInfo,allowHttpsFallback:undefined});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('https-fallback').hidden,true,'older firmware without the new field does not offer an unsupported bypass');
  context.page.probe({...soundlingInfo,allowHttpsFallback:false});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('https-fallback').hidden,true,'apps can switch off the HTTPS escape');
  location.protocol='http:';location.origin='http://other.local:8080';location.port='8080';
  assert.equal(context.page.sameHostHttpsDestination(info),null);
  context.page.probe(soundlingInfo);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('https-fallback').hidden,true,'the escape requires an HTTPS page');
  location.protocol='https:';location.hostname='localhost';location.origin='https://localhost:9443';location.port='9443';
  assert.equal(context.page.sameHostHttpsDestination(info),null);
  context.page.probe(soundlingInfo);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('https-fallback').hidden,true,'localhost never offers the HTTPS escape');
  location.hostname='show.local';location.origin='https://show.local:9443';
  context.page.probe(soundlingInfo);
  assert.equal(nodes.get('https-fallback').hidden,true,'the canonical HTTPS address never offers an escape');
  location.origin='https://show.local:9555';location.port='9555';
  assert.equal(context.page.sameHostHttpsDestination(info),null,'a different port on the canonical host does not qualify');
  context.page.probe(soundlingInfo);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('https-fallback').hidden,true,'a failed probe on the canonical hostname does not offer the escape');
  location.hostname='other.local';location.origin='https://other.local:9443';location.port='9443';
  context.page.render(info);
  context.page.probe(info);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,false);
  assert.equal(nodes.get('https-fallback').hidden,false);
  nodes.get('continue-http').listeners.click({preventDefault(){}});
  assert.equal(document.cookie,'gsp-tlsca-http=1; Path=/; SameSite=Lax');
  assert.equal(assigned,'http://other.local:8080/shows/1?view=live');
  context.page.probe({...info,allowHttpFallback:undefined});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,true);
  assert.equal(nodes.get('https-fallback').hidden,false);
  context.fetch = async () => ({ok:true,json:async()=>info});
  let redirectTimers = 0;
  context.setInterval = () => { redirectTimers++; return redirectTimers; };
  context.page.probe(info);
  for(let i=0;i<5;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,true);
  assert.equal(nodes.get('https-fallback').hidden,true,'a successful probe clears the HTTPS exception action');
  assigned = null;
  nodes.get('continue-https').listeners.click({preventDefault(){}});
  assert.equal(assigned,null,'a successful probe cannot use the HTTPS bypass');
  assert.equal(redirectTimers,0,'a successful probe starts no redirect countdown');
  assert.equal(replaced,null,'a successful probe never redirects automatically');
  assert.match(nodes.get('probe').children.map(child => child.textContent).join(' '), /HTTPS connection succeeded/i);
  // Your own certificate (ESP32 firmware only).
  const settle = async () => { for (let n = 0; n < 4; n++) await new Promise(resolve => setImmediate(resolve)); };
  const setPage = (protocol) => { location.protocol = protocol; location.hostname = 'show.local'; location.origin = protocol + '//show.local'; location.port = ''; };
  const fileOf = (text) => ({ text: async () => text, size: text.length });
  const respond = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => { if (body === undefined) throw new SyntaxError('no body'); return body; }, text: async () => String(body) });
  const device = { ...info, gate: 'boot', certificateUpload: true, certificateSource: 'ca', certificateDnsNames: ['show.local'], certificateRequestPending: false };
  const owned = { ...device, certificateSource: 'own', certificateNotAfter: 4102444800, certificateDnsNames: ['show.local', 'show.example.com'] };
  const text = (id) => nodes.get(id).textContent;
  const factValues = () => nodes.get('own-facts').children.map(child => child.children[0] ? child.children[0].textContent : child.textContent);
  const sent = [];
  const reply = (status, body) => { context.fetch = async (url, options) => { sent.push({ url, options, body: options && options.body ? JSON.parse(options.body) : null }); return respond(status, body); }; };
  const click = async (id) => { nodes.get(id).listeners.click(); await settle(); };

  setPage('http:');
  context.page.render(info);
  assert.equal(nodes.get('own-cert').hidden, true, 'no capability flag: the section stays hidden (.NET library)');
  context.page.render({ ...info, certificateUpload: false });
  assert.equal(nodes.get('own-cert').hidden, true);

  context.page.render(device);
  assert.equal(nodes.get('own-cert').hidden, false);
  assert.ok(factValues().includes('show.local'));
  assert.ok(factValues().some(value => /default/.test(value)));
  assert.ok(factValues().includes('None'), 'no signing request pending');
  assert.equal(nodes.get('own-key').disabled, true, 'key input disabled on plain HTTP');
  assert.equal(nodes.get('own-upload').disabled, true);
  assert.equal(nodes.get('own-key-reason').hidden, false);
  assert.equal(nodes.get('signed-upload').disabled, true, 'nothing pending yet');
  assert.equal(nodes.get('own-remove').disabled, true, 'nothing to remove');
  assert.equal(nodes.get('csr-link').hidden, true);
  assert.match(text('own-gate'), /within 5 minutes/);

  context.page.render(owned);
  assert.ok(factValues().some(value => /^Valid until/.test(value)));
  assert.ok(factValues().includes('show.local, show.example.com'));
  assert.equal(nodes.get('own-remove').disabled, false);
  context.page.render({ ...owned, certificateNotAfter: 1700000000 });
  assert.ok(factValues().some(value => /^Expired/.test(value)));
  context.page.render({ ...device, certificateRequestPending: true });
  assert.equal(nodes.get('csr-link').hidden, false);
  assert.equal(nodes.get('signed-upload').disabled, false);
  assert.equal(nodes.get('signed-hint').hidden, true);
  assert.equal(nodes.get('own-remove').disabled, false, 'a pending request can be removed');

  // Over HTTPS the key input is enabled.
  setPage('https:');
  context.page.render(device);
  assert.equal(nodes.get('own-key').disabled, false);
  assert.equal(nodes.get('own-upload').disabled, false);
  assert.equal(nodes.get('own-key-reason').hidden, true);

  // Upload certificate and key (HTTPS): one JSON body with time, certificate and key.
  document.getElementById('own-cert-file').files = [fileOf('CERT-PEM')];
  nodes.get('own-key').files = [fileOf('KEY-PEM')];
  sent.length = 0;
  reply(200, owned);
  await click('own-upload');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, '/.well-known/gameshowpro/certificate');
  assert.equal(sent[0].options.method, 'POST');
  assert.equal(sent[0].options.headers['Content-Type'], 'application/json');
  assert.equal(typeof sent[0].body.time, 'number');
  assert.ok(Math.abs(sent[0].body.time - Date.now() / 1000) < 60);
  assert.equal(sent[0].body.certificate, 'CERT-PEM');
  assert.equal(sent[0].body.key, 'KEY-PEM');
  assert.equal(nodes.get('own-result').className, 'ok note');
  assert.match(text('own-result'), /restarting its secure server/);
  assert.match(text('own-result'), /reload it/);
  assert.ok(factValues().includes('Your own certificate'), 'the page shows the fresh info.json');

  // Missing key file: nothing is sent.
  sent.length = 0;
  document.getElementById('own-cert-file').files = [fileOf('CERT-PEM')];
  nodes.get('own-key').files = [];
  await click('own-upload');
  assert.equal(sent.length, 0);
  assert.match(text('own-result'), /Choose the private key file first/);

  // A key is never sent over plain HTTP, even if the handler is reached.
  setPage('http:');
  nodes.get('own-key').files = [fileOf('KEY-PEM')];
  await click('own-upload');
  assert.equal(sent.length, 0);
  assert.match(text('own-result'), /secure \(https\) connection/);

  // Signing request (HTTP): body is only the time; the PEM is shown and the download link appears.
  context.page.render(device);
  reply(200, '-----BEGIN CERTIFICATE REQUEST-----');
  await click('csr-make');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, '/.well-known/gameshowpro/certificate/request');
  assert.deepEqual(Object.keys(sent[0].body), ['time']);
  assert.equal(nodes.get('csr-text').value, '-----BEGIN CERTIFICATE REQUEST-----');
  assert.equal(nodes.get('csr-text').hidden, false);
  assert.equal(nodes.get('csr-link').hidden, false);
  assert.equal(nodes.get('signed-upload').disabled, false);
  assert.match(text('own-result'), /Signing request created/);

  // Signed certificate without a key (HTTP).
  sent.length = 0;
  document.getElementById('signed-cert-file').files = [fileOf('SIGNED-PEM')];
  reply(200, owned);
  await click('signed-upload');
  assert.equal(sent[0].url, '/.well-known/gameshowpro/certificate');
  assert.deepEqual(Object.keys(sent[0].body).sort(), ['certificate', 'time']);
  assert.equal(sent[0].body.certificate, 'SIGNED-PEM');
  assert.match(text('own-result'), /plain HTTP page is not affected/);

  // Remove.
  sent.length = 0;
  reply(200, device);
  await click('own-remove');
  assert.equal(sent[0].url, '/.well-known/gameshowpro/certificate/remove');
  assert.deepEqual(Object.keys(sent[0].body), ['time']);
  assert.match(text('own-result'), /removed/);
  assert.equal(nodes.get('csr-text').hidden, true);

  // Errors: the device's own message for 400, 409 and 503; plain words for 403 and 415.
  document.getElementById('signed-cert-file').files = [fileOf('SIGNED-PEM')];
  context.page.render({ ...device, certificateRequestPending: true });
  for (const [status, message] of [[400, 'The private key does not belong to the server certificate.'], [409, 'Conflict text from the device.'], [503, 'The device is short of free memory; try again.']]) {
    reply(status, { error: message });
    await click('signed-upload');
    assert.equal(text('own-result'), message, 'status ' + status);
    assert.equal(nodes.get('own-result').className, 'bad note');
  }
  reply(400, undefined);
  await click('signed-upload');
  assert.match(text('own-result'), /status 400/);
  reply(503, undefined);
  await click('signed-upload');
  assert.match(text('own-result'), /short of memory/);
  reply(403, undefined);
  await click('signed-upload');
  assert.match(text('own-result'), /five minutes after the device powered up have passed/);
  assert.match(text('own-result'), /Power-cycle the device/);
  reply(403, undefined);
  await click('csr-make');
  assert.match(text('own-result'), /Power-cycle the device/);
  reply(415, undefined);
  await click('signed-upload');
  assert.match(text('own-result'), /status 415/);
  reply(500, undefined);
  await click('signed-upload');
  assert.match(text('own-result'), /status 500/);

  // A dropped connection (the HTTPS server restarting) is explained, not shown as an error.
  setPage('https:');
  context.fetch = async () => { throw new TypeError('Failed to fetch'); };
  await click('signed-upload');
  assert.equal(nodes.get('own-result').className, 'warn note');
  assert.match(text('own-result'), /restarts its secure server/);
  assert.match(text('own-result'), /reload this page/);

  // The section follows the capability flag.
  context.page.render(device);
  assert.equal(nodes.get('own-cert').hidden, false);
  context.page.render(info);
  assert.equal(nodes.get('own-cert').hidden, true);


  // The gate countdown (firmware: info.json has gateSecondsRemaining). The page counts down on its own clock and
  // disables the gated buttons at zero; a device without the field (the .NET library) is unchanged.
  const RealDate = Date;
  let fakeNow = RealDate.now();
  context.Date = class extends RealDate { static now() { return fakeNow; } };
  let gateTicks = [];
  context.setInterval = handler => { gateTicks.push(handler); return gateTicks.length; };
  context.clearInterval = () => {};
  const advance = (seconds) => { fakeNow += seconds * 1000; if (gateTicks.length) { gateTicks[gateTicks.length - 1](); } };
  const gated = ['renew', 'reset', 'csr-make', 'signed-upload', 'own-upload', 'own-remove'];
  setPage('https:');
  context.page.render({ ...device, certificateRequestPending: true, certificateSource: 'own', gateSecondsRemaining: 125 });
  assert.match(text('own-gate'), /another 2:05/);
  assert.match(text('gate'), /another 2:05/);
  assert.equal(nodes.get('renew').disabled, false);
  assert.equal(nodes.get('csr-make').disabled, false);
  advance(65);
  assert.match(text('own-gate'), /another 1:00/);
  advance(59);
  assert.match(text('own-gate'), /another 0:01/);
  assert.equal(nodes.get('csr-make').disabled, false, 'one second left: still open');
  advance(1);
  for (const id of gated) { assert.equal(nodes.get(id).disabled, true, id + ' disabled at zero'); }
  assert.match(text('own-gate'), /Power-cycle the device/);
  assert.match(text('own-gate'), /have passed/);
  assert.match(text('gate'), /Power-cycle the device/);
  // Already closed at load (not a power-up): disabled at once, no timer needed.
  context.page.render({ ...device, certificateRequestPending: true, certificateSource: 'own', gateSecondsRemaining: 0 });
  for (const id of gated) { assert.equal(nodes.get(id).disabled, true, id + ' disabled when closed at load'); }
  assert.match(text('own-gate'), /Power-cycle the device/);
  // A fresh info.json with time left (reload after a power cycle) enables them again.
  context.page.render({ ...device, certificateRequestPending: true, certificateSource: 'own', gateSecondsRemaining: 300 });
  for (const id of gated) { assert.equal(nodes.get(id).disabled, false, id + ' enabled with time left'); }
  assert.match(text('own-gate'), /another 5:00/);
  // No field (the .NET library, an older firmware): the original wording and no disabling.
  context.page.render({ ...device, certificateRequestPending: true, certificateSource: 'own' });
  assert.match(text('own-gate'), /within 5 minutes/);
  assert.equal(nodes.get('renew').disabled, false);
  assert.equal(nodes.get('own-remove').disabled, false);
  context.page.render({ ...info, gate: 'loopback', gateSecondsRemaining: 0 });
  assert.equal(nodes.get('renew').disabled, false, 'only the boot gate counts down');

  // Each 403 reason has its own wording; no body, an unknown reason and the .NET code fall back to the gate's.
  context.page.render({ ...device, certificateRequestPending: true, gateSecondsRemaining: 200 });
  const reasons = {
    'gate-closed': /five minutes after the device powered up have passed/,
    host: /address the device does not accept as its own/,
    origin: /different web address/,
  };
  for (const [reason, pattern] of Object.entries(reasons)) {
    context.page.render({ ...device, certificateRequestPending: true, gateSecondsRemaining: 200 });
    reply(403, { error: 'ignored text', reason });
    await click('signed-upload');
    assert.match(text('own-result'), pattern, 'own section, ' + reason);
    assert.equal(nodes.get('own-result').className, 'bad note');
    context.page.render({ ...device, certificateRequestPending: true, gateSecondsRemaining: 200 });
    reply(403, { error: 'ignored text', reason });
    await click('renew');
    assert.match(text('result'), pattern, 'renew, ' + reason);
    assert.equal(nodes.get('result').className, 'bad note');
  }
  // gate-closed also closes the page's own gate (its clock was wrong or another session used the window).
  context.page.render({ ...device, certificateRequestPending: true, gateSecondsRemaining: 200 });
  reply(403, { error: 'x', reason: 'gate-closed' });
  await click('csr-make');
  assert.equal(nodes.get('csr-make').disabled, true);
  assert.equal(nodes.get('renew').disabled, true);
  assert.match(text('own-gate'), /have passed/);
  for (const body of [undefined, { error: 'x', reason: 'refused' }, { error: 'x', reason: 'unheard-of' }, { error: 'x' }, null]) {
    context.page.render({ ...device, certificateRequestPending: true });
    reply(403, body);
    await click('signed-upload');
    assert.match(text('own-result'), /five minutes after the device powered up have passed, or this page was opened by an address/, 'fallback ' + JSON.stringify(body));
    reply(403, body);
    await click('renew');
    assert.match(text('result'), /power-cycle the device first/, 'renew fallback ' + JSON.stringify(body));
  }

  const elementText = node => (node.textContent || '') + node.children.map(elementText).join(' ');
  const pageText = id => elementText(nodes.get(id));
  // A successful browser fetch proves that HTTPS responded, but it does not prove
  // that the user installed the CA: Firefox can have a per-site exception. Keep
  // the install controls available and offer an explicit, safe link without redirecting.
  const successfulConnectionCheck = async (hostname, deviceInfo) => {
    setPage('http:');
    location.hostname = hostname; location.origin = 'http://' + hostname; location.port = '';
    replaced = null;
    let timerCount = 0;
    context.setInterval = () => { timerCount++; return timerCount; };
    context.clearInterval = () => {};
    context.fetch = async () => ({ ok: true, json: async () => deviceInfo });
    context.page.render(deviceInfo);
    context.page.probe(deviceInfo);
    for (let n = 0; n < 12; n++) await Promise.resolve();
    const message = pageText('probe');
    const links = [];
    const visit = node => { if (node.tagName === 'a') links.push(node); node.children.forEach(visit); };
    visit(nodes.get('probe'));
    assert.match(message, /HTTPS connection succeeded/i);
    assert.match(message, /cannot verify.*(certificate|authority)|does not (prove|confirm).*install/i);
    assert.doesNotMatch(message, /trusted|trusts this device/i);
    assert.equal(nodes.get('install').hidden, false, 'the certificate download/install section stays visible');
    assert.equal(replaced, null, 'a successful check never redirects automatically');
    assert.equal(timerCount, 0, 'a successful check starts no redirect countdown');
    if (hostname === 'localhost') { assert.equal(links.length, 0, 'localhost keeps the page on the install/download view'); }
    else { assert.ok(links.some(link => link.href === 'https://show.local:9443/shows/1?view=live'), 'explicit secure link keeps the safe returnTo for ' + hostname + '; actual=' + JSON.stringify(links.map(link => link.href)) + '; children=' + JSON.stringify(nodes.get('probe').children.map(node => [node.tagName, node.textContent, node.href]))); }
  };
  const upload = { ...info, gate: 'loopback', certificateUpload: true, certificateSource: 'ca', certificateDnsNames: [], certificateRequestPending: false };
  await successfulConnectionCheck('other.local', upload);
  await successfulConnectionCheck('localhost', upload);
  // The canonical HTTPS page can use the same success message without a network fetch.
  location.protocol = 'https:'; location.hostname = 'show.local'; location.origin = 'https://show.local:9443'; location.port = '9443';
  replaced = null;
  context.page.render(upload);
  context.page.probe(upload);
  assert.match(pageText('probe'), /HTTPS connection succeeded/i);
  assert.doesNotMatch(pageText('probe'), /trusted|trusts this device/i);
  assert.equal(nodes.get('install').hidden, false, 'canonical HTTPS keeps certificate download/install controls visible');
  assert.equal(replaced, null, 'canonical HTTPS does not trigger navigation');
  assert.ok(nodes.get('probe').children.some(node => node.tagName === 'a' && node.href === 'https://show.local:9443/shows/1?view=live'));

  // Connection probe guidance is diagnosis only. Drive its timeout explicitly so the
  // warning and retry behavior do not depend on wall-clock timing.
  setPage('http:');
  location.hostname = 'other.local'; location.origin = 'http://other.local:8080'; location.port = '8080';
  const probeTimers = new Map();
  let nextProbeTimer = 0;
  context.setTimeout = (handler, delay) => { const id = ++nextProbeTimer; probeTimers.set(id, { handler, delay }); return id; };
  context.clearTimeout = id => { probeTimers.delete(id); };
  const defaultPortInfo = { ...withoutHttp, secureAddress: 'https://show.local/' };
  context.fetch = (url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')));
  });
  context.page.render(defaultPortInfo);
  context.page.probe(defaultPortInfo);
  assert.equal(nodes.get('setup-connection').hidden, false, 'setup transport guidance is visible');
  assert.match(pageText('setup-connection'), /HTTP/i);
  assert.doesNotMatch(pageText('setup-connection'), /HTTPS/i, 'setup guidance reports the page transport only');
  const timeout = [...probeTimers.values()].find(timer => timer.delay === 5000);
  assert.ok(timeout, 'probe has a five second timeout');
  timeout.handler();
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /timed out/i);
  assert.match(pageText('probe'), /443/, 'default HTTPS port is shown as the TCP port');
  assert.equal(nodes.get('connection-help').hidden, false, 'failure reveals connection-help');
  const helpMarkup = pageHtml.match(/<details id="connection-help"[\s\S]*?<\/details>/)[0];
  assert.match(helpMarkup, /firewall/i);
  assert.match(helpMarkup, /name/i);
  assert.match(helpMarkup, /network/i);
  assert.doesNotMatch(helpMarkup, /confirmed|definitely|must be/i);
  assert.doesNotMatch(pageText('probe'), /install.*certificate/i, 'primary diagnosis does not recommend installing a certificate');

  // The deadline also covers a stalled response body, after HTTPS headers arrived.
  context.fetch = async (url, options) => ({ ok: true, json: () => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('body aborted')));
  }) });
  context.page.probe(info);
  for (let i = 0; i < 4; i++) await Promise.resolve();
  [...probeTimers.values()].find(timer => timer.delay === 5000).handler();
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /timed out/i, 'body timeout is not reported as malformed metadata');
  assert.match(pageText('probe'), /9443/, 'configured non-default port is shown');

  context.page.render(defaultPortInfo);
  assert.equal(nodes.get('connection-help').hidden, true, 'fresh identity metadata clears old connection-help');
  assert.equal(nodes.get('retry-probe').hidden, true, 'fresh identity metadata clears retry');

  // Immediate fetch failures allow certificate and network possibilities without
  // claiming which one happened; HTTP responses retain their status code.
  context.fetch = async () => { throw new TypeError('Failed to fetch'); };
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /certificate/i);
  assert.match(pageText('probe'), /network/i);
  assert.doesNotMatch(pageText('probe'), /certificate is invalid|certificate mismatch/i);
  context.fetch = async () => ({ ok: false, status: 503, json: async () => ({}) });
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /503/);

  // A different certificate identity is a terminal result: do not offer either
  // address fallback, even when both are configured.
  context.fetch = async () => ({ ok: true, json: async () => ({ ...info, caFingerprintSha256: '11:22' }) });
  context.page.render(info);
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /different certificate identity|another device/i);
  assert.equal(nodes.get('http-fallback').hidden, true);
  assert.equal(nodes.get('https-fallback').hidden, true);

  context.fetch = async () => ({ ok: true, json: async () => ({ product: 'App' }) });
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /unexpected response/i);
  assert.doesNotMatch(pageText('probe'), /timed out|another identity/i);

  context.fetch = async () => ({ ok: true, json: async () => { throw new SyntaxError('invalid JSON'); } });
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.match(pageText('probe'), /unexpected response/i, 'invalid JSON is distinguished from transport failure');

  // Retry clears the previous diagnosis and fallback actions while the request
  // is pending, then restores the normal successful connection flow.
  let finishRetry;
  context.fetch = () => new Promise(resolve => { finishRetry = resolve; });
  const retry = nodes.get('retry-probe');
  assert.equal(typeof retry.onclick, 'function');
  assert.equal(retry.disabled, false);
  retry.onclick({ preventDefault() {} });
  assert.equal(retry.disabled, true, 'retry is disabled while its probe is pending');
  assert.equal(nodes.get('connection-help').hidden, true, 'retry clears connection-help');
  assert.equal(nodes.get('http-fallback').hidden, true, 'retry clears old fallback actions');
  assert.equal(nodes.get('https-fallback').hidden, true);
  finishRetry({ ok: true, json: async () => info });
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.equal(retry.disabled, true, 'completed retry remains unavailable while hidden');
  assert.equal(nodes.get('retry-probe').hidden, true, 'success clears retry');
  assert.equal(nodes.get('connection-help').hidden, true);
  assert.equal(nodes.get('http-fallback').hidden, true, 'success returns to canonical secure address');

  // An older in-flight failure cannot replace the result of a newer successful probe.
  let finishOld;
  context.fetch = () => new Promise(resolve => { finishOld = resolve; });
  context.page.probe(info);
  for (let i = 0; i < 2; i++) await Promise.resolve();
  context.fetch = async () => ({ ok: true, json: async () => info });
  context.page.probe(info);
  for (let i = 0; i < 12; i++) await Promise.resolve();
  finishOld({ ok: false, status: 502, json: async () => ({}) });
  for (let i = 0; i < 12; i++) await Promise.resolve();
  assert.doesNotMatch(pageText('probe'), /502|timed out|another identity/i, 'stale completion is ignored');

  console.log('Page script: safe paths, QR, localhost address block, fallback gate/cookie, connection checks, own-certificate section, gate countdown and 403 reasons passed.');
})().catch(error => { console.error(error); process.exitCode=1; });
