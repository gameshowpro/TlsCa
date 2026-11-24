const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
let source = fs.readFileSync(path.join(__dirname, '..', 'src', 'GameshowPro.TlsCa', 'wwwroot', 'management.html'), 'utf8').split('<script>')[1].split('</script>')[0];
source = source.replace('  fetch(P + "info.json", { cache: "no-store" })', '  globalThis.page = { safeReturnTo, secureDestination, sameHostHttpDestination, render, probe };\n  fetch(P + "info.json", { cache: "no-store" })');
const nodes = new Map();
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.hidden = true; this.style = {}; this.textContent = ''; this.listeners = {}; this.firstChild = null; }
  appendChild(child) { this.children.push(child); this.firstChild = this.children[0]; this.lastChild = child; return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); this.firstChild = this.children[0] || null; }
  insertBefore(child) { this.children.unshift(child); this.firstChild = child; }
  setAttribute() {}
  addEventListener(name, handler) { this.listeners[name] = handler; }
  getContext() { return { fillRect() {}, set fillStyle(value) {} }; }
}
const document = { title: '', cookie: '', createElement: tag => new Element(tag), getElementById: id => { if (!nodes.has(id)) nodes.set(id, new Element(id)); return nodes.get(id); } };
let calls = [], replaced = null, assigned = null, copied = null;
const info = { product:'App', mdnsName:'show.local', httpsPort:9443, caFingerprintSha256:'AA:BB', caNotAfter:4102444800, leafNotBefore:1700000000, leafNotAfter:4102444800, gate:'loopback', secureAddress:'https://show.local:9443/', setupAddress:'http://show.local:8080/', fallbackAddress:'http://192.168.1.5:8080/', allowHttpFallback:true };
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
  context.page.render(info);
  assert.equal(nodes.get('other-computers').hidden,true);
  location.protocol='http:';location.hostname='localhost';location.origin='http://localhost:8080';location.port='8080';
  context.page.render(info);
  assert.equal(nodes.get('other-computers').hidden,false);
  assert.equal(nodes.get('share-address').textContent,info.secureAddress);
  assert.equal(nodes.get('setup-address').textContent,info.setupAddress);
  assert.equal(nodes.get('fallback-block').hidden,false);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),[info.fallbackAddress]);
  const multiple = {...info,fallbackAddresses:['http://192.168.1.5:8080/','http://10.0.0.5:8080/']};
  context.page.render(multiple);
  assert.deepEqual(nodes.get('fallback-addresses').children.map(item=>item.children[0].textContent),multiple.fallbackAddresses);
  assert.equal(nodes.get('fallback-block').hidden,false);
  context.page.render({...info,fallbackAddresses:[]});
  assert.equal(nodes.get('fallback-addresses').children.length,0);
  assert.equal(nodes.get('fallback-block').hidden,true);
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
  context.page.probe(info);
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,false);
  nodes.get('continue-http').listeners.click({preventDefault(){}});
  assert.equal(document.cookie,'gsp-tlsca-http=1; Path=/; SameSite=Lax');
  assert.equal(assigned,'http://other.local:8080/shows/1?view=live');
  context.page.probe({...info,allowHttpFallback:undefined});
  for(let i=0;i<8;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,true);
  context.fetch = async () => ({ok:true,json:async()=>info});
  let tick;
  context.setInterval = handler => { tick=handler; return 1; };
  context.page.probe(info);
  for(let i=0;i<5;i++) await Promise.resolve();
  assert.equal(nodes.get('http-fallback').hidden,true);
  assert.equal(typeof tick,'function');
  for(let i=0;i<5;i++) tick();
  assert.equal(replaced,'https://show.local:9443/shows/1?view=live');
  console.log('Page script: safe paths, QR, localhost address block, fallback gate/cookie, wrong-host trust probe and forward passed.');
})().catch(error => { console.error(error); process.exitCode=1; });
