// Run with jsdom on NODE_PATH. Exercises the actual About panel source with
// a mocked native bridge: no network downloads or installation are performed.
const {JSDOM} = require('jsdom');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const html = fs.readFileSync('/src/apps/windows/cmd/pqcsign-desktop/frontend/dist/index.html','utf8');
const start=html.indexOf('  $("verTag").textContent = APP_VERSION;');
const panel = html.slice(start,html.indexOf('  $("srv").value = state.srv;',start));
const dom = new JSDOM('<div><span id="verTag"></span></div>', {runScripts:'outside-only'});
const win = dom.window;
win.HTMLDialogElement.prototype.showModal = function(){this.open=true};
win.HTMLDialogElement.prototype.close = function(){this.open=false};
let release=null, error=null, resolveDownload, installs=0;
win.call = async name => {
 if(name==='CheckUpdate') {if(error)throw Error(error);return JSON.stringify(release)}
 if(name==='DownloadUpdate') return new Promise(resolve=>resolveDownload=resolve);
 if(name==='InstallUpdate') {installs++}
 throw Error(name);
};
win.confirm=()=>true;
win.eval('const $=id=>document.getElementById(id); const APP_VERSION="v0.7.2"; '+panel);
const $=id=>win.document.getElementById(id);
(async()=>{
 assert.equal($('aboutVersion').textContent,'v0.7.2');
 assert.equal($('updateInstall').hidden,true);
 await $('updateCheck').onclick();
 assert.match($('updateStatus').textContent,/sudah terbaru/);
 error='offline';await $('updateCheck').onclick();
 assert.match($('updateStatus').textContent,/gagal/);assert.equal($('updateCheck').disabled,false);
 error=null;release={version:'0.8.0',size:1048576,notes:'Perbaikan <script>unsafe</script>'};
 await $('updateCheck').onclick();assert.equal($('updateDownload').hidden,false);
 assert.equal($('updateNotes').children.length,0);
 const downloading=$('updateDownload').onclick();
 assert.equal($('updateProgress').hidden,false);assert.equal($('updateInstall').hidden,true);
 assert.equal($('updateDownload').disabled,true);assert.equal(installs,0);
 resolveDownload();await downloading;
 assert.equal($('updateInstall').hidden,false);assert.equal($('updateInstall').disabled,false);
 assert.equal($('updateCheck').disabled,true);assert.equal(installs,0);
 assert.match($('updateStatus').textContent,/terverifikasi/);
 $('aboutClose').onclick();win.document.querySelector('button').onclick();
 assert.equal($('updateInstall').hidden,false);
 await $('updateInstall').onclick();assert.equal(installs,1);
 console.log('About UI: current/error/new/download/verified/reopen/explicit-install PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
