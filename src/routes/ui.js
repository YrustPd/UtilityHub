import { htmlResponse, randomId } from '../helpers/utils.js';

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizePrefix(prefix) {
  if (!prefix || prefix === '/') return '/';
  const trimmed = prefix.replace(/\/+$/, '');
  return `${trimmed}/`;
}

function inlineCss() {
  return `:root{color-scheme:dark;--bg:#040506;--panel:#0b0d12;--border:#1a1c24;--text:#f6f8fb;--muted:#9aa2b4;--neon-green:#7cfa4c;--neon-magenta:#ff7bd2;--link:#9bc7ff;}*{box-sizing:border-box}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}body{margin:0;min-height:100vh;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}a{color:inherit;text-decoration:none}.container{width:min(1200px,92vw);margin:0 auto 52px}.page-header,.page-footer{width:min(1200px,92vw);margin:34px auto 20px;display:flex;align-items:center;justify-content:space-between;gap:22px;color:var(--muted)}.brand{display:flex;align-items:center;gap:14px}.logo-dot{width:16px;height:16px;border-radius:50%;background:var(--neon-green);box-shadow:0 0 6px rgba(124,250,76,0.7),0 0 12px rgba(124,250,76,0.35)}.brand-name{font-weight:750;color:var(--text);font-size:1.6rem}.brand-tagline{color:var(--muted);font-size:0.92rem}.meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.meta-item{padding:6px 12px;border:1px solid var(--border);border-radius:8px;background:var(--panel);color:var(--muted);font-size:0.9rem}.meta-link{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:6px 10px;text-decoration:none;cursor:pointer;transition:color 140ms ease,border-color 140ms ease,box-shadow 140ms ease}.meta-link svg{width:22px;height:22px;fill:currentColor}.meta-link:hover{color:var(--text);border-color:rgba(255,255,255,0.25);box-shadow:0 0 10px rgba(155,199,255,0.18)}.meta-link:focus-visible{outline:2px solid rgba(155,199,255,0.45);outline-offset:2px}.intro .lede{margin:0;color:var(--muted);max-width:720px;line-height:1.6}.placeholder-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;margin-top:24px}.search-box{margin:16px auto 30px;width:min(480px,92vw);text-align:center}.search-box input[type='search']{width:100%;padding:12px 14px;border-radius:10px;border:1px solid var(--border);background:var(--panel);color:var(--text);font-size:1rem;transition:border-color 120ms ease,box-shadow 120ms ease}.search-box input[type='search']::placeholder{color:var(--muted)}.search-box input[type='search']:focus{outline:2px solid rgba(124,250,76,0.55);outline-offset:1px;border-color:rgba(124,250,76,0.7);box-shadow:0 0 0 3px rgba(124,250,76,0.08)}.section-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin:44px 0 18px;flex-wrap:wrap}.section-heading h2{margin:0;font-size:1.35rem;font-weight:720;color:var(--text);display:flex;align-items:center;gap:10px}.section-heading .section-count{display:inline-flex;align-items:center;justify-content:center;min-width:20px;padding:2px 8px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,0.05);color:var(--muted);font-size:0.85rem}.section-heading .section-chevron{display:none;font-size:0.9rem;color:var(--muted);opacity:0.8;transition:transform 160ms ease}.section-heading p{margin:0;color:var(--muted)}.section-heading:focus-visible{outline:2px solid rgba(124,250,76,0.35);outline-offset:3px}.section-controls{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.is-empty{display:none}.card{position:relative;overflow:hidden;background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0)),var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:0 6px 18px rgba(0,0,0,0.35),0 2px 6px rgba(0,0,0,0.22);transition:border-color 140ms ease,transform 140ms ease,box-shadow 140ms ease;cursor:pointer}.card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:rgba(255,255,255,0.08);opacity:0.9;pointer-events:none;transition:background-color 140ms ease,box-shadow 140ms ease}.card:has(.chip.get)::before{background:linear-gradient(180deg,rgba(124,250,76,0.7),rgba(124,250,76,0.4));}.card:has(.chip.post)::before{background:linear-gradient(180deg,rgba(255,123,210,0.75),rgba(255,123,210,0.45));}.card:hover,.card:focus-within{border-color:rgba(255,255,255,0.22);box-shadow:0 10px 26px rgba(0,0,0,0.4),0 0 0 1px rgba(124,250,76,0.18),0 0 18px rgba(124,250,76,0.2);transform:translateY(-1px)}.card:has(.chip.post):hover,.card:has(.chip.post):focus-within{border-color:rgba(255,123,210,0.6);box-shadow:0 10px 26px rgba(0,0,0,0.4),0 0 0 1px rgba(255,123,210,0.2),0 0 18px rgba(255,123,210,0.22)}.card:has(.chip.get):hover,.card:has(.chip.get):focus-within{border-color:rgba(124,250,76,0.55)}.card:focus-within::before,.card:hover::before{box-shadow:0 0 10px rgba(124,250,76,0.25)}.card:has(.chip.post):focus-within::before,.card:has(.chip.post):hover::before{box-shadow:0 0 10px rgba(255,123,210,0.25)}.card-header{display:flex;align-items:center;justify-content:space-between;gap:10px}.card h3{margin:0;font-size:1.18rem;font-weight:720;color:var(--text)}.card p{margin:10px 0 0;color:var(--muted);line-height:1.5}.card code{display:inline-block;margin-top:10px;padding:8px 10px;background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:10px;color:var(--link);font-size:0.9rem;cursor:pointer;white-space:pre-wrap;word-break:break-word;overflow:auto;text-shadow:0 0 6px rgba(155,199,255,0.35)}.card code:hover{text-decoration:underline;color:#c7d3ff}.card.hidden{display:none}.chip{padding:6px 11px;border-radius:999px;background:rgba(255,255,255,0.05);color:var(--text);border:1px solid rgba(255,255,255,0.12);font-size:0.85rem;box-shadow:0 0 8px rgba(0,0,0,0.35)}.chip.get{color:var(--neon-green);border-color:rgba(124,250,76,0.55);background:rgba(124,250,76,0.12);text-shadow:0 0 6px rgba(124,250,76,0.35)}.chip.post{color:var(--neon-magenta);border-color:rgba(255,123,210,0.55);background:rgba(255,123,210,0.1);text-shadow:0 0 6px rgba(255,123,210,0.35)}.advanced-toggle{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;transition:border-color 160ms ease}.advanced-toggle:hover{border-color:rgba(255,255,255,0.12)}.advanced-toggle:focus-visible{outline:2px solid rgba(124,250,76,0.55);outline-offset:2px}.hidden-advanced{display:none}.status-pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,0.04);color:var(--muted);font-size:0.85rem}.status-pill[data-state='on']{border-color:rgba(124,250,76,0.45);color:var(--neon-green);text-shadow:0 0 6px rgba(124,250,76,0.35)}.status-pill[data-state='unknown']{border-color:rgba(255,255,255,0.15)}.toast-container{position:fixed;left:50%;bottom:calc(16px + env(safe-area-inset-bottom));transform:translateX(-50%);display:flex;flex-direction:column;gap:8px;z-index:99999;pointer-events:none}.toast{min-width:200px;max-width:360px;margin:0 auto;padding:10px 14px;border-radius:10px;border:1px solid var(--border);background:rgba(14,16,22,0.95);color:var(--text);box-shadow:0 4px 14px rgba(0,0,0,0.35),0 0 10px rgba(124,250,76,0.12);font-size:0.95rem;text-align:center;opacity:0;transform:translateY(8px);pointer-events:none;transition:opacity 200ms ease,transform 200ms ease}.toast.show{opacity:1;transform:translateY(0)}@media (prefers-reduced-motion: reduce){.toast{transition:none;transform:none}}.page-footer{justify-content:center;color:var(--muted);margin-bottom:32px}.divider{margin:0 8px}@media(max-width:640px){.section-heading{align-items:center;cursor:pointer;background:rgba(255,255,255,0.02);padding:8px 10px;border-radius:10px}.section-heading .section-chevron{display:inline-block}.section-heading[aria-expanded="true"] .section-chevron{transform:rotate(90deg)}.section-collapsed .placeholder-grid{display:none}.section-heading h2{font-size:1.1rem}.section-heading:hover{background:rgba(255,255,255,0.04)}}
@media(max-width:640px){.page-header{flex-direction:column;align-items:flex-start;gap:12px;margin:26px auto 14px}.meta{justify-content:flex-start;width:100%}.search-box{width:min(420px,92vw);margin:12px auto 24px}.placeholder-grid{grid-template-columns:1fr}.card{padding:16px}.card h3{font-size:1.08rem}.page-footer{margin-top:10px}}@media(max-width:480px){.card{padding:15px}.card code{font-size:0.88rem}.brand-name{font-size:1.32rem}.section-heading{margin:34px 0 14px}.search-box input[type='search']{padding:11px 12px}}`;
}

function inlineJs() {
  return `(function bootstrap(){
const cards=Array.from(document.querySelectorAll('.card'));
const mobileMq=window.matchMedia('(max-width: 640px)');
const sectionInfo=Array.from(document.querySelectorAll('section[data-section-id]')).map((el)=>({el,id:el.dataset.sectionId||'',heading:el.querySelector('.section-heading'),countEls:Array.from(el.querySelectorAll('.section-count'))}));
const searchInput=document.getElementById('filter');
const advancedToggle=document.getElementById('advanced-toggle');
const advancedLabel=document.getElementById('advanced-label');
const advancedSections=Array.from(document.querySelectorAll('[data-advanced]'));
let advancedOpen=false;let toastBox=null;let toastTimer=null;let searchTimer=null;let sectionState={};
const accordionKey='uh-section-state';
function isMobile(){return mobileMq.matches;}
function loadAccordionState(){try{const raw=localStorage.getItem(accordionKey);return raw?JSON.parse(raw):{};}catch(_){return{};}}
function saveAccordionState(){if(!isMobile())return;try{localStorage.setItem(accordionKey,JSON.stringify(sectionState));}catch(_){}}
function setSectionExpanded(info,expanded,{persist=false}={}){if(!info)return;const shouldExpand=isMobile()?expanded:true;info.el.classList.toggle('section-collapsed',!shouldExpand);if(info.heading)info.heading.setAttribute('aria-expanded',shouldExpand?'true':'false');if(persist&&isMobile()){sectionState[info.id]=shouldExpand;saveAccordionState();}}
sectionState=loadAccordionState();
function initAccordion(){const mobile=isMobile();sectionInfo.forEach((info)=>{const stored=sectionState[info.id];const defaultExpandedMobile=false;const shouldExpand=mobile?(stored!==undefined?stored:defaultExpandedMobile):true;setSectionExpanded(info,shouldExpand,{persist:false});if(info.heading){info.heading.setAttribute('role','button');info.heading.setAttribute('tabindex',mobile?'0':'-1');info.heading.addEventListener('click',(e)=>{if(!isMobile())return;if(e.target.closest('.section-controls'))return;const expanded=info.el.classList.contains('section-collapsed');setSectionExpanded(info,expanded,{persist:true});});info.heading.addEventListener('keydown',(e)=>{if(!isMobile())return;if(e.key==='Enter'||e.key===' '){e.preventDefault();const expanded=info.el.classList.contains('section-collapsed');setSectionExpanded(info,expanded,{persist:true});}});}});}
function syncHeadingTabIndex(){const mobile=isMobile();sectionInfo.forEach((info)=>{if(info.heading)info.heading.setAttribute('tabindex',mobile?'0':'-1');});}

function visibleCard(card){return !card.classList.contains('hidden')&&!card.classList.contains('hidden-advanced');}
function refreshSectionVisibility(query=''){const mobile=isMobile();sectionInfo.forEach((info)=>{const cardsInSection=Array.from(info.el.querySelectorAll('.card'));const visibleCards=cardsInSection.filter((card)=>visibleCard(card));const hasVisible=visibleCards.length>0;info.el.classList.toggle('is-empty',!hasVisible);info.countEls.forEach((el)=>{el.textContent=visibleCards.length;});if(mobile){if(query){setSectionExpanded(info,hasVisible,{persist:false});}else{const stored=Object.prototype.hasOwnProperty.call(sectionState,info.id)?sectionState[info.id]:false;setSectionExpanded(info,stored,{persist:false});}}else{setSectionExpanded(info,true,{persist:false});}});}
function applyFilter(term){const query=(term||'').toLowerCase().trim();cards.forEach((card)=>{const haystack=(card.dataset.search||'').toLowerCase();const match=!query||haystack.includes(query);card.classList.toggle('hidden',!match);});refreshSectionVisibility(query);}
function scheduleFilter(value){if(searchTimer){clearTimeout(searchTimer);}const pending=value;searchTimer=setTimeout(()=>{applyFilter(pending);searchTimer=null;},120);}
if(searchInput){searchInput.addEventListener('input',(event)=>scheduleFilter(event.target.value));}
function renderAdvancedLabel(){if(advancedLabel){advancedLabel.textContent=advancedOpen?'Advanced: On':'Advanced: Off';}}
function toggleAdvanced(open){advancedOpen=open;advancedSections.forEach((section)=>{section.classList.toggle('hidden-advanced',!advancedOpen);});if(advancedToggle){advancedToggle.setAttribute('aria-pressed',advancedOpen?'true':'false');}renderAdvancedLabel();refreshSectionVisibility(searchInput?.value||'');}
if(advancedToggle){advancedToggle.addEventListener('click',()=>toggleAdvanced(!advancedOpen));}
initAccordion();toggleAdvanced(false);applyFilter('');
mobileMq.addEventListener('change',()=>{syncHeadingTabIndex();refreshSectionVisibility(searchInput?.value||'');});
function ensureToast(){if(toastBox&&document.body.contains(toastBox))return toastBox;toastBox=document.getElementById('uh-toast');if(!toastBox){toastBox=document.createElement('div');toastBox.id='uh-toast';toastBox.className='toast-container';toastBox.setAttribute('aria-live','polite');toastBox.setAttribute('role','status');try{document.body.appendChild(toastBox);}catch(err){console.warn('UtilityHub toast init failed',err);return null;}}return toastBox;}function showToast(message){const box=ensureToast();if(!box){console.warn('Toast unavailable:',message);return;}if(toastTimer){clearTimeout(toastTimer);toastTimer=null;}box.textContent='';const toast=document.createElement('div');toast.className='toast';toast.textContent=message;box.appendChild(toast);const reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;if(reduce)toast.style.transition='none';requestAnimationFrame(()=>toast.classList.add('show'));toastTimer=setTimeout(()=>{toast.classList.remove('show');toastTimer=setTimeout(()=>{toast.remove();toastTimer=null;},200);},1200);}function copy(text){const payload=text||'';if(!navigator.clipboard){showToast('Copy failed • Use long-press to select');return;}navigator.clipboard.writeText(payload).then(()=>{const clean=payload.trim();const preview=clean?(clean.length>28?clean.slice(0,25)+'…':clean):'';const msg=preview?'Copied '+preview:'Copied endpoint';showToast(msg);}).catch(()=>{showToast('Copy failed • Use long-press to select');});}

document.addEventListener('click',(event)=>{const codeTarget=event.target.closest('code[data-copy]');if(codeTarget){event.preventDefault();event.stopPropagation();const text=codeTarget.textContent?.trim()||'';copy(text);return;}const card=event.target.closest('.card');if(card){event.preventDefault();const path=card.querySelector('code[data-copy]')?.textContent?.trim()||'';if(!path)return;const absPath=path.startsWith('/')?path:'/'+path;let targetUrl;try{targetUrl=new URL(absPath,window.location.origin);}catch(_){showToast('Invalid path');return;}if(targetUrl.origin!==window.location.origin){showToast('Blocked cross-origin');return;}window.open(targetUrl.href,'_blank','noopener');}});
})();`;
}


export async function handleUi(request, env, ctx, meta = {}) {
  const { config, hostname, url } = meta;
  const nonce = randomId(16);
  const prefix = normalizePrefix(config.prefix);
  const prefixEsc = escapeHtml(prefix);
  const name = escapeHtml(config.name);
  const tagline = escapeHtml(config.tagline);
  const version = escapeHtml(config.version);
  const hostEsc = escapeHtml(hostname);
  const ogImage = escapeHtml(`${url.origin}${prefix}apple-touch-icon.png`);

  const seoTitle = 'UtilityHub — Minimal Edge Utilities for Diagnostics, Crypto, and APIs';
  const seoDescription = 'Cloudflare Worker utility hub for diagnostics, crypto helpers, and developer APIs.';
  const seoTitleEsc = escapeHtml(seoTitle);
  const seoDescriptionEsc = escapeHtml(seoDescription);
  const canonicalRaw = `${url.origin}${prefix}`;
  const canonical = escapeHtml(canonicalRaw);
  const ldJson = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: seoTitle,
    description: seoDescription,
    applicationCategory: 'DeveloperTool',
    operatingSystem: 'Any',
    url: canonicalRaw,
    license: 'MIT',
    author: { '@type': 'Organization', name: 'UtilityHub', url: 'https://github.com/YrustPd/UtilityHub' },
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${seoTitleEsc}</title>
  <meta name="description" content="${seoDescriptionEsc}" />
  <link rel="canonical" href="${canonical}" />
  <meta property="og:title" content="${seoTitleEsc}" />
  <meta property="og:description" content="${seoDescriptionEsc}" />
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="${name}" />
  <meta property="og:url" content="${canonical}" />
  <meta property="og:image" content="${ogImage}" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${seoTitleEsc}" />
  <meta name="twitter:description" content="${seoDescriptionEsc}" />
  <meta name="twitter:url" content="${canonical}" />
  <meta name="twitter:image" content="${ogImage}" />
  <script nonce="${nonce}" type="application/ld+json">${ldJson}</script>
  <style nonce="${nonce}">${inlineCss()}</style>
</head>
<body>
  <header class="page-header">
    <div class="brand">
      <span class="logo-dot" aria-hidden="true"></span>
      <div>
        <div class="brand-name">${name}</div>
        <div class="brand-tagline">${tagline}</div>
      </div>
    </div>
    <div class="meta">
      <span class="meta-item">v${version}</span>
      <span class="meta-item">${hostEsc}</span>
      <a class="meta-item meta-link" href="https://github.com/YrustPd/UtilityHub" target="_blank" rel="noopener noreferrer" aria-label="GitHub repository">
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
      </a>
    </div>
  </header>

  <main class="container">
  <h1 class="sr-only">${seoTitleEsc}</h1>
  <div class="search-box">
    <label class="sr-only" for="filter">Search endpoints</label>
    <input id="filter" type="search" placeholder="Search endpoints…" aria-label="Search endpoints" />
  </div>

    <section class="intro">
      <p class="lede">${tagline}</p>
    </section>

    <section id="section-diagnostics" data-section data-section-id="diagnostics">
      <div class="section-heading">
        <h2 id="heading-diagnostics"><span class="section-title">Diagnostics</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Quick service checks for liveness and edge timing.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="health diagnostics alive status hostname">
          <div class="card-header">
            <h3>Health</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Lightweight alive signal with hostname echo.</p>
          <code data-copy>${prefixEsc}health</code>
        </article>
        <article class="card" data-search="status diagnostics version features">
          <div class="card-header">
            <h3>Status</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Version, timestamp, and enabled feature list.</p>
          <code data-copy>${prefixEsc}api/status</code>
        </article>
        <article class="card" data-search="ping diagnostics latency timing">
          <div class="card-header">
            <h3>Ping</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Edge-received and response timestamps.</p>
          <code data-copy>${prefixEsc}api/ping</code>
        </article>
        <article class="card" data-search="trace diagnostics colo country asn">
          <div class="card-header">
            <h3>Trace</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Minimal edge trace info (colo, country, ASN).</p>
          <code data-copy>${prefixEsc}api/trace</code>
        </article>
      </div>
    </section>

    <section id="section-identity" data-section data-section-id="identity">
      <div class="section-heading">
        <h2 id="heading-identity"><span class="section-title">Identity &amp; Request</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Safe request insights without leaking sensitive headers.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="whoami identity ip user agent cf">
          <div class="card-header">
            <h3>Who Am I</h3>
            <span class="chip get">GET</span>
          </div>
          <p>IP, user agent, and selected Cloudflare edge metadata.</p>
          <code data-copy>${prefixEsc}api/whoami</code>
        </article>
        <article class="card" data-search="ip address identity">
          <div class="card-header">
            <h3>IP Only</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Returns the resolved client IP address only.</p>
          <code data-copy>${prefixEsc}api/ip</code>
        </article>
        <article class="card" data-search="headers request safe accept language user agent">
          <div class="card-header">
            <h3>Safe Headers</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Whitelisted request headers for quick inspection.</p>
          <code data-copy>${prefixEsc}api/headers</code>
        </article>
        <article class="card" data-search="user agent ua browser os device">
          <div class="card-header">
            <h3>User Agent</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Minimal UA parsing for browser and OS hints.</p>
          <code data-copy>${prefixEsc}api/useragent</code>
        </article>
      </div>
    </section>

    <section id="section-crypto" data-section data-section-id="crypto">
      <div class="section-heading">
        <h2 id="heading-crypto"><span class="section-title">Crypto &amp; IDs</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Stateless primitives for hashing and identifiers.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="time now clock utc">
          <div class="card-header">
            <h3>Current Time</h3>
            <span class="chip get">GET</span>
          </div>
          <p>UTC timestamp for synchronization checks.</p>
          <code data-copy>${prefixEsc}api/time</code>
        </article>
        <article class="card" data-search="random integer crypto min max">
          <div class="card-header">
            <h3>Random Integer</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Cryptographically secure integer with optional bounds.</p>
          <code data-copy>${prefixEsc}api/random?min=1&max=10</code>
        </article>
        <article class="card" data-search="hash sha256 crypto salt">
          <div class="card-header">
            <h3>Hash</h3>
            <span class="chip get">GET</span>
          </div>
          <p>SHA-256 hashing with optional salt and generated defaults.</p>
          <code data-copy>${prefixEsc}api/hash?input=hello</code>
        </article>
        <article class="card" data-search="uuid shortid identifiers">
          <div class="card-header">
            <h3>UUID &amp; Short ID</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Standard UUID v4 and URL-safe short IDs.</p>
          <code data-copy>${prefixEsc}api/uuid</code>
        </article>
        <article class="card" data-search="redirect http https">
          <div class="card-header">
            <h3>Redirect</h3>
            <span class="chip get">GET</span>
          </div>
          <p>Validated HTTP/HTTPS redirect.</p>
          <code data-copy>${prefixEsc}api/redirect?url=https://example.com</code>
        </article>
      </div>
    </section>

    <section id="section-encoding" data-section data-section-id="encoding">
      <div class="section-heading">
        <h2 id="heading-encoding"><span class="section-title">Encoding/Decoding</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Core transforms for text and bytes.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="base64 encode decode">
          <div class="card-header">
            <h3>Base64</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Encode or decode base64 payloads.</p>
          <code data-copy>${prefixEsc}api/base64/encode</code>
        </article>
        <article class="card" data-search="url encode decode">
          <div class="card-header">
            <h3>URL</h3>
            <span class="chip post">POST</span>
          </div>
          <p>URL-safe encode or decode.</p>
          <code data-copy>${prefixEsc}api/url/encode</code>
        </article>
        <article class="card" data-search="hex encode decode">
          <div class="card-header">
            <h3>Hex</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Hex encoding and decoding helpers.</p>
          <code data-copy>${prefixEsc}api/hex/encode</code>
        </article>
      </div>
    </section>

    <section id="section-json-tools" data-section data-section-id="json-tools">
      <div class="section-heading">
        <h2 id="heading-json-tools"><span class="section-title">JSON Tools</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Formatter, minifier, and validator.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="json format pretty">
          <div class="card-header">
            <h3>Format JSON</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Pretty-print JSON payloads.</p>
          <code data-copy>${prefixEsc}api/json/format</code>
        </article>
        <article class="card" data-search="json minify compact">
          <div class="card-header">
            <h3>Minify JSON</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Compact JSON payloads.</p>
          <code data-copy>${prefixEsc}api/json/minify</code>
        </article>
        <article class="card" data-search="json validate schema">
          <div class="card-header">
            <h3>Validate JSON</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Validate JSON with error details.</p>
          <code data-copy>${prefixEsc}api/json/validate</code>
        </article>
      </div>
    </section>

    <section id="section-text-tools" data-section data-section-id="text-tools">
      <div class="section-heading">
        <h2 id="heading-text-tools"><span class="section-title">Text Tools</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>Regex tester, lorem, slug, passwords, QR codes.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="regex test pattern flags">
          <div class="card-header">
            <h3>Regex Tester</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Test patterns with flags and grouped matches.</p>
          <code data-copy>${prefixEsc}api/regex/test</code>
        </article>
        <article class="card" data-search="lorem ipsum generator">
          <div class="card-header">
            <h3>Lorem</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Generate placeholder text.</p>
          <code data-copy>${prefixEsc}api/lorem</code>
        </article>
        <article class="card" data-search="slug text url-safe">
          <div class="card-header">
            <h3>Slugify</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Normalize text into URL-safe slugs.</p>
          <code data-copy>${prefixEsc}api/text/slug</code>
        </article>
        <article class="card" data-search="password generate secure">
          <div class="card-header">
            <h3>Password Generator</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Generate secure passwords with options.</p>
          <code data-copy>${prefixEsc}api/password</code>
        </article>
        <article class="card" data-search="qrcode qr svg">
          <div class="card-header">
            <h3>QR Code</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Generate SVG QR codes from text.</p>
          <code data-copy>${prefixEsc}api/qrcode</code>
        </article>
      </div>
    </section>

    <section id="section-security" data-section data-section-id="security">
      <div class="section-heading">
        <h2 id="heading-security"><span class="section-title">Security &amp; Validation</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
        <p>URL and IP validation helpers.</p>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="url validate safe">
          <div class="card-header">
            <h3>Validate URL</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Check and normalize absolute URLs.</p>
          <code data-copy>${prefixEsc}api/validate/url</code>
        </article>
        <article class="card" data-search="ip validate">
          <div class="card-header">
            <h3>Validate IP</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Validate IPv4/IPv6 addresses.</p>
          <code data-copy>${prefixEsc}api/validate/ip</code>
        </article>
      </div>
    </section>

    <section id="section-crypto-adv" data-advanced class="hidden-advanced" data-section-id="crypto-adv">
      <div class="section-heading">
        <div>
          <h2 id="heading-crypto-adv"><span class="section-title">Advanced Crypto</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
          <p>Disabled by default; enable via env.</p>
        </div>
        <div class="section-controls">
          <span class="status-pill" data-status="crypto-adv" data-state="unknown">Unknown</span>
          <button id="advanced-toggle" class="advanced-toggle" type="button" aria-pressed="false"><span id="advanced-label">Advanced: Off</span></button>
        </div>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="pbkdf2 password hash crypto advanced">
          <div class="card-header">
            <h3>PBKDF2 Hash</h3>
            <span class="chip post">POST</span>
          </div>
          <p>PBKDF2-SHA256 hashing (disabled by default).</p>
          <code data-copy>${prefixEsc}api/password/hash</code>
        </article>
        <article class="card" data-search="jwt sign verify hs256 advanced">
          <div class="card-header">
            <h3>JWT Sign</h3>
            <span class="chip post">POST</span>
          </div>
          <p>HS256 signing with env secret (disabled by default).</p>
          <code data-copy>${prefixEsc}api/jwt/sign</code>
        </article>
        <article class="card" data-search="jwt verify hs256 advanced">
          <div class="card-header">
            <h3>JWT Verify</h3>
            <span class="chip post">POST</span>
          </div>
          <p>HS256 verification (disabled by default).</p>
          <code data-copy>${prefixEsc}api/jwt/verify</code>
        </article>
      </div>
    </section>

    <section id="section-network-adv" data-advanced class="hidden-advanced" data-section-id="network-adv">
      <div class="section-heading">
        <div>
          <h2 id="heading-network-adv"><span class="section-title">Network &amp; Performance (Advanced)</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
          <p>Disabled by default; enable via env.</p>
        </div>
        <div class="section-controls">
          <span class="status-pill" data-status="network-adv" data-state="unknown">Unknown</span>
        </div>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="dns resolve doh network">
          <div class="card-header">
            <h3>DNS Resolve</h3>
            <span class="chip post">POST</span>
          </div>
          <p>DNS-over-HTTPS queries (allowlist, disabled by default).</p>
          <code data-copy>${prefixEsc}api/dns/resolve</code>
        </article>
        <article class="card" data-search="compress gzip brotli network">
          <div class="card-header">
            <h3>Compression Test</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Measure gzip/brotli sizes (disabled by default).</p>
          <code data-copy>${prefixEsc}api/compress/test</code>
        </article>
        <article class="card" data-search="perf benchmark network">
          <div class="card-header">
            <h3>Perf Benchmark</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Fetch timing breakdown (allowlist, disabled by default).</p>
          <code data-copy>${prefixEsc}api/perf/benchmark</code>
        </article>
        <article class="card" data-search="ip geolocate network">
          <div class="card-header">
            <h3>IP Geolocate</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Edge-provided geolocation (disabled by default).</p>
          <code data-copy>${prefixEsc}api/ip/geolocate</code>
        </article>
      </div>
    </section>

    <section id="section-high-risk" data-advanced class="hidden-advanced" data-section-id="high-risk">
      <div class="section-heading">
        <div>
          <h2 id="heading-high-risk"><span class="section-title">High Risk (Disabled by Default)</span><span class="section-count">0</span><span class="section-chevron" aria-hidden="true">▸</span></h2>
          <p>Require explicit enablement and allowlists.</p>
        </div>
        <div class="section-controls">
          <span class="status-pill" data-status="high-risk" data-state="unknown">Unknown</span>
        </div>
      </div>
      <div class="placeholder-grid">
        <article class="card" data-search="proxy allowlist high risk">
          <div class="card-header">
            <h3>Proxy</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Allowlisted proxy (disabled by default).</p>
          <code data-copy>${prefixEsc}api/proxy</code>
        </article>
        <article class="card" data-search="mock generator schema high risk">
          <div class="card-header">
            <h3>Mock Generator</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Bounded mock data (disabled by default).</p>
          <code data-copy>${prefixEsc}api/mock</code>
        </article>
        <article class="card" data-search="schema validate high risk">
          <div class="card-header">
            <h3>Schema Validate</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Subset schema validation (disabled by default).</p>
          <code data-copy>${prefixEsc}api/schema/validate</code>
        </article>
        <article class="card" data-search="vuln scan heuristic high risk">
          <div class="card-header">
            <h3>Vuln Scan</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Heuristic text scan (disabled by default).</p>
          <code data-copy>${prefixEsc}api/vuln/scan</code>
        </article>
        <article class="card" data-search="playground echo inspect high risk">
          <div class="card-header">
            <h3>Playground</h3>
            <span class="chip post">POST</span>
          </div>
          <p>Echo/inspect helper (disabled by default).</p>
          <code data-copy>${prefixEsc}api/playground</code>
        </article>
      </div>
    </section>

  </main>

  <footer class="page-footer">
    <span>${name} • v${version}</span>
    <span class="divider">•</span>
    <span>${hostEsc}</span>
  </footer>

  <script nonce="${nonce}">${inlineJs()}</script>
</body>
</html>`;

  return htmlResponse(html, 200, {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'none'",
      "script-src-attr 'none'",
      "style-src-attr 'none'",
      'upgrade-insecure-requests',
    ].join('; '),
  });
}
