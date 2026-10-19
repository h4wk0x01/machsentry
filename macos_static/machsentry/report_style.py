"""Self-contained, printable analyst report styling; no external assets."""

CSS = '''
:root{color-scheme:light;--ink:#182b3e;--muted:#516477;--line:#dce4eb;--paper:#fff;--bg:#f1f5f8;--accent:#146b72;--warn:#94510b}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible,summary:focus-visible{outline:3px solid #078b98;outline-offset:5px}
.top{background:#102d39;color:#e8f5f6;padding:23px max(24px,calc((100vw - 1220px)/2));display:flex;align-items:center;justify-content:space-between;gap:18px}
.brand{font-size:20px;font-weight:750;letter-spacing:-.6px}.brand span{color:#79d5cf}.tag{font-size:11px;letter-spacing:1.6px;text-transform:uppercase}
.layout{max-width:1268px;margin:32px auto 70px;padding:0 24px;display:grid;grid-template-columns:205px minmax(0,1fr);gap:34px}
nav{position:sticky;top:24px;align-self:start}nav p{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);margin:0 0 16px}
nav a{display:block;color:var(--muted);font-size:13px;padding:9px 0;text-decoration:none}nav a:hover{color:var(--accent)}nav a span{display:inline-block;width:25px;color:#718497;font:11px ui-monospace,monospace}
main{min-width:0}.eyebrow{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);font-weight:750;margin:0}
h1{font-size:32px;letter-spacing:-1px;line-height:1.2;margin:10px 0 12px;overflow-wrap:anywhere}h2{font-size:21px;letter-spacing:-.5px;margin:0 0 20px}h3{font-size:16px;margin:0 0 8px}p{margin:8px 0 16px}
.muted,.meta{color:var(--muted)}.meta{font-size:12px}.hero{margin-bottom:24px}.hero p{max-width:760px}.pill{display:inline-block;padding:4px 10px;border:1px solid #b9cece;color:var(--accent);border-radius:5px;font-size:11px;font-weight:700;letter-spacing:.3px}
.pill.warn{color:#8b4705;background:#fff6e9;border-color:#e9c28e}.pill.fail{color:#9c313b;background:#fff2f3;border-color:#e2bdc1}
.panel{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:26px;margin-bottom:22px;scroll-margin-top:24px}
.summary-grid{display:grid;grid-template-columns:165px minmax(0,1fr);gap:28px}.score{border-right:1px solid var(--line);padding-right:22px}.score strong{font-size:52px;letter-spacing:-2px;line-height:1.15;font-weight:650}.score small{font-size:16px;color:var(--muted)}
.score p{font-size:11px;color:var(--muted);margin:10px 0 0}meter{display:block;width:100%;height:9px;margin-top:14px}meter::-webkit-meter-bar{background:#e5ebf0;border:0}meter::-webkit-meter-optimum-value{background:#b06a1c}
.factors{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}.factor{background:#f2f6f8;color:#475c6a;font-size:11px;padding:5px 8px;border-radius:4px}
dl{margin:0;display:grid;grid-template-columns:150px minmax(0,1fr);gap:12px 20px}dt{font-size:12px;color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.mono,code{font-size:12px}
.card{border-top:1px solid var(--line);padding:21px 0}.card:first-of-type{border-top:0;padding-top:0}.card:last-child{padding-bottom:0}.card p{margin-bottom:10px}.card-head{display:flex;justify-content:space-between;gap:15px;align-items:baseline}
.evidence{margin:12px 0 0;border-left:3px solid #a8c6c9;background:#f6f9fa;padding:12px 16px}.evidence pre{background:transparent;border:0;padding:0;margin:5px 0}
pre{font-size:12px;line-height:1.7;background:#f3f6f8;border:1px solid #e2e9ef;border-radius:6px;padding:16px;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4;max-height:340px;overflow:auto;margin:12px 0}
.rule{background:#142d3b;color:#e6f0f6;border:0;max-height:470px}.empty{color:var(--muted);background:#f7f9fb;padding:16px;border-radius:6px;margin:0}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:650}th,td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}td{overflow-wrap:anywhere}th:first-child,td:first-child{padding-left:0}tr:last-child td{border-bottom:0}
details{margin-top:12px}summary{color:var(--accent);cursor:pointer;font-size:13px;font-weight:600}.notice{background:#fff7e9;border-left:3px solid #c28c39;padding:12px 16px;color:#704d1d;font-size:13px;margin:16px 0}.button{display:inline-block;background:var(--accent);color:white;padding:10px 16px;border-radius:6px;text-decoration:none;font-size:13px;font-weight:650;margin:6px 0 14px}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:18px 0}.stat{background:#f2f6f8;padding:12px;border-radius:6px}.stat strong{display:block;font-size:20px;line-height:1.35}.stat span{display:block;font-size:11px;color:var(--muted)}
ul{padding-left:20px}li{margin-bottom:8px}.small{font-size:12px}.footer{font-size:11px;color:var(--muted);padding:4px 0 20px}.break{overflow-wrap:anywhere}
@media(max-width:850px){.layout{display:block;margin:20px auto;padding:0 16px}nav{display:none}.top{padding:18px}.top .tag{display:none}.panel{padding:20px}h1{font-size:27px}.summary-grid{grid-template-columns:130px minmax(0,1fr);gap:20px}dl{grid-template-columns:115px minmax(0,1fr)}}
@media(max-width:480px){.summary-grid{display:block}.score{border-right:0;border-bottom:1px solid var(--line);padding:0 0 18px;margin-bottom:18px}.score strong{font-size:42px}.stats{grid-template-columns:1fr}.card-head{display:block}dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:12px}}
@media print{body{background:white;font-size:11px}.top{background:white;color:var(--ink);padding:0 0 16px;border-bottom:2px solid var(--ink)}.top .brand span{color:var(--ink)}.layout{display:block;margin:22px 0;padding:0}nav,.button{display:none}.panel{padding:18px 0;border:0;border-top:1px solid var(--line);border-radius:0;break-inside:auto}h2,h3{break-after:avoid}pre,.rule{max-height:none;overflow:visible;background:#f4f5f6;color:#182b3e}.card,.evidence{break-inside:avoid}a{color:inherit}details:not([open])> :not(summary){display:block}.footer{margin-top:20px}}
'''

# Unpacked frame: neutral, print-friendly document with the brand purple in the header and accents.
UNPACKED_CSS = '''
:root{--ink:#161824;--muted:#5d6377;--line:#e4e5ee;--paper:#fff;--bg:#f5f5f9;--accent:#6a3fd2;--accent-soft:#f3effd}
body{font-feature-settings:"tnum" 1}a:focus-visible,summary:focus-visible{outline-color:#8b5cf6}
.top{background:linear-gradient(115deg,#0a0c12 0%,#120f1d 62%,#1b1230 100%);color:#ecebf6;padding:18px max(24px,calc((100vw - 1220px)/2));border-bottom:1px solid #2b2243}
.brand{display:flex;align-items:center;gap:10px;color:#fff;font-size:22px;font-weight:850;letter-spacing:-.03em;line-height:1}
.brand svg{flex:none;width:30px;height:30px;filter:drop-shadow(0 0 9px rgba(162,65,255,.65))}.brand span{color:inherit}
.tag{color:#c7bdec;text-align:right;line-height:1.7}.tag b{display:block;color:#fff;font-weight:650;letter-spacing:.4px}
nav a:hover,nav a:focus-visible{color:var(--accent)}nav a span{color:#9a8fc0}
.hero{border-bottom:1px solid var(--line);padding-bottom:20px}.eyebrow{color:var(--accent)}
.panel{border-color:var(--line);box-shadow:0 1px 2px rgba(22,24,36,.04)}.panel h2{display:flex;align-items:center;gap:10px}
.panel h2::before{content:"";width:4px;height:18px;border-radius:2px;background:linear-gradient(#a855f7,#6a3fd2)}
.pill{border-color:#d9ccfb;background:var(--accent-soft);color:var(--accent)}
.factor{background:#f2f0f8;color:#4b4565}.evidence{border-left-color:#c7b5f6;background:#faf8ff}
pre{background:#f6f6fa;border-color:#e6e4f0}.rule{background:#13101f;color:#ece6ff}
.stat{background:#f4f2fa}.empty{background:#f7f6fb}.button{background:var(--accent)}
meter::-webkit-meter-optimum-value{background:linear-gradient(90deg,#a855f7,#6a3fd2)}
.footer{display:flex;flex-wrap:wrap;align-items:center;gap:8px;border-top:1px solid var(--line);padding-top:16px}
.footer strong{color:var(--ink);font-weight:850;letter-spacing:-.02em}
@media(max-width:850px){.top{padding:16px}.brand{font-size:19px}.brand svg{width:26px;height:26px}}
@media print{.top{background:#fff;color:var(--ink);border-bottom:2px solid var(--ink)}.brand{color:var(--ink)}.brand svg{filter:none}
.tag{display:block;color:var(--muted)}.tag b{color:var(--ink)}.hero{border-bottom:0;padding-bottom:0}
.panel h2::before{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
'''
