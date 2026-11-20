const http=require("http"),fs=require("fs"),path=require("path");const {chromium}=require("playwright");
const srv=http.createServer((q,r)=>{const f=q.url==="/"?path.join(__dirname,"index.html"):path.join(__dirname,"dist",q.url);if(!fs.existsSync(f)){r.writeHead(404);return r.end();}
r.writeHead(200,{"content-type":f.endsWith(".js")?"text/javascript":"text/html","content-security-policy":"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'"});r.end(fs.readFileSync(f));}).listen(8977,async()=>{
const b=await chromium.launch();const p=await b.newPage();const msgs=[];p.on("console",m=>msgs.push(m.type()+": "+m.text()));p.on("pageerror",e=>msgs.push("error: "+e.message));
await p.goto("http://127.0.0.1:8977/");await p.waitForTimeout(800);
await p.click("#open");await p.waitForTimeout(500);
const open=await p.evaluate(()=>{const c=document.querySelector("ui-dialog-content");return {dialogOpen:c&&(c.hasAttribute("data-open")||getComputedStyle(c).display!=="none"),role:c&&(c.getAttribute("role")||c.querySelector("[role]")?.getAttribute("role")),focus:document.activeElement?.outerHTML?.slice(0,80)}});
await p.keyboard.press("Escape");await p.waitForTimeout(300);
await p.click("text=B");await p.waitForTimeout(300);
const tabs=await p.evaluate(()=>[...document.querySelectorAll("ui-tabs-panel")].map(e=>e.textContent+":"+(e.hidden||getComputedStyle(e).display==="none"?"hidden":"shown")));
console.log(JSON.stringify({open,tabs,msgs},null,1));await b.close();srv.close();});
