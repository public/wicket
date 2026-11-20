// How much code each prototype is, and how branchy, counted the same way whatever the framework:
// logic in a Vue or Svelte template counts as much as logic in a script, and markup counts the same
// whether it is JSX, a template or a Lit `html` literal.
//
//   NODE_PATH=$(npm root -g) node complexity.mjs [candidate...]   (needs the `typescript` package)
//
// Counted over each candidate's own source in src/ (scripts, components and templates), leaving out
// helpers.js / shared.js: the same domain helpers copied into every candidate.
// - lines: non-blank lines that aren't only a comment;
// - size: syntax nodes. A script's AST nodes, without JSX's own scaffolding; for markup (JSX, Vue and
//   Svelte templates, Lit literals) one per element, attribute and text run, plus the AST nodes of every
//   expression in it. A formatting-independent measure of how much there is to read;
// - branches: decision points, as in cyclomatic complexity: if, ?:, &&, ||, ??, ?., case, catch, and
//   every loop however it is written: for and while, an array method that loops (map, filter, forEach,
//   some, every, find, flatMap, reduce), Lit's repeat(), plain JS's keyed(), Solid's <For> and <Index>,
//   Vue's v-for and Svelte's {#each}. Conditions in templates count too: Solid's <Show> and <Match>,
//   v-if, v-else-if, v-show, {#if}, {:else if}, {#await};
// - worst unit: the most branches in one function, or in one component's template;
// - functions: functions, arrows and methods written;
// - writes: state changed by hand: assignments, ++/--, and calls to a setter (setX(…), Preact's and
//   Solid's way to change state);
// - DOM calls: uses of the browser's DOM API by name (createElement, append, replaceChildren,
//   textContent, setAttribute, addEventListener, classList, querySelector, getElementById, …): the
//   page managed by hand rather than by a framework.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const ts = createRequire(import.meta.url)("typescript");

const here = path.dirname(fileURLToPath(import.meta.url));
const SHARED = new Set(["helpers.js", "shared.js"]);
const DOM = new Set(["createElement", "createTextNode", "append", "appendChild", "prepend", "replaceChildren", "removeChild",
  "insertBefore", "replaceWith", "remove", "textContent", "innerText", "setAttribute", "removeAttribute", "toggleAttribute",
  "addEventListener", "removeEventListener", "classList", "className", "querySelector", "querySelectorAll", "getElementById",
  "children", "firstChild", "lastChild", "isConnected", "dataset", "hidden"]);
const ASSIGN = new Set([ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken]);
const LOGIC = new Set([ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.AmpersandAmpersandEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken]);
const JSX_SCAFFOLD = new Set([ts.SyntaxKind.JsxOpeningElement, ts.SyntaxKind.JsxClosingElement, ts.SyntaxKind.JsxAttributes,
  ts.SyntaxKind.JsxExpression, ts.SyntaxKind.JsxOpeningFragment, ts.SyntaxKind.JsxClosingFragment]);
// A Lit template's own scaffolding, as JSX's: the literal's pieces are counted as markup instead.
const TEMPLATE_SCAFFOLD = new Set([ts.SyntaxKind.TemplateExpression, ts.SyntaxKind.TemplateHead, ts.SyntaxKind.TemplateMiddle,
  ts.SyntaxKind.TemplateTail, ts.SyntaxKind.TemplateSpan, ts.SyntaxKind.NoSubstitutionTemplateLiteral]);
const inHtml = n => { for (let p = n; p; p = p.parent) { if (ts.isTaggedTemplateExpression(p)) return p.tag.getText() === "html" && p.template.pos <= n.pos; if (!TEMPLATE_SCAFFOLD.has(p.kind)) return false; } return false; };
const LOOPS = new Set(["map", "filter", "forEach", "some", "every", "find", "findIndex", "flatMap", "reduce", "repeat", "keyed"]);
const JSX_BRANCH = new Set(["Show", "Match", "For", "Index"]);
const isFn = n => ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) ||
  ts.isGetAccessor(n) || ts.isSetAccessor(n);

function blank() { return { lines: 0, size: 0, branches: 0, worst: 0, functions: 0, writes: 0, dom: 0 }; }

// Markup counted the same way in every form: elements, attributes and non-blank text runs.
function markup(html, m) {
  for (const t of html.matchAll(/<([A-Za-z][\w.:-]*)([^>]*)>/g)) {
    m.size += 1;
    // Attributes: name, name="…", name='…', name=value. Expression placeholders count as attributes.
    m.size += (t[2].match(/[^\s=/"']+(\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g) || []).length;
  }
  // An expression's placeholder (\u0001) is not text: its own nodes are counted where it is parsed.
  for (const t of html.replace(/<[^>]*>/g, "\u0000").split("\u0000")) if (t.replace(/\u0001/g, "").trim()) m.size += 1;
}

// A script (or one template expression): AST size, branches, functions, writes, DOM calls. Returns the
// branches outside any function, so a template's expressions add to its own unit.
function script(code, m, kind = ts.ScriptKind.JSX, units = []) {
  const sf = ts.createSourceFile("x.jsx", code, ts.ScriptTarget.Latest, true, kind);
  let loose = 0;
  const stack = [];
  const branch = () => { m.branches++; if (stack.length) stack[stack.length - 1].b++; else loose++; };
  (function walk(n) {
    if (n.kind === ts.SyntaxKind.EndOfFileToken) return;
    // JSX: one per element, attribute and text run, as in markup(); its scaffolding isn't counted.
    if (ts.isJsxText(n)) { if (n.text.trim()) m.size++; return; }
    if (!JSX_SCAFFOLD.has(n.kind) && !(ts.isIdentifier(n) && n.parent && (ts.isJsxOpeningElement(n.parent) || ts.isJsxClosingElement(n.parent) ||
      ts.isJsxSelfClosingElement(n.parent) || ts.isJsxAttribute(n.parent))) &&
      !(TEMPLATE_SCAFFOLD.has(n.kind) && inHtml(n)) && !(ts.isIdentifier(n) && ts.isTaggedTemplateExpression(n.parent) && n.text === "html")) m.size++;
    // A Lit template: its literal parts are markup.
    if (ts.isTaggedTemplateExpression(n) && n.tag.getText(sf) === "html") {
      const t = n.template;
      const parts = ts.isNoSubstitutionTemplateLiteral(t) ? [t.text] : [t.head.text, ...t.templateSpans.map(s => s.literal.text)];
      markup(parts.join("\u0001"), m);
    }
    const fn = isFn(n);
    if (fn) { m.functions++; stack.push({ b: 0 }); }
    if (ts.isIfStatement(n) || ts.isConditionalExpression(n) || ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isForInStatement(n) ||
      ts.isWhileStatement(n) || ts.isDoStatement(n) || ts.isCaseClause(n) || ts.isCatchClause(n)) branch();
    if (ts.isBinaryExpression(n) && LOGIC.has(n.operatorToken.kind)) branch();
    if ((ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n) || ts.isCallExpression(n)) && n.questionDotToken) branch();
    if (ts.isCallExpression(n)) {
      const callee = ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : ts.isIdentifier(n.expression) ? n.expression.text : "";
      if (LOOPS.has(callee)) branch();
      if (/^set[A-Z]/.test(callee) && ts.isIdentifier(n.expression)) m.writes++;
    }
    if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && JSX_BRANCH.has(n.tagName.getText(sf))) branch();
    if (ts.isBinaryExpression(n) && ASSIGN.has(n.operatorToken.kind)) m.writes++;
    if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
      (n.operator === ts.SyntaxKind.PlusPlusToken || n.operator === ts.SyntaxKind.MinusMinusToken)) m.writes++;
    if (ts.isPropertyAccessExpression(n) && DOM.has(n.name.text)) m.dom++;
    ts.forEachChild(n, walk);
    if (fn) units.push(stack.pop().b);
  })(sf);
  return loose;
}

// Lines that hold code: not blank, not only a comment.
function codeLines(text) {
  const s = text.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, "")).replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ""));
  return s.split("\n").filter(l => l.trim() && !/^\s*\/\//.test(l)).length;
}

// Svelte markup: control blocks are branches; every {expression} is code; the rest is markup.
function svelteMarkup(html, m, unit) {
  let out = "", i = 0;
  while (i < html.length) {
    if (html[i] !== "{") { out += html[i++]; continue; }
    let depth = 0, j = i;
    for (; j < html.length; j++) { if (html[j] === "{") depth++; else if (html[j] === "}" && --depth === 0) break; }
    let e = html.slice(i + 1, j).trim();
    i = j + 1;
    out += "\u0001";
    const ctl = /^(#if|:else if|#each|#await|#key|:else|\/\w+|:then|:catch|@html|@const)\b\s*/.exec(e);
    if (ctl) {
      if (/^(#if|:else if|#each|#await)$/.test(ctl[1])) { m.branches++; unit.b++; }
      m.size++;
      e = e.slice(ctl[0].length).replace(/\s+as\s+[\s\S]*$/, "");
      if (ctl[1] === "@const") e = e.replace(/^[^=]+=/, "");
      if (!e) continue;
    }
    unit.b += script("(" + e + ")", m, ts.ScriptKind.JSX);
  }
  markup(out, m);
}

// Vue template: v-if, v-else-if, v-show and v-for are branches; directive values and {{ }} are code.
function vueTemplate(html, m, unit) {
  html = html.replace(/\{\{([\s\S]*?)\}\}/g, (_, e) => { unit.b += script("(" + e + ")", m); return "\u0001"; });
  for (const a of html.matchAll(/\s(v-[\w-]+|:[\w-]+|@[\w.-]+)(?:\s*=\s*"([^"]*)")?/g)) {
    if (/^v-(if|else-if|show|for)$/.test(a[1])) { m.branches++; unit.b++; }
    if (a[2] === undefined) continue;
    const e = a[1] === "v-for" ? a[2].replace(/^[\s\S]*?\s(in|of)\s/, "") : a[2];
    unit.b += script(a[1].startsWith("@") ? e : "(" + e + ")", m);
  }
  markup(html, m);
}

function measure(dir, cut) {
  const m = blank();
  const units = [];
  const files = [];
  (function list(d) { for (const f of fs.readdirSync(d)) { const p = path.join(d, f); fs.statSync(p).isDirectory() ? list(p) : files.push(p); } })(path.join(dir, "src"));
  for (const f of files.sort()) {
    const base = path.basename(f);
    if (SHARED.has(base) || !/\.(jsx?|svelte|vue)$/.test(base)) continue;
    let text = fs.readFileSync(f, "utf8");
    if (cut) text = cut(text);
    m.lines += codeLines(text);
    if (/\.jsx?$/.test(base)) {
      const loose = script(text, m, ts.ScriptKind.JSX, units);
      units.push(loose);
      continue;
    }
    // A component: its scripts, then its template as one unit.
    const unit = { b: 0 };
    let rest = text.replace(/<style[\s\S]*?<\/style>/g, "");
    rest = rest.replace(/<script[^>]*>([\s\S]*?)<\/script>/g, (_, code) => { unit.b += script(code, m, ts.ScriptKind.JS, units); return ""; });
    rest = rest.replace(/<!--[\s\S]*?-->/g, "");
    if (base.endsWith(".vue")) vueTemplate(rest.replace(/^\s*<template>|<\/template>\s*$/g, ""), m, unit);
    else svelteMarkup(rest, m, unit);
    units.push(unit.b);
  }
  m.worst = Math.max(0, ...units);
  return m;
}

let names = process.argv.slice(2);
if (!names.length) names = fs.readdirSync(here).filter(d => fs.existsSync(path.join(here, d, "src")) && !/-esbuild$|-nobuild$|^solid-h$/.test(d)).sort();
const rows = [];
for (const n of names) rows.push([n, measure(path.join(here, n))]);
// Plain JS without its framework-like part (h, add, keyed, live times): what the screens themselves take.
if (names.includes("vanilla")) rows.push(["vanilla, screens only (without h, keyed, live times)",
  measure(path.join(here, "vanilla"), t => t.slice(0, t.indexOf("// ---- building elements ----")) + t.slice(t.indexOf("// ---- small pieces ----")))]);
console.log("| candidate | lines | size (nodes) | branches | worst unit | functions | writes | DOM calls |");
console.log("|---|---|---|---|---|---|---|---|");
for (const [n, m] of rows) console.log(`| ${n} | ${m.lines} | ${m.size} | ${m.branches} | ${m.worst} | ${m.functions} | ${m.writes} | ${m.dom} |`);
fs.mkdirSync(path.join(here, "results"), { recursive: true });
fs.writeFileSync(path.join(here, "results", "complexity.json"), JSON.stringify(Object.fromEntries(rows), null, 1));
