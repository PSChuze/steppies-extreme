#!/usr/bin/env python3
"""The board page: the game's own screens, in a browser.

Every screen is a picture boards.py draws from the art boardart.py baked from
the disc (/view/<id>.png) -- the same picture Discord shows -- so the page
looks exactly like the game and exactly like the post. Around it the page is
built from the game too:

    backdrop   the game's own background art, blurred and dimmed, filling the
               window, so the screen sits in its world rather than on black
    header     the game's logo and the live count, in the game's font
    tabs       the screens, as header tabs on top of the screen the way the
               games place them (RANKING / ONLINE PLAY; Extreme 2's own
               RANKING CHALLENGE / HEAD-TO-HEAD buttons)
    choices    the tournaments, the cards, this week / all time, and pages

The screen is sized to the window's height as well as its width, so the whole
of it and every control are in view without scrolling, from a phone to a wide
monitor. Words are pictures in the game's font (/label/...), never a web font.

The view is in the address (#rank.12.0), so any screen can be linked. Left
and right switch choice, up and down page. The picture's alt text is the whole
screen as text, kept current, for screen readers.
"""
import html

_PAGE = r"""<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>__TITLE__ Online</title>
<style>
:root{--accent:#3cf;--ar:1.4815;--chrome:208px}
*{box-sizing:border-box}
html{background:#05060c}
/* no background on body: it would paint over the backdrop behind it */
body{margin:0;min-height:100%;color:#fff}
.backdrop{position:fixed;inset:-48px;z-index:-1;background:#05060c center/cover no-repeat;
  filter:blur(20px) brightness(.38) saturate(1.25)}
main{min-height:100vh;min-height:100svh;display:flex;flex-direction:column;align-items:center;
  justify-content:center;padding:12px 16px 16px}
/* the console: as wide as the window allows AND short enough that the whole
   screen and its controls fit the window's height */
.console{width:min(100%,1120px,calc((100vh - var(--chrome)) * var(--ar)));
  width:min(100%,1120px,calc((100svh - var(--chrome)) * var(--ar)))}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;
  margin:0 2px 10px;min-height:56px}
.logo{height:clamp(40px,9vh,76px);width:auto;display:block;
  filter:drop-shadow(0 4px 10px rgba(0,0,0,.6))}
.status{display:flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;
  background:rgba(0,0,0,.55);border:1px solid rgba(255,255,255,.14)}
.status img{height:18px;width:auto;display:block}
.dot{width:10px;height:10px;border-radius:50%;background:#666;flex:none}
.dot.on{background:#41e07a;box-shadow:0 0 8px #41e07a}
.tabs{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;padding:0 2px}
.tabs::-webkit-scrollbar{display:none}
.tabs button{flex:none;background:rgba(0,0,0,.6);border:1px solid rgba(255,255,255,.14);
  border-bottom:0;border-radius:8px 8px 0 0;padding:8px 12px 6px;opacity:.6}
.tabs button[aria-pressed=true]{opacity:1;background:rgba(0,0,0,.85);
  border-color:var(--accent);box-shadow:inset 0 3px 0 var(--accent)}
.tabs button img{height:22px}
/* a tab that is the game's own button keeps the game's frame, not ours */
.tabs button.sprite{padding:4px 2px 6px;background:none;border:0;box-shadow:none}
.tabs button.sprite[aria-pressed=true]{background:none;box-shadow:inset 0 -3px 0 var(--accent)}
.tabs button.sprite img{height:28px}
.screen{display:block;width:100%;height:auto;border:1px solid rgba(255,255,255,.18);
  border-radius:0 8px 8px 8px;box-shadow:0 14px 48px rgba(0,0,0,.7);background:#000}
.below{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;
  gap:8px;margin-top:10px}
.choices,.pager{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.choices button,.pager button{background:rgba(0,0,0,.6);border:1px solid rgba(255,255,255,.16);
  border-radius:6px;padding:7px 10px;opacity:.7}
.choices button[aria-pressed=true]{opacity:1;border-color:var(--accent);
  background:color-mix(in srgb,var(--accent) 22%,rgba(0,0,0,.75))}
.pager button{opacity:1}
.choices img,.pager img{height:16px}
button{cursor:pointer;line-height:0;color:inherit;font:inherit}
button img{display:block;width:auto}
button:hover{opacity:1}
button:focus-visible{outline:2px solid var(--accent);outline-offset:2px;opacity:1}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
#bare{font:16px/1.5 monospace;padding:16px;display:none;max-width:40em}
@media (max-width:600px){
  main{padding:8px 8px 12px;justify-content:flex-start}
  :root{--chrome:180px}
  .logo{height:40px}
  .tabs button img{height:16px}.tabs button.sprite img{height:22px}
  .choices img,.pager img{height:13px}
}
</style></head><body>
<div class=backdrop id=backdrop></div>
<main>
<div class=console>
  <header>
    <h1 class=sr>__TITLE__ Online</h1>
    <img class=logo id=logo alt="__TITLE__" hidden>
    <div class=status id=status hidden><span class=dot id=dot></span><img id=count alt=""></div>
  </header>
  <nav aria-label=Screens class=tabs id=sections></nav>
  <img class=screen id=screen alt="Loading the board.">
  <div class=below>
    <nav aria-label=Choices class=choices id=items></nav>
    <nav aria-label=Pages class=pager id=pager></nav>
  </div>
  <div id=bare>No art has been baked for this board yet. Run boardart.py against
  your disc; see the README.</div>
</div>
</main>
<script>
"use strict";
let view = decodeURIComponent(location.hash.slice(1)), N = null, dressed = false;

function label(text, on) {
  const font = N.labels[on ? 1 : 0];
  return "label/" + encodeURIComponent(font) + "/" + encodeURIComponent(text) + ".png?a=" + N.art;
}
function button(text, target, on, sprite) {
  const b = document.createElement("button"), i = document.createElement("img");
  i.src = sprite ? "sprite/" + encodeURIComponent(sprite) + ".png?a=" + N.art : label(text, on);
  i.alt = text;
  if (sprite) b.className = "sprite";
  b.setAttribute("aria-pressed", on ? "true" : "false");
  b.appendChild(i);
  b.onclick = () => go(target);
  return b;
}
function fill(id, list) { document.getElementById(id).replaceChildren(...list); }
function dress(n) {
  // once: the game's colours, logo and world around the screen
  dressed = true;
  document.documentElement.style.setProperty("--accent", n.accent);
  document.getElementById("backdrop").style.backgroundImage = "url(art/bg.png?a=" + n.art + ")";
  if (n.logo) {
    const l = document.getElementById("logo");
    l.src = "sprite/logo.png?a=" + n.art;
    l.hidden = false;
  }
}
function show(n) {
  N = n;
  if (!dressed) dress(n);
  view = n.view;
  if (decodeURIComponent(location.hash.slice(1)) !== view)
    history.replaceState(null, "", "#" + encodeURIComponent(view));
  const st = document.getElementById("status");
  st.hidden = false;
  const txt = n.online == null ? "OFFLINE" : "ONLINE " + n.online;
  document.getElementById("count").src = label(txt, false);
  document.getElementById("count").alt = n.online == null ? "Server offline" : n.online + " online";
  document.getElementById("dot").className = "dot" + (n.online ? " on" : "");
  fill("sections", n.sections.map(s => button(s.label, s.view, s.on, s.sprite)));
  fill("items", n.items.length > 1 ? n.items.map(s => button(s.label, s.view, s.on)) : []);
  const pg = [];
  if (n.prev) pg.push(button("PREV", n.prev, true));
  if (n.pages > 1) pg.push(Object.assign(document.createElement("img"),
    {src: label((n.page + 1) + " OF " + n.pages, false),
     alt: "Page " + (n.page + 1) + " of " + n.pages}));
  if (n.next) pg.push(button("NEXT", n.next, true));
  fill("pager", pg);
  const minute = Math.floor(Date.now() / 60000);
  // p=1: without the in-screen logo, which the header already carries
  const src = "view/" + encodeURIComponent(view) + ".png?p=1&v=" + n.sig.slice(0, 12) + "-" + minute;
  const img = document.getElementById("screen");
  if (img.dataset.src !== src) {
    // load the new picture before swapping, so the screen never blanks
    const pre = new Image();
    pre.onload = () => {
      img.src = src; img.dataset.src = src; img.alt = n.alt;
      document.documentElement.style.setProperty("--ar", pre.naturalWidth / pre.naturalHeight);
    };
    pre.src = src;
  } else img.alt = n.alt;
}
async function go(target) {
  if (target !== undefined) view = target;
  try {
    const r = await fetch("nav.json?view=" + encodeURIComponent(view), {cache: "no-store"});
    if (r.status === 404) { document.getElementById("bare").style.display = "block"; return; }
    show(await r.json());
  } catch (e) {}
}
function step(list, d) {
  const i = list.findIndex(x => x.on);
  if (i >= 0 && list.length > 1) go(list[(i + d + list.length) % list.length].view);
}
document.addEventListener("keydown", e => {
  if (!N || e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.key === "ArrowLeft") step(N.items, -1);
  else if (e.key === "ArrowRight") step(N.items, 1);
  else if (e.key === "ArrowUp" && N.prev) go(N.prev);
  else if (e.key === "ArrowDown" && N.next) go(N.next);
  else return;
  e.preventDefault();
});
window.addEventListener("hashchange", () => {
  const h = decodeURIComponent(location.hash.slice(1));
  if (h !== view) go(h);
});
go();
setInterval(go, 15000);
</script></body></html>
"""


def page(title):
    return _PAGE.replace('__TITLE__', html.escape(title))
