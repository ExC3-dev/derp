const express = require("express")
const bcrypt = require("bcryptjs")
const sqlite = require("better-sqlite3")
const cookieParser = require("cookie-parser")
const crypto = require("crypto")

const app = express()
const db = sqlite("derp.db")

app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(cookieParser())

const PORT = 3000

// ---------------- DATABASE ----------------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  passhash TEXT,
  coins INTEGER DEFAULT 100,
  exp INTEGER DEFAULT 0,
  level INTEGER DEFAULT 1,
  admin INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER
);

CREATE TABLE IF NOT EXISTS pages (
  owner INTEGER PRIMARY KEY,
  html TEXT,
  likes INTEGER DEFAULT 0,
  dislikes INTEGER DEFAULT 0
);
`)

// ---------------- HELPERS ----------------
function auth(req) {
  const token = req.cookies.session
  if (!token) return null
  const row = db.prepare("SELECT user_id FROM sessions WHERE token=?").get(token)
  if (!row) return null
  return db.prepare("SELECT * FROM users WHERE id=?").get(row.user_id)
}

function newToken() {
  return crypto.randomBytes(32).toString("hex")
}

// ---------------- LANDING ----------------
app.get("/", (req, res) => {
  res.send(`
<!doctype html>
<meta charset="utf-8">
<title>derp.digital</title>
<style>
body {
  background:#0b0b0e;
  color:#eee;
  font-family:monospace;
  padding:40px;
}
input, button {
  background:#111;
  color:#fff;
  border:1px solid #333;
  padding:6px;
  margin:4px 0;
}
</style>

<h1>derp.digital</h1>
<p>paste html. run scripts. gamble coins.</p>

<h3>register</h3>
<form method="post" action="/register">
  <input name="username" placeholder="username" required><br>
  <input type="password" name="password" placeholder="password" required><br>
  <button>register</button>
</form>

<h3>login</h3>
<form method="post" action="/login">
  <input name="username" placeholder="username" required><br>
  <input type="password" name="password" placeholder="password" required><br>
  <label><input type="checkbox" name="remember"> remember device</label><br>
  <button>login</button>
</form>
`)
})

// ---------------- AUTH ----------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body
  const hash = await bcrypt.hash(password, 10)
  try {
    db.prepare("INSERT INTO users (username, passhash) VALUES (?,?)")
      .run(username, hash)
    res.redirect("/")
  } catch {
    res.send("username taken")
  }
})

app.post("/login", async (req, res) => {
  const { username, password, remember } = req.body
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username)
  if (!user) return res.send("nope")
  if (!await bcrypt.compare(password, user.passhash)) return res.send("nope")

  const token = newToken()
  db.prepare("INSERT INTO sessions VALUES (?,?)").run(token, user.id)

  res.cookie("session", token, {
    httpOnly: true,
    maxAge: remember ? 1000 * 60 * 60 * 24 * 30 : undefined
  })

  res.redirect("/me")
})

app.post("/logout", (req, res) => {
  const token = req.cookies.session
  if (token) db.prepare("DELETE FROM sessions WHERE token=?").run(token)
  res.clearCookie("session")
  res.redirect("/")
})

// ---------------- DASHBOARD ----------------
app.get("/me", (req, res) => {
  const user = auth(req)
  if (!user) return res.redirect("/")

  const page = db.prepare("SELECT html FROM pages WHERE owner=?")
    .get(user.id)?.html || ""

  res.send(`
<!doctype html>
<meta charset="utf-8">
<title>${user.username} — derp</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b0b0e;color:#eee;font-family:monospace}
header{padding:16px;border-bottom:1px solid #222;display:flex;justify-content:space-between}
main{display:grid;grid-template-columns:1fr 1fr;height:calc(100vh - 60px)}
textarea{width:100%;height:100%;background:#0a0a0f;color:#baffc9;border:none;padding:16px}
iframe{width:100%;height:100%;border:none;background:#fff}
.actions{padding:10px;border-top:1px solid #222;background:#0e0e13}
button{background:#14141d;color:#fff;border:1px solid #333;padding:6px}
a{color:#7aa2ff;text-decoration:none}
</style>

<header>
  <div>${user.username} · coins ${user.coins} · exp ${user.exp} · lvl ${user.level}</div>
  <a href="/${user.username}" target="_blank">view site</a>
</header>

<main>
<form method="post" action="/save">
  <textarea id="editor" name="html">${page
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")}</textarea>
  <div class="actions">
    <button>save</button>
    <button type="button" onclick="preview()">preview</button>
  </div>
</form>

<div>
  <iframe id="frame" sandbox="allow-scripts allow-forms allow-popups"></iframe>
  <div class="actions">
    <form method="post" action="/logout"><button>logout</button></form>
  </div>
</div>
</main>

<script>
const editor=document.getElementById("editor")
const frame=document.getElementById("frame")
function preview(){ frame.srcdoc=editor.value }
preview()
</script>
`)
})

// ---------------- SAVE PAGE ----------------
app.post("/save", (req, res) => {
  const user = auth(req)
  if (!user) return res.sendStatus(401)

  db.prepare(`
    INSERT INTO pages (owner, html)
    VALUES (?,?)
    ON CONFLICT(owner) DO UPDATE SET html=excluded.html
  `).run(user.id, req.body.html)

  res.redirect("/me")
})

// ---------------- VIEW USER SITE ----------------
app.get("/:username", (req, res) => {
  const user = db.prepare("SELECT id FROM users WHERE username=?")
    .get(req.params.username)
  if (!user) return res.send("no such derp")

  const page = db.prepare("SELECT html FROM pages WHERE owner=?")
    .get(user.id)

  res.send(`
<!doctype html>
<meta charset="utf-8">
<title>${req.params.username}.derp</title>
<iframe
  sandbox="allow-scripts allow-forms allow-popups"
  style="border:none;width:100vw;height:100vh"
  srcdoc="${(page?.html||"").replace(/"/g,"&quot;")}"
></iframe>
`)
})

// ---------------- LIKES ----------------
app.post("/like/:user", (req, res) => {
  const u = db.prepare("SELECT id FROM users WHERE username=?").get(req.params.user)
  if (!u) return res.sendStatus(404)
  db.prepare("UPDATE pages SET likes=likes+1 WHERE owner=?").run(u.id)
  res.send("ok")
})

app.post("/dislike/:user", (req, res) => {
  const u = db.prepare("SELECT id FROM users WHERE username=?").get(req.params.user)
  if (!u) return res.sendStatus(404)
  db.prepare("UPDATE pages SET dislikes=dislikes+1 WHERE owner=?").run(u.id)
  res.send("ok")
})

// ---------------- LEADERBOARD ----------------
app.get("/leaderboard", (req, res) => {
  const rows = db.prepare(`
    SELECT username, coins, exp
    FROM users
    WHERE admin=0
    ORDER BY coins DESC
    LIMIT 10
  `).all()
  res.json(rows)
})

// ---------------- COIN FLIP ----------------
app.post("/coinflip", (req, res) => {
  const user = auth(req)
  if (!user) return res.sendStatus(401)

  const bet = Math.max(1, Math.min(50, req.body.bet|0))
  if (user.coins < bet) return res.send("broke")

  const win = Math.random() < 0.5
  db.prepare("UPDATE users SET coins=coins+?, exp=exp+5 WHERE id=?")
    .run(win ? bet : -bet, user.id)

  res.json({ win })
})

// ---------------- START ----------------
app.listen(PORT, () => {
  console.log("derp.digital running on http://localhost:" + PORT)
})
