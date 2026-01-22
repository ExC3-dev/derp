const express = require("express")
const bcrypt = require("bcrypt")
const sqlite = require("better-sqlite3")
const cookieParser = require("cookie-parser")
const crypto = require("crypto")

const app = express()
const db = sqlite("derp.db")

app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(cookieParser())

const PORT = 3000

// ---------------- DB ----------------
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
  id INTEGER PRIMARY KEY,
  owner INTEGER,
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

// ---------------- AUTH ----------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body
  const hash = await bcrypt.hash(password, 10)
  try {
    db.prepare("INSERT INTO users (username, passhash) VALUES (?,?)")
      .run(username, hash)
    res.send("registered")
  } catch {
    res.status(400).send("username taken")
  }
})

app.post("/login", async (req, res) => {
  const { username, password, remember } = req.body
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username)
  if (!user) return res.status(401).send("nope")
  if (!await bcrypt.compare(password, user.passhash)) return res.status(401).send("nope")

  const token = newToken()
  db.prepare("INSERT INTO sessions VALUES (?,?)").run(token, user.id)

  res.cookie("session", token, {
    httpOnly: true,
    maxAge: remember ? 1000 * 60 * 60 * 24 * 30 : undefined
  })
  res.send("ok")
})

app.post("/logout", (req, res) => {
  const token = req.cookies.session
  if (token) db.prepare("DELETE FROM sessions WHERE token=?").run(token)
  res.clearCookie("session")
  res.send("bye")
})

// ---------------- USER SITE ----------------
app.post("/save", (req, res) => {
  const user = auth(req)
  if (!user) return res.sendStatus(401)

  db.prepare(`
    INSERT INTO pages (owner, html)
    VALUES (?,?)
    ON CONFLICT(owner) DO UPDATE SET html=excluded.html
  `).run(user.id, req.body.html)

  res.send("saved")
})

// ---------------- VIEW SITE ----------------
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
  srcdoc="${(page?.html || "").replace(/"/g, "&quot;")}"
></iframe>
`)
})

// ---------------- LIKES ----------------
app.post("/like/:user", (req, res) => {
  const pageOwner = db.prepare("SELECT id FROM users WHERE username=?")
    .get(req.params.user)
  if (!pageOwner) return res.sendStatus(404)

  db.prepare("UPDATE pages SET likes=likes+1 WHERE owner=?")
    .run(pageOwner.id)
  res.send("liked")
})

app.post("/dislike/:user", (req, res) => {
  const pageOwner = db.prepare("SELECT id FROM users WHERE username=?")
    .get(req.params.user)
  if (!pageOwner) return res.sendStatus(404)

  db.prepare("UPDATE pages SET dislikes=dislikes+1 WHERE owner=?")
    .run(pageOwner.id)
  res.send("boo")
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

// ---------------- COIN FLIP GAME ----------------
app.post("/coinflip", (req, res) => {
  const user = auth(req)
  if (!user) return res.sendStatus(401)

  const bet = Math.min(50, Math.max(1, req.body.bet|0))
  if (user.coins < bet) return res.send("broke")

  const win = Math.random() < 0.5

  db.prepare("UPDATE users SET coins=coins+?, exp=exp+5 WHERE id=?")
    .run(win ? bet : -bet, user.id)

  res.json({ win })
})

app.listen(PORT, () =>
  console.log("derp.digital lives on http://localhost:" + PORT)
)
