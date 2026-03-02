
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const SQLite = require("better-sqlite3");
const multer = require("multer");
const path = require("path");

const app = express();
const db = new SQLite("database.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  price INTEGER,
  filename TEXT
);
`);

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: "secureSecretKey123",
  resave: false,
  saveUninitialized: false
}));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const storage = multer.diskStorage({
  destination: "./public/uploads",
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  }
});
const upload = multer({ storage });

// Home
app.get("/", (req, res) => {
  const courses = db.prepare("SELECT * FROM courses").all();
  res.render("index", { user: req.session.user, courses });
});

// Register
app.post("/register", async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  try {
    db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
      .run(req.body.username, hashed);
    res.redirect("/");
  } catch {
    res.send("User already exists");
  }
});

// Login
app.post("/login", async (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE username = ?")
    .get(req.body.username);
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    req.session.user = user;
    res.redirect("/");
  } else {
    res.send("Invalid credentials");
  }
});

// Admin Panel
app.get("/admin", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.send("Access denied");
  const courses = db.prepare("SELECT * FROM courses").all();
  res.render("admin", { courses });
});

// Upload Course
app.post("/upload", upload.single("coursefile"), (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.send("Access denied");
  db.prepare("INSERT INTO courses (title, price, filename) VALUES (?, ?, ?)")
    .run(req.body.title, req.body.price, req.file.filename);
  res.redirect("/admin");
});

// Payment Page
app.get("/pay/:id", (req, res) => {
  const course = db.prepare("SELECT * FROM courses WHERE id = ?")
    .get(req.params.id);
  res.render("payment", { course });
});

// Download after manual confirmation
app.get("/download/:filename", (req, res) => {
  res.download("./public/uploads/" + req.params.filename);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
