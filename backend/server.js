const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // serve uploaded files

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Path to user data file
const USERS_FILE = path.join(__dirname, 'users.json');

// Helper: read users from file
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE);
  return JSON.parse(data);
}

// Helper: write users to file
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  const users = readUsers();
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: Date.now().toString(),
    name,
    email,
    password: hashedPassword,
    files: [] // array of file objects { originalName, filename, path, uploadedAt }
  };
  users.push(newUser);
  writeUsers(users);

  // Return user data without password
  const { password: _, ...userWithoutPassword } = newUser;
  res.json({ user: userWithoutPassword });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const { password: _, ...userWithoutPassword } = user;
  res.json({ user: userWithoutPassword });
});

// Upload files (authenticated – we'll pass user ID in headers)
app.post('/api/upload', upload.array('files'), (req, res) => {
  const userId = req.headers['user-id'];
  if (!userId) return res.status(401).json({ error: 'User ID missing' });

  const users = readUsers();
  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex === -1) return res.status(404).json({ error: 'User not found' });

  const uploadedFiles = req.files.map(file => ({
    originalName: file.originalname,
    filename: file.filename,
    path: `/uploads/${file.filename}`,
    size: file.size,
    uploadedAt: new Date().toISOString()
  }));

  users[userIndex].files = [...(users[userIndex].files || []), ...uploadedFiles];
  writeUsers(users);

  res.json({ files: users[userIndex].files });
});

// Get user data (including files)
app.get('/api/user/:userId', (req, res) => {
  const userId = req.params.userId;
  const users = readUsers();
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { password, ...userWithoutPassword } = user;
  res.json({ user: userWithoutPassword });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});