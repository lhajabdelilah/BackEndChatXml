const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bodyParser = require('body-parser');
const cors = require('cors'); // Import CORS
const multer = require('multer'); // Import multer
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: 'http://localhost:3001', // Allow React app
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// Middleware
app.use(cors()); // Enable CORS
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // Add URL-encoded body parser

// Serve uploaded files
app.use('/uploads', express.static('uploads')); // Serve files from uploads directory

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Save to the uploads directory
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`); // Create a unique filename
    }
});

// Allowed file types
const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedTypes = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.pdf', '.docx', '.txt'];
    
    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error('File type not allowed'), false);
    }
};

const upload = multer({ 
    storage,
    fileFilter
});

// JWT secret key
const JWT_SECRET = 'Y^2g8#KbNQ9@G$P!pFg^dRz3';

// Mock database for users
const users = [
    { id: 1, username: 'user1', password: bcrypt.hashSync('password1', 8) },
    { id: 2, username: 'user2', password: bcrypt.hashSync('password2', 8) }
];

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token invalid' });
        req.user = user;
        next();
    });
};

// Authentication route
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// File upload route
app.post('/upload', authenticateToken, upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).send('No file uploaded.');

    // Return the filename or URL of the uploaded file
    res.json({ filename: `http://localhost:3000/uploads/${req.file.filename}` });
});

// Socket.IO connection
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('sendMessage', (messageData) => {
        io.emit('receiveMessage', messageData); // Broadcast the message to all connected clients
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});

// Start server
server.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
