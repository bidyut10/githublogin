const express = require('express');
const cors = require('cors');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const jwt = require('jsonwebtoken');
const axios = require('axios');  // Use axios instead of node-fetch
const cookieParser = require('cookie-parser');

const app = express();

// Middleware to parse cookies
app.use(cookieParser());
// CORS configuration to allow your frontend domain
const corsOptions = {
    origin: 'https://gitai.netlify.app/',  // Replace with your frontend domain
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,  // Allow credentials (cookies or authorization headers)
};

app.use(cors(corsOptions));
app.use(express.json());

// GitHub OAuth Setup
passport.use(new GitHubStrategy({
    clientID: 'Ov23liaqiM1eayQKHRmn',
    clientSecret: '88130c9beccd1b3368fd17175cf51f19e5217a9f',
    callbackURL: 'https://githublogin.onrender.com/auth/github/callback',
}, (accessToken, refreshToken, profile, done) => {
    return done(null, { profile, accessToken });
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Routes
app.get('/auth/github', passport.authenticate('github', { scope: ['repo', 'user'] }));

// GitHub OAuth Callback
app.get('/auth/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.profile.id, accessToken: user.accessToken }, 'gitaiproject', { expiresIn: '1h' });

    // Set the token as an HttpOnly cookie
    res.cookie('token', token, {
        httpOnly: true,  // Make the cookie inaccessible to JavaScript (for security)
        secure: process.env.NODE_ENV === 'production',  // Use secure cookies in production
        sameSite: 'Strict',  // Restrict cross-site requests
        maxAge: 3600000,  // 1 hour expiration
    });

    // Redirect the user to the home page
    res.redirect('https://gitai.netlify.app/home');
});

// Route to fetch user repositories
app.get('/user/repos', (req, res) => {
    const token = req.cookies.token;  // Get the token from the HttpOnly cookie

    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, 'gitaiproject');
        const accessToken = decoded.accessToken;

        // Fetch user repositories using GitHub API with axios
        axios.get('https://api.github.com/user/repos', {
            headers: { Authorization: `token ${accessToken}` }
        })
            .then(response => res.json(response.data))  // Return repos data
            .catch(err => {
                console.error('Error fetching repos:', err);
                res.status(500).json({ error: 'Failed to fetch repos' });
            });
    } catch (err) {
        console.error('Invalid token error:', err);
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports =app