import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
dotenv.config();
const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5000';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const ADMIN_URL = process.env.ADMIN_URL || 'http://localhost:3001';
const googleClient = new OAuth2Client({
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: `${BACKEND_URL}/api/auth/google/callback`
});
// The dashboard runs on a separate Next.js app (port 3001 in development), so
// it must be an allowed browser origin as well as the public website.
app.use(cors({ origin: [FRONTEND_URL, ADMIN_URL], credentials: true }));
app.use(express.json());
const getYouTubeVideoId = (value) => {
    if (typeof value !== 'string')
        return null;
    try {
        const url = new URL(value.trim());
        const host = url.hostname.replace(/^www\./, '').toLowerCase();
        let id = null;
        if (host === 'youtu.be')
            id = url.pathname.split('/')[1] || null;
        if (host === 'youtube.com' || host === 'm.youtube.com') {
            id = url.searchParams.get('v') || url.pathname.match(/^\/(?:embed|shorts|live)\/([^/?#]+)/)?.[1] || null;
        }
        return id && /^[A-Za-z0-9_-]{11}$/.test(id) ? id : null;
    }
    catch {
        return null;
    }
};
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'RMCodeLab Academy API' });
});
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email, and password are required.' });
        }
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) {
            return res.status(409).json({ message: 'User already exists.' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { name, email, passwordHash, isVerified: true }
        });
        const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '7d' });
        res.status(201).json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }
    catch (error) {
        res.status(500).json({ message: 'Registration failed', error });
    }
});
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !user.passwordHash) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '7d' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    }
    catch (error) {
        res.status(500).json({ message: 'Login failed', error });
    }
});
app.get('/api/auth/google', (_req, res) => {
    const authorizeUrl = googleClient.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope: ['openid', 'profile', 'email']
    });
    res.redirect(authorizeUrl);
});
app.get('/api/auth/google/callback', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) {
            return res.status(400).json({ message: 'Missing Google authorization code.' });
        }
        const { tokens } = await googleClient.getToken(code);
        googleClient.setCredentials(tokens);
        const userInfoResponse = await googleClient.request({ url: 'https://www.googleapis.com/oauth2/v2/userinfo' });
        const profile = userInfoResponse.data;
        if (!profile.email || !profile.verified_email) {
            return res.status(403).json({ message: 'Google account email not verified.' });
        }
        let user = await prisma.user.findUnique({ where: { email: profile.email } });
        if (!user) {
            user = await prisma.user.create({
                data: {
                    name: profile.name,
                    email: profile.email,
                    googleId: profile.id,
                    isVerified: true
                }
            });
        }
        else if (!user.googleId) {
            user = await prisma.user.update({
                where: { email: profile.email },
                data: { googleId: profile.id, isVerified: true }
            });
        }
        const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: '7d' });
        res.cookie('rmcodelab_token', token, {
            httpOnly: true,
            secure: BACKEND_URL.startsWith('https'),
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.redirect(`${FRONTEND_URL}/dashboard`);
    }
    catch (error) {
        res.status(500).json({ message: 'Google OAuth callback failed', error });
    }
});
app.get('/api/courses', async (_req, res) => {
    const courses = await prisma.course.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(courses);
});
app.get('/api/news', async (_req, res) => {
    const news = await prisma.newsItem.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(news);
});
app.get('/api/ai', async (_req, res) => {
    const config = await prisma.aIConfig.findFirst();
    res.json(config || { isEnabled: true, personality: 'Helpful and encouraging', knowledge: 'Use the academy curriculum.' });
});
// Video Management Endpoints
app.get('/api/videos', async (_req, res) => {
    try {
        const videos = await prisma.video.findMany({
            where: { isPublished: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(videos);
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to fetch videos', error });
    }
});
app.get('/api/videos/:level', async (req, res) => {
    try {
        const { level } = req.params;
        const videos = await prisma.video.findMany({
            where: { level, isPublished: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(videos);
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to fetch videos by level', error });
    }
});
app.get('/api/admin/videos', async (_req, res) => {
    try {
        const videos = await prisma.video.findMany({
            orderBy: { createdAt: 'desc' }
        });
        res.json(videos);
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to fetch videos', error });
    }
});
app.post('/api/admin/videos', async (req, res) => {
    try {
        const { title, description, youtubeUrl, level, category, isPublished } = req.body;
        const youtubeId = getYouTubeVideoId(youtubeUrl);
        if (!title?.trim() || !youtubeId) {
            return res.status(400).json({ message: 'A title and a valid YouTube video link are required.' });
        }
        const video = await prisma.video.create({
            data: {
                title: title.trim(),
                description: description || '',
                youtubeUrl: `https://www.youtube.com/watch?v=${youtubeId}`,
                level: level || 'Beginner',
                category: category || 'General',
                isPublished: isPublished !== undefined ? isPublished : true
            }
        });
        res.status(201).json({ message: 'Video added successfully', video });
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to add video', error });
    }
});
app.put('/api/admin/videos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description, youtubeUrl, level, category, isPublished } = req.body;
        const youtubeId = youtubeUrl === undefined ? null : getYouTubeVideoId(youtubeUrl);
        if (youtubeUrl !== undefined && !youtubeId) {
            return res.status(400).json({ message: 'Please provide a valid YouTube video link.' });
        }
        const video = await prisma.video.update({
            where: { id },
            data: {
                title: typeof title === 'string' && title.trim() ? title.trim() : undefined,
                description: description || undefined,
                youtubeUrl: youtubeId ? `https://www.youtube.com/watch?v=${youtubeId}` : undefined,
                level: level || undefined,
                category: category || undefined,
                isPublished: isPublished !== undefined ? isPublished : undefined
            }
        });
        res.json({ message: 'Video updated successfully', video });
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to update video', error });
    }
});
app.delete('/api/admin/videos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.video.delete({ where: { id } });
        res.json({ message: 'Video deleted successfully' });
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to delete video', error });
    }
});
// Simple health check for required OAuth environment
if (!process.env.GOOGLE_CLIENT_ID) {
    console.warn('WARNING: GOOGLE_CLIENT_ID is not set. Google OAuth will fail until configured.');
}
else {
    console.log('Google OAuth client ID loaded.');
}
// Attempt to listen, and if the port is in use, try the next port up to a limit.
function attemptListen(port, retries = 5) {
    const server = app.listen(port, () => {
        console.log(`API listening on http://localhost:${port}`);
    });
    server.on('error', (err) => {
        if (err && err.code === 'EADDRINUSE') {
            console.error(`Port ${port} is already in use.`);
            if (retries > 0) {
                const next = port + 1;
                console.log(`Retrying with port ${next} (${retries - 1} retries left)...`);
                setTimeout(() => attemptListen(next, retries - 1), 500);
                return;
            }
            console.error('No available ports found; please free the port or set a different PORT in backend/.env');
            process.exit(1);
        }
        console.error('Server error', err);
        process.exit(1);
    });
}
attemptListen(Number(PORT));
