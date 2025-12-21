const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const User = require('./models/user');
const { sendVerificationEmail } = require('./utils/mailer');
const { normalizeName } = require('./utils/helpers');
const { isLogged } = require('./middlewares/auth');
const { loginLimiter, apiLimiter } = require('./middlewares/rateLimiters');
require('./jobs/cleanup');

const app = express();
const port = process.env.PORT || 3000;
const publicFolder = path.join(__dirname, 'public');

// app settings
app.set('view engine', 'ejs');
app.set('view cache', false);

// built-in middlewares
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicFolder));

// simple request logger
app.use((req, res, next) => {
	console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
	next();
});
app.use(session({
	secret: process.env.SESSION_SECRET_KEY,
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 24 * 60 * 60 * 1000 // 1 day
	}
}));
app.use(passport.initialize());
app.use(passport.session());

app.use('/login', loginLimiter);

app.use('/api', apiLimiter);

// passport stuff
passport.use(new LocalStrategy(
	{
		usernameField: 'email',
		passwordField: 'password'
	},
	async (email, password, done) => {
		if(!email || !password) {
			return done(new Error('Missing Credentials'), null);
		}
		const user = await User.findOne({ email });
		if(!user) {
			return done(new Error('Invalid Credentials - Incorrect email or password'), null);
		}
		const isValid = await bcrypt.compare(password, user.password);
		if(!isValid) {
			return done(new Error('Invalid Credentials'), null);
		}
		// successfully authenticated - go to serialization
		done(null, user);
	}
));

passport.serializeUser((user, done) => {
	try {
		done(null, user.id); // using id to serialize
	} catch(err) {
		done(err, null);
	}
});

passport.deserializeUser(async (id, done) => {
	try {
		const user = await User.findById(id);
		if(!user) {
			return done(new Error('Invalid Credentials - Incorrect email or password'), null);
		}
		// there's user, deserualize it
		done(null, user);
	} catch(err) {
		done(err, null);
	}
});

// CRUD operation
app.get('/signup', (req, res, next) => {
	try{
		res.render('signup');
	} catch(err) {
		next(err);
	}
});

app.post('/signup', async (req, res, next) => {
	try {
		const { name, email, password, confirmPassword } = req.body;
		if(!name || !email || !password || !confirmPassword) {
			return res.status(400).send('Bad Request - Missing Credentials');
		}
		if(password !== confirmPassword) {
			return res.status(400).send('Bad Request - Password Mismatch');
		}
		if(password.length < 8) {
			return res.status(400).send('Bad Request - Password must be at least 8 characters long');
		}
		// keep emails consistent so duplicates can't slip through by casing
		const normalizedEmail = email.trim().toLowerCase();
		const user = await User.findOne({ email: normalizedEmail });
		if(user) {
			return res.status(403).send('Email already exists, <a href="/login"> Login </a> to continue.');
		}
		// save it
		const hashedPassword = await bcrypt.hash(password, 10);
		const name2 = normalizeName(name);
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1day plus

		const newUser = new User({
			name: name2,
			email: normalizedEmail,
			password: hashedPassword,
			verificationToken,
			verificationExpires
		});

		await newUser.save();
		res.status(201).send('Registration Successful. Please check your email to verify your account.');

		sendVerificationEmail(normalizedEmail, verificationToken).catch((err) => {
			console.log('Failed to send verification email: ', err.message);
		});
		
	} catch(err) {
		next(err);
	}
});

app.get('/api/verify-email/:token', async (req, res, next) => {
	try {
		const token = req.params.token.toString();
		// we use the random string to verify the user
		const user = await User.findOne({
			verificationToken: token,
			verificationExpires: { $gt: Date.now() }
		});
		if(!user) {
			//return res.status(400).send('Invalid or Expired Verification Link.');
			return res.render('resend-verification');
		}
		// update the user infos
		user.verificationToken = undefined; // remove from db
		user.verificationExpires = undefined;
		user.isVerified = true; // re-write the default false
		user.verifiedAt = Date.now(); // mark the Date of verification
		await user.save();

		req.login(user, (err) => {
			if(err) {
				return next(err);
			}
			res.redirect('/profile');
		});
		
	} catch(err) {
		next(err);
	}
});

app.get('/resend-verification', (req, res, next) => {
	try {
		res.render('resend-verification');
	} catch(err) {
		next(err);
	}
});

app.post('/resend-verification', async (req, res, next) => {
	try {
		const { email } = req.body;
		const user = await User.findOne({
			email,
			isVerified: false
		});
		if(!user) {
			return res.status(403).send('Email not found or already verified');
		}
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; //1day plus

		user.verificationToken = verificationToken;
		user.verificationExpires = verificationExpires;
		await user.save();

		// first notify them - since it'll lag if used after sending token
		res.status(200).send('Email Sent. Check your email to verify');

		sendVerificationEmail(email, verificationToken).catch((err) => {
			console.log('Resending verification email failed: ', err.message);
		});
		
	} catch(err) {
		next(err);
	}
});

app.get('/login', (req, res, next) => {
	try {
		res.render('login');
	} catch(err) {
		next(err);
	}
});

app.post('/login', passport.authenticate('local', {
	failureRedirect: '/login',
	successRedirect: '/profile'
}));

app.get('/profile', isLogged, (req, res, next) => {
	try {
		res.render('profile', {
			user: req.user
		});
	} catch(err) {
		next(err);
	}
});

app.get('/logout', (req, res, next) => {
	try {
		req.logout((err) => {
			if(err) {
				return res.send('Logout Failed, Try again.');
			}
			res.redirect('/login');
		});
	} catch(err) {
		next(err);
	}
});

// health check
app.get('/health', (req, res) => {
	res.status(200).json({ status: 'ok', uptime: process.uptime() });
});

app.use((req, res, next) => {
	try {
		res.status(404).send('Page Not Found - <a href="/login"> Back to Login </a>');
	} catch(err) {
		next(err);
	}
});

app.use((err, req, res, next) => {
	if(process.env.NODE_ENV !== 'development') {
		console.log('Error Message: ', err.message);
		console.log('Error Stack: ', err.stack);
		return res.status(500).send('Internal Server Error');
	}
	res.json({ error: err.stack });
});

const server = app.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});

// graceful shutdown
const shutdown = (signal) => {
	console.log(`${signal} received. Shutting down...`);
	server.close(() => {
		console.log('Server closed.');
		process.exit(0);
	});
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
