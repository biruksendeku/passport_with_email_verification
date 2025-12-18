const express = require('express');
const nodemailer = require('nodemailer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const User = require('./models/user');

const app = express();
const port = process.env.PORT || 3000;
const publicFolder = path.join(__dirname, 'public');

// app settings
app.set('view engine', 'ejs');
app.set('view cache', false);

// built-in middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicFolder));
app.use(session({
	secret: process.env.SESSION_SECRET_KEY,
	resave: false,
	saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// custom middlewares
const loginLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 10, // 10 will do it - I guess
	message: 'Too many login attempts. Try again later.'
});
app.use('/login', loginLimiter);

const apiLimiter = rateLimit({
	windowMs: 2 * 60 * 1000, // 2 minutes
	max: 10, // since these pages are 3 in total
	message: 'Too many request. Try again later.'
});
app.use('/api', apiLimiter);

const isLogged = (req, res, next) => {
	try {
		if(!req.isAuthenticated()) {
			return res.redirect('/login');
		}
		next();
	} catch(err) {
		next(err);
	}
};

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS
	}
});

const sendVerificationEmail = async (email, token) => {
	const verificationUrl = `${process.env.BASE_URL}/api/verify-email/${token}`;
	const mailOptions = {
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Verify Your Email',
		html: `
		<h1> Verify Your Email </h1>
		<p> Clicl on the link below to verify your email: </p>
		<a href="${verificationUrl}"> Verify Here </a>
		<p> This link will expire in 24 hours. </p>
		`
	};
	await transporter.sendMail(mailOptions);
};

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
		const user = await User.findOne({ email });
		if(user) {
			return res.status(403).send('Email already exists, <a href="/login"> Login </a> to continue.');
		}
		// save it
		const hashedPassword = await bcrypt.hash(password, 10);
		const name2 = name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1day plus

		const newUser = new User({
			name: name2,
			email,
			password: hashedPassword,
			verificationToken,
			verificationExpires
		});

		await newUser.save();
		res.status(201).send('Registration Successful. Please check your email to verify your account.');

		sendVerificationEmail(email, verificationToken).catch((err) => {
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

app.use((req, res, next) => {
	try {
		res.status(404).send('Page Not Found');
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

app.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});
