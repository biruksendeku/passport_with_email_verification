const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 10,
	message: 'Too many login attempts. Try again later.'
});

const apiLimiter = rateLimit({
	windowMs: 2 * 60 * 1000, // 2 minutes
	max: 10,
	message: 'Too many requests. Try again later.'
});

module.exports = { loginLimiter, apiLimiter };
