const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 10, // 10 will do it - I guess
	message: 'Too many login attempts. Try again later.'
});

const apiLimiter = rateLimit({
	windowMs: 2 * 60 * 1000, // 2 minutes
	max: 10, // since these pages are 3 in total
	message: 'Too many request. Try again later.'
});

module.exports = { loginLimiter, apiLimiter };
