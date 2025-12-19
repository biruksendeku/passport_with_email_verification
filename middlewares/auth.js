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

module.exports = { isLogged };
