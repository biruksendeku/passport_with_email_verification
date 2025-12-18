const mongoose = require('mongoose');
const { isEmail } = require('validator');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
	console.log('Database Connected');
	//loadUsers();
})
.catch((err) => {
	console.log('Failed to connect to Database: ', err.message);
	process.exit(1);
});

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: [ true, 'Name field is required' ]
	},
	email: {
		type: String,
		unique: true,
		index: true,
		required: [ true, 'Email field is required' ],
		validate: [ isEmail, 'Invalid email address' ]
	},
	password: {
		type: String,
		required: [ true, 'Password field id required' ]
	},
	isVerified: {
		type: Boolean,
		default: false
	},
	verificationToken: String,
	verificationExpires: Date,
	createdAt: {
		type: Date,
		default: Date.now
	},
	verifiedAt: {
		type: Date,
		default: null
	}
});

module.exports = mongoose.model('user', userSchema);

/*
const loadUsers = async () => {
	const users = await User.find({});
	console.log(users);
};

//module.exports = User
*/
