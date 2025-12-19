const nodemailer = require('nodemailer');
require('dotenv').config();

/**
 * Shared Nodemailer SMTP transport used for all outgoing mail.
 * Configured from EMAIL_USER / EMAIL_PASS environment variables.
 */
const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS
	}
});

/**
 * Sends the email verification mail for a given user.
 * @param {string} email - recipient email address
 * @param {string} token - raw verification token stored on the user document
 * @returns {Promise<void>} resolves when the mail is accepted by the transport
 * @throws {Error} if the SMTP transport fails to send the message
 */
const sendVerificationEmail = async (email, token) => {
	const verificationUrl = `${process.env.BASE_URL}/api/verify-email/${token}`;
	const mailOptions = {
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Verify Your Email',
		html: `
		<h1> Verify Your Email </h1>
		<p> Click on the link below to verify your email: </p>
		<a href="${verificationUrl}"> Verify Here </a>
		<p> This link will expire in 24 hours. </p>
		`
	};
	await transporter.sendMail(mailOptions);
};

module.exports = { transporter, sendVerificationEmail };
