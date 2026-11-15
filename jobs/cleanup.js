const cron = require('node-cron');

const User = require('../models/user');

// every day at midnight, delete unverified accounts older than 7 days
cron.schedule('0 0 * * *', async () => {
	try {
		const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
		const result = await User.deleteMany({
			isVerified: false,
			createdAt: { $lt: sevenDaysAgo }
		});
		console.log(`Unverified users deleted (7+ days old): ${result.deletedCount}`);
	} catch(err) {
		console.log('Cleanup job failed: ', err.message);
	}
});
