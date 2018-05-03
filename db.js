var mongoose = require('mongoose');
mongoose.connect('mongodb://shoppyAuth:shoppyauth123@ds143892.mlab.com:43892/shoppy-auth')
	.then(() => {
		console.log('Database connection successful')
	})
	.catch(err => {
		console.error(err)
	})