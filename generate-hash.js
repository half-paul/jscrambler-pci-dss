
const bcrypt = require('bcrypt');

const plainPassword = 'admin123';
const saltRounds = 10;

bcrypt.hash(plainPassword, saltRounds, function(err, hash) {
    if (err) {
        console.error('Error hashing password:', err);
        return;
    }
    console.log('New hash:', hash);
});
