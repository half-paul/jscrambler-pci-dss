const bcrypt = require('bcrypt');

const plainPassword = 'admin123';
const hashedPassword = '$2b$10$rBV2uMXVz7WqNqyNjHjCJeX.8pKz2QKZvH.kP9C4xD5L6JLhYv6OW';

bcrypt.compare(plainPassword, hashedPassword, function(err, result) {
    if (err) {
        console.error('Error comparing passwords:', err);
        return;
    }
    console.log('Passwords match:', result);
});