const mongoose = require('mongoose');
const { Schema } = mongoose;

function requiresPassword() {
    // this
    return !this.withGoogle;
}


const userSchema = new Schema([{
    userName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: requiresPassword
    },
    rol: {
        type: String,
        default: 'pending',
        enum: ['admin', 'seller', 'pending']
    },
    withGoogle: {
        type: Boolean,
        required: true,
    },
    userId: {
        type: String,
    },
    status: {
        type: String,
        required: true,
        default:"pending",
        enum: ['pending', 'authorized', 'unauthorized']
    },
}, {
    versionKey: false
}]);

userSchema.methods.toJSON = function () {
    return { ...this.toObject(), password: undefined };
}

module.exports = mongoose.model('users', userSchema);