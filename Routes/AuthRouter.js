const { signup, login, requestOtp, verifyOtp } = require('../Controllers/AuthController');
const { signupValidation, loginValidation } = require('../Middlewares/AuthValidation');

const router = require('express').Router();

// Email-password signup and login
router.post('/signup', signupValidation, signup);
router.post('/login', loginValidation, login);

// OTP-based login
router.post('/loginviaotp', requestOtp);       
router.post('/verifyotp', verifyOtp);         

module.exports = router;
