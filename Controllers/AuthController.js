const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const emailjs = require('emailjs-com');
const UserModel = require("../Models/User");
const OtpModel = require("../Models/User");

// Function to generate a 6-digit OTP
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

// Send OTP email using EmailJS
const sendOtpMail = async (email, otp) => {
    try {
        const response = await emailjs.send(
            'service_zyeeiwa', // Service ID from EmailJS dashboard
            'template_19kroh6', // Your Template ID
            {
                to_email: email,
                otp: otp, // You can add the OTP to the email template as a variable
            },
            'brakinbad2504@gmail.com' // User ID from EmailJS account
        );
        console.log('Email sent successfully', response);
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Email sending failed');
    }
};

// Signup
const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const user = await UserModel.findOne({ email });
        if (user) {
            return res.status(409).json({ message: 'User already exists, please login', success: false });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModel({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "Signup successful", success: true });
    } catch (err) {
        res.status(500).json({ message: "Internal server error", success: false });
    }
};

// Login with email & password
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserModel.findOne({ email });
        const errorMsg = 'Authentication failed: email or password is incorrect';

        if (!user) {
            return res.status(403).json({ message: errorMsg, success: false });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).json({ message: errorMsg, success: false });
        }

        const token = jwt.sign({ email: user.email, _id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(200).json({
            message: "Login successful",
            success: true,
            jwtToken: token,
            email,
            name: user.name
        });
    } catch (err) {
        res.status(500).json({ message: "Internal server error", success: false });
    }
};

// Request OTP login
const requestOtp = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "Email not found" });
        }

        const otp = generateOtp();

        await OtpModel.deleteMany({ email }); // clear old OTPs
        const otpDoc = new OtpModel({ email, otp });
        await otpDoc.save();

        await sendOtpMail(email, otp);

        res.status(200).json({ success: true, message: "OTP sent to email" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Internal server error" });
    }
};

// Verify OTP and login
const verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    try {
        const otpRecord = await OtpModel.findOne({ email, otp });
        if (!otpRecord) {
            return res.status(401).json({ success: false, message: "Invalid or expired OTP" });
        }

        await OtpModel.deleteMany({ email }); // delete used OTP

        const user = await UserModel.findOne({ email });
        const token = jwt.sign({ email: user.email, _id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.status(200).json({
            success: true,
            message: "Login successful",
            jwtToken: token,
            email: user.email,
            name: user.name
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Internal server error" });
    }
};

module.exports = {
    signup,
    login,
    requestOtp,
    verifyOtp
};
