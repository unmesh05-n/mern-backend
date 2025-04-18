import validator from "validator";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import userModel from "../models/userModel.js";

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};

// User Login
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "User doesn't exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      const token = createToken(user._id);
      res.json({ success: true, token });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// User Register
const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    if (!validator.isEmail(email)) {
      return res.json({ success: false, message: "Please enter a valid email" });
    }

    if (password.length < 8) {
      return res.json({ success: false, message: "Please enter a strong password" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new userModel({ name, email, password: hashedPassword });
    const user = await newUser.save();

    const token = createToken(user._id);
    res.json({ success: true, token });

  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Admin Login
const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign(email + password, process.env.JWT_SECRET);
      res.json({ success: true, token });
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Get User Profile
const getUserProfile = async (req, res) => {
  try {
    const user = await userModel.findById(req.body.userId).select('name email address');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Update User Profile
const updateUserProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await userModel.findById(req.body.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.name = name || user.name;
    user.email = email || user.email;

    await user.save();

    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Update Address
const updateUserAddress = async (req, res) => {
  try {
    const user = await userModel.findById(req.body.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.address = req.body.address || user.address;
    await user.save();

    res.json({ success: true, message: 'Address updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
export const changeUserPassword = async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = await userModel.findById(req.body.userId);
  
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
  
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Incorrect current password' });
      }
  
      if (newPassword.length < 8) {
        return res.status(400).json({ success: false, message: 'New password must be at least 8 characters' });
      }
  
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
      await user.save();
  
      res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: error.message });
    }
  };
  

export {
  loginUser,
  registerUser,
  adminLogin,
  getUserProfile,
  updateUserProfile,
  updateUserAddress
};
