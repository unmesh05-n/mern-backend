// backend/routes/userRoute.js
import express from 'express';
import {
  loginUser,
  registerUser,
  adminLogin,
  getUserProfile,
  updateUserProfile,
  updateUserAddress,
  changeUserPassword
} from '../controllers/userController.js';
import authUser from '../middleware/auth.js'; // Make sure this is the correct path

const userRouter = express.Router();

// Auth & Admin
userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/admin', adminLogin);

// User Profile
userRouter.get('/me', authUser, getUserProfile);
userRouter.put('/me', authUser, updateUserProfile);
userRouter.put('/update-address', authUser, updateUserAddress);
userRouter.put('/change-password', authUser, changeUserPassword); // ✅ Change password route

export default userRouter;
