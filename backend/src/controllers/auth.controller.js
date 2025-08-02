import cloudinary from "../lib/cloudinary.js";
import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from 'bcryptjs';

export const signup =  async (req, res) => {
    const { email, fullName, password } = req.body;
    try {
        
        if(!email || !fullName || !password) {
            return res.status(400).json({message:'Please fill all the fields'});
        }

        if(password.length < 6) {
            return res.status(400).json({message:'Password must be at least 6 characters long'});
        }

        const user = await User.findOne({ email });
        if(user) {
            return res.status(400).json({message:'User already exists with this email'});
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            email,
            fullName,
            password: hashedPassword
        });

        if(newUser) {
            //generate jwt token here
            generateToken(newUser._id, res);
            await newUser.save();

            res.status(201).json({
                user: {
                    _id: newUser._id,
                    fullName: newUser.fullName,
                    email: newUser.email,
                    profilePicture: newUser.profilePicture
                }
            });
        }
        else{
            res.status(400).json({
                message: 'User signup failed'})
        }
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}
export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if(!user) {
            return res.status(400).json({message:'Invalid credentials'});
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if(!isPasswordCorrect) {
            return res.status(400).json({message:'Invalid credentials'});
        }

        generateToken(user._id, res);

        res.status(200).json({
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                profilePicture: user.profilePicture
            }
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}
export const logout = (req, res) => {
    try {
        res.cookie('jwt', "", {maxAge:0});
        res.status(200).json({ message: 'User logged out successfully' });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

export const updateProfile = async (req, res) => {
    try {
        const { profilePicture } = req.body;
        const userId = req.user._id;

        if(!profilePicture) {
            return res.status(400).json({message: 'Please provide a profile picture'});
        }
        
        const uploadResponse = await cloudinary.uploader.upload(profilePicture)

        const updatedUser = await User.findByIdAndUpdate(userId, {
            profilePicture: uploadResponse.secure_url
        }, {new: true});

        res.status(200).json({
            message: 'Profile updated successfully',
            updatedUser
        });
    } catch (error) {
        console.error('Error during profile update:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

export const checkAuth = (req, res) => {
    try {
        res.status(200).json(
            {
                user: {
                    _id: req.user._id,
                    fullName: req.user.fullName,
                    email: req.user.email,
                    profilePicture: req.user.profilePicture,
                    createdAt: req.user.createdAt,
                    updatedAt: req.user.updatedAt
                }
            }
        )
    } catch (error) {
        console.error('Error during authentication check:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}