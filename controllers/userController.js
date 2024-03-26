const User = require("../models/user");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const { body, validationResult } = require("express-validator");
let verifyToken = require("../middlewares/verifyToken");
let { loginRedirector } = require("../middlewares/redirector");

const passport = require("passport");
require("../strategies/local");
require("../strategies/jwt");

require("dotenv").config();

const salt = process.env.SALT;
const secret = process.env.JWT_SECRET;
const frontend_url = process.env.FRONTEND_URL;

// get user data by userId (jwt verification + rediraction if not logged in)
exports.profile_get = [
    passport.authenticate("jwt", { session: false }),
    loginRedirector,
    asyncHandler(async (req, res, next) => {
        const userId = req.params.userId;
        if (!userId) {
            // bad request
            return res.status(400).json({ message: "User ID is required" });
        }
        try {
            const user = await User.findById(userId);
            if (!user) {
                return res.status(404).json({ message: "User not found" });
            }
            return res.status(200).json({
                status: "success",
                data: user,
            });
        } catch (error) {
            return res.status(500).json({ message: "Internal server error" });
        }
    }),
];
