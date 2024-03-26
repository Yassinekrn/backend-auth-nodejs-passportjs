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

// return a json message (protected route)
exports.homepage_get = [
    passport.authenticate("jwt", { session: false }),
    loginRedirector,
    asyncHandler(async (req, res, next) => {
        res.status(200).json({
            message: "Welcome to the protected homepage",
            userId: req.user._id,
        });
    }),
];
