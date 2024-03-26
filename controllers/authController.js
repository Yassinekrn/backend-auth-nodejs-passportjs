const User = require("../models/user");

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const { body, validationResult } = require("express-validator");
let verifyToken = require("../middlewares/verifyToken");
// home redirections are handled by the frontend

const passport = require("passport");
require("../strategies/local");
require("../strategies/jwt");

require("dotenv").config();

const salt = process.env.SALT;
const secret = process.env.JWT_SECRET;
const frontend_url = process.env.FRONTEND_URL;

// returns a 200 status if the token is valid
exports.verify_token = [
    verifyToken,
    asyncHandler(async (req, res, next) => {
        // if you reach here, the token is valid
        return res.status(200).json({ success: "token is valid" });
    }),
];

// validate fields, authenticate user, create and add token in header and return it
exports.login_post = [
    body("username", "Username must not be empty.")
        .trim()
        .isLength({ min: 1 })
        .escape(),
    body("password", "Password must not be empty.")
        .trim()
        .isLength({ min: 1 })
        .escape(),

    asyncHandler(async (req, res, next) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            // form errors
            res.status(400).json({ errors: errors.array() });
        }

        passport.authenticate("local", (err, user) => {
            if (err) {
                return next(err); // db query error
            }
            if (!user) {
                // auth failed
                return res
                    .status(401)
                    .json({ message: "Invalid username or password." });
            }

            const opts = {};
            opts.expiresIn = 3600; // 1Hr
            const token = jwt.sign({ user }, secret, opts);

            // add the token to the header
            res.setHeader("authorization", `Bearer ${token}`);
            res.setHeader("Access-Control-Expose-Headers", "authorization");

            return res.status(200).json({
                message: "Auth Passed",
            });
        })(req, res, next);
    }),
];

// validate fields, create user, hash password, save user, redirect to login
exports.signup_post = [
    body("fullName", "Full name must not be empty.")
        .trim()
        .isLength({ min: 1 })
        .escape(),
    body("username", "Username must not be empty.")
        .trim()
        .isLength({ min: 1 })
        .escape(),
    body("password", "Password must not be empty.")
        .trim()
        .isLength({ min: 1 })
        .escape(),
    body("confirm_password", "The password confirmation must not be empty")
        .trim()
        .isLength({ min: 1 })
        .escape(),
    body("confirm_password").custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error("Password confirmation does not match password");
        }
        return value === req.body.password;
    }),
    body("username").custom(async (value, { req }) => {
        const userWithSameUserName = await User.findOne({
            username: value,
        }).exec();
        if (userWithSameUserName) {
            throw new Error("Username already exists");
        }
        return !userWithSameUserName;
    }),
    asyncHandler(async (req, res, next) => {
        const errors = validationResult(req);

        let user = new User({
            fullName: req.body.fullName,
            username: req.body.username,
            password: req.body.password,
        });

        if (!errors.isEmpty()) {
            res.json({ errors: errors.array() });
        } else {
            // data is valid
            // hash the password
            bcrypt.hash(
                req.body.password,
                parseInt(salt),
                async (err, hashedPassword) => {
                    if (err) return next(err);
                    // otherwise, store hashedPassword in DB
                    user.password = hashedPassword;
                    await user.save();
                }
            );
            // res.json({ message: "User created successfully" });
            res.redirect(frontend_url + "/auth/login");
        }
    }),
];
