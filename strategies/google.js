let passport = require("passport");
let GoogleStrategy = require("passport-google-oauth20").Strategy;
require("dotenv").config();
const { v4: uuidv4 } = require("uuid");
let User = require("../models/user");

const removeSpaces = (str) => {
    return str.replace(/\s/g, "");
};

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            // callbackURL: process.env.FRONTEND_URL + "/auth/google/callback", // use this to make the operation work in frontend
            callbackURL: "http://localhost:3000/auth/google/callback",
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                let user = await User.findOne({ googleId: profile.id });
                if (!user) {
                    let uniqueUsername = "";
                    while (true) {
                        uniqueUsername = removeSpaces(profile.displayName);
                        uniqueUsername = uniqueUsername.toLowerCase();
                        uniqueUsername = uniqueUsername + uuidv4().slice(0, 5);
                        const userWithSameUserName = await User.findOne({
                            username: uniqueUsername,
                        }).exec();
                        if (!userWithSameUserName) {
                            break;
                        }
                    }
                    user = new User({
                        googleId: profile.id,
                        username: uniqueUsername,
                        fullName: profile.displayName,
                        password: uuidv4(),
                    });
                    await user.save();
                    return cb(null, user);
                } else {
                    return cb(null, user);
                }
            } catch (error) {
                return cb(error);
            }
        }
    )
);
