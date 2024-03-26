let express = require("express");
let router = express.Router();
let authController = require("../controllers/authController");

let passport = require("passport");
require("../strategies/google");

require("dotenv").config();

// get requests for pages are handled by the frontend, access depends on the user's authentication status ( using the token )
router.get("/verify-token", authController.verify_token);

router.post("/login", authController.login_post);

router.post("/signup", authController.signup_post);

router.get("/google", passport.authenticate("google", { scope: ["profile"] }));

router.get(
    "/google/callback",
    passport.authenticate("google", {
        session: false,
        failureRedirect: process.env.FRONTEND_URL + "/auth/login",
    }),
    authController.google_callback
);

module.exports = router;
