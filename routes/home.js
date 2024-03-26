let express = require("express");
let router = express.Router();
let homeController = require("../controllers/homeController");

let passport = require("passport");
require("../strategies/jwt");

router.get("/", homeController.homepage_get);

module.exports = router;
