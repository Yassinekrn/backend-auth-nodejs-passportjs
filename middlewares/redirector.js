require("dotenv").config();
const frontEndUrl = process.env.FRONTEND_URL;

const loginRedirector = (req, res, next) => {
    req.user ? next() : res.status(401).redirect(frontEndUrl + "/auth/login");
};

// handled by the frontend
// const homeRedirector = (req, res, next) => {
//     req.user ? res.status(401).redirect(frontEndUrl + "/") : next();
// };

module.exports = { loginRedirector };
