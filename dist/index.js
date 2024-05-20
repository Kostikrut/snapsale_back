var $bdTtH$process = require("process");
var $bdTtH$mongoose = require("mongoose");
var $bdTtH$dotenv = require("dotenv");
var $bdTtH$express = require("express");
require("morgan");
var $bdTtH$expressratelimit = require("express-rate-limit");
var $bdTtH$helmet = require("helmet");
var $bdTtH$expressmongosanitize = require("express-mongo-sanitize");
var $bdTtH$xssclean = require("xss-clean");
var $bdTtH$hpp = require("hpp");
var $bdTtH$cors = require("cors");
var $bdTtH$util = require("util");
var $bdTtH$jsonwebtoken = require("jsonwebtoken");
var $bdTtH$crypto = require("crypto");
var $bdTtH$validator = require("validator");
var $bdTtH$bcryptjs = require("bcryptjs");
var $bdTtH$nodemailer = require("nodemailer");
var $bdTtH$slugify = require("slugify");
var $bdTtH$buffer = require("buffer");




$bdTtH$dotenv.config({
    path: "./config.env"
});
// Catch uncaught exceptions if not handled
$bdTtH$process.on("uncaughtException", (err)=>{
    console.log("UNCAUGHT EXCEPTION! \uD83D\uDCA5 Shutting down...");
    console.log(err.name, err.message, err);
    $bdTtH$process.exit(1);
});
var $84a264530b3fb4fb$exports = {};








var $e203200498571e93$exports = {};
class $e203200498571e93$var$AppError extends Error {
    constructor(message, statusCode){
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
$e203200498571e93$exports = $e203200498571e93$var$AppError;


var $6e01d007996f5575$exports = {};

const $6e01d007996f5575$var$handleCastErrorDB = (err)=>{
    const message = `Invalid ${err.path}: ${err.value}`;
    return new $e203200498571e93$exports(message, 400);
};
const $6e01d007996f5575$var$handleValidationErrorDB = (err)=>{
    const errors = Object.values(err.errors).map((el)=>el.message);
    const message = `Invalid input data. ${errors.join(". ")}`;
    return new $e203200498571e93$exports(message, 400);
};
const $6e01d007996f5575$var$handleJWTError = (err)=>new $e203200498571e93$exports("Invalid token, please log in again.", 401);
const $6e01d007996f5575$var$handleExpiredJWTError = (err)=>new $e203200498571e93$exports("Access token has expired, please log in again to get access.", 401);
const $6e01d007996f5575$var$sendErrorDev = (err, res)=>{
    return res.status(err.statusCode).json({
        status: err.status,
        err: err,
        message: err.message,
        stack: err.stack
    });
};
const $6e01d007996f5575$var$sendErrorProd = (err, res)=>{
    if (err.isOperational) return res.status(err.statusCode).json({
        status: err.status,
        message: err.message
    });
    // for unknown errors in production - general error/not operational
    return res.status(500).json({
        status: "error",
        message: "Something went wrong"
    });
};
$6e01d007996f5575$exports = (err, req, res, next)=>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "error";
    {
        let error = {
            ...err
        };
        if (err.name === "CastError") error = $6e01d007996f5575$var$handleCastErrorDB(error); //handle invalid id query
        if (err.name === "ValidationError") error = $6e01d007996f5575$var$handleValidationErrorDB(error); // handle validation error
        if (err.name === "JsonWebTokenError") error = $6e01d007996f5575$var$handleJWTError(error); // handle incorrect jwt
        if (err.name === "TokenExpiredError") error = $6e01d007996f5575$var$handleExpiredJWTError(error); // handle expired jwt
        $6e01d007996f5575$var$sendErrorProd(error, res);
    }
    next();
};


var $73d7888de7213739$exports = {};

var $ce487c6e3030a219$export$7200a869094fec36;
//                             {{{{DO LATER}}}}      ACTIVATE USER AGAIN IF HE IS DELETED HIS ACCOUNT
var $ce487c6e3030a219$export$596d806903d1f59e;
var $ce487c6e3030a219$export$eda7ca9e36571553;
// Restrict certain user roles from access to certain route
var $ce487c6e3030a219$export$e1bac762c84d3b0c;
var $ce487c6e3030a219$export$66791fb2cfeec3e;
var $ce487c6e3030a219$export$dc726c8e334dd814;
var $ce487c6e3030a219$export$e2853351e15b7895;

var $ce487c6e3030a219$require$promisify = $bdTtH$util.promisify;

var $ca4b57b91abcd647$exports = {};




const $ca4b57b91abcd647$var$userSchema = new $bdTtH$mongoose.Schema({
    fullName: {
        type: String,
        required: [
            true,
            "Please tell us your name"
        ],
        trim: true
    },
    email: {
        type: String,
        unique: true,
        required: [
            true,
            "Please provide your email address"
        ],
        trim: true,
        lowerCase: true,
        validate: [
            $bdTtH$validator.isEmail,
            "Please provide a valid email address"
        ]
    },
    phone: {
        type: Number,
        unique: true,
        required: [
            true,
            "Please tell us your phone number"
        ]
    },
    role: {
        type: String,
        enum: [
            "admin",
            "moderator",
            "user",
            "maintainer"
        ],
        default: "user"
    },
    photo: String,
    password: {
        type: String,
        required: [
            true,
            "Please provide a password"
        ],
        select: false,
        minLength: 8
    },
    passwordConfirm: {
        type: String,
        required: [
            true,
            "Please confirm your password"
        ],
        validate: {
            validator: function(el) {
                return el === this.password;
            },
            message: "Passwords are not the same"
        }
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    isActive: {
        type: Boolean,
        default: true,
        select: false
    }
});
// Hash password before saving new user data to the database
$ca4b57b91abcd647$var$userSchema.pre("save", async function(next) {
    // only run this funtion if the password has beenn modified
    if (!this.isModified("password")) return next();
    this.password = await $bdTtH$bcryptjs.hash(this.password, 12); // hashing the password
    this.passwordConfirm = undefined; // clearing the password confirm field before saving the doc
    next();
});
// Filter none-active/deleted users
$ca4b57b91abcd647$var$userSchema.pre(/^find/, function(next) {
    this.find({
        isActive: {
            $ne: false
        }
    });
    next();
});
$ca4b57b91abcd647$var$userSchema.pre("save", function(next) {
    // If doc is new or the password has been modified
    if (!this.isModified("password") || this.isNew) return next();
    // create time stamp of when the user changed password
    this.passwordChangedAt = Date.now() - 1000; // sometimes token created a bit before the passwordChangedAt actually being created, so i subtract 1 sec.
    next();
});
// Compare input password with user password in DB
$ca4b57b91abcd647$var$userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
    return await $bdTtH$bcryptjs.compare(candidatePassword, userPassword);
};
// Check if user changed his password after the jwt was isssued
$ca4b57b91abcd647$var$userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
    if (this.passwordChangedAt) {
        const formatedTimeStamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimestamp < formatedTimeStamp;
    }
    return false;
};
$ca4b57b91abcd647$var$userSchema.methods.createPasswordResetToken = function() {
    const resetToken = $bdTtH$crypto.randomBytes(32).toString("hex");
    this.passwordResetToken = $bdTtH$crypto.createHash("sha256").update(resetToken).digest("hex");
    this.passwordResetExpires = Date.now() + 600000;
    return resetToken;
};
const $ca4b57b91abcd647$var$User = $bdTtH$mongoose.model("User", $ca4b57b91abcd647$var$userSchema);
$ca4b57b91abcd647$exports = $ca4b57b91abcd647$var$User;


var $9e7a345a81ca5826$exports = {};
$9e7a345a81ca5826$exports = (fn)=>{
    return (req, res, next)=>{
        fn(req, res, next).catch(next);
    };
};



var $18c8568767daaa72$exports = {};

const $18c8568767daaa72$var$sendEmail = async (options)=>{
    // 1) create transporter
    const transporter = $bdTtH$nodemailer.createTransport({
        host: undefined,
        port: undefined,
        auth: {
            user: undefined,
            pass: undefined
        }
    });
    // 2) define email options
    const emailOptions = {
        from: "BlastBid admin <admin@blastbid.com>",
        to: options.email,
        subject: options.subject,
        text: options.message
    };
    // 3) send email
    await transporter.sendMail(emailOptions);
};
$18c8568767daaa72$exports = $18c8568767daaa72$var$sendEmail;



const $ce487c6e3030a219$var$signToken = (id)=>{
    return $bdTtH$jsonwebtoken.sign({
        id: id
    }, undefined, {
        expiresIn: undefined
    });
};
const $ce487c6e3030a219$var$createSendToken = (user, statusCode, res)=>{
    const token = $ce487c6e3030a219$var$signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() + NaN),
        // secure: true, // for secure https
        httpOnly: true
    };
    cookieOptions.secure = true;
    res.cookie("jwt", token, cookieOptions);
    // Remove password from the output
    user.password = undefined;
    res.status(statusCode).json({
        status: "success",
        token: token,
        data: {
            user: user
        }
    });
};
$ce487c6e3030a219$export$88d962a279f8d761;
$ce487c6e3030a219$export$7200a869094fec36 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const newUser = await $ca4b57b91abcd647$exports.create({
        fullName: req.body.fullName,
        email: req.body.email,
        phone: req.body.phone,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });
    $ce487c6e3030a219$var$createSendToken(newUser, 201, res);
});
$ce487c6e3030a219$export$596d806903d1f59e = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const { email: email, password: password } = req.body;
    // 1) Check if email and password actualy exist
    if (!email || !password) return next(new $e203200498571e93$exports("Please provide an email and password", 400));
    // 2) Check if user exists and the password is correct
    const user = await $ca4b57b91abcd647$exports.findOne({
        email: email
    }).select("+password");
    if (!user || !await user.correctPassword(password, user.password)) return next(new $e203200498571e93$exports("Incorrect email or password ", 401));
    // 3) Send the token to the client
    $ce487c6e3030a219$var$createSendToken(user, 200, res);
});
$ce487c6e3030a219$export$eda7ca9e36571553 = $9e7a345a81ca5826$exports(async function(req, res, next) {
    let token;
    // 1) Get the jwt and check if it exist
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) token = req.headers.authorization.split(" ")[1];
    if (!token) return next(new $e203200498571e93$exports("You are not logged in, please log in to get access.", 401));
    // 2) Verify token
    const decoded = await $ce487c6e3030a219$require$promisify($bdTtH$jsonwebtoken.verify)(token, undefined);
    // 3) Check if user that matches the token exists
    const freshUser = await $ca4b57b91abcd647$exports.findById(decoded.id);
    if (!freshUser) return next(new $e203200498571e93$exports("The user belonging to this token does no longer exist, pleasse log in again.", 401));
    // 4) Check if user changed the password after the token was isssued
    if (freshUser.changedPasswordAfter(decoded.iat)) return next(new $e203200498571e93$exports("User changed password recently, please log in again.", 401));
    req.user = freshUser;
    next();
});
$ce487c6e3030a219$export$e1bac762c84d3b0c = (...roles)=>{
    return (req, res, next)=>{
        if (!roles.includes(req.user.role)) return next(new $e203200498571e93$exports("User do not have a premission to access this route.", 403));
        return next();
    };
};
$ce487c6e3030a219$export$66791fb2cfeec3e = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    // 1) Get user by posted email
    const user = await $ca4b57b91abcd647$exports.findOne({
        email: req.body.email
    });
    if (!user) return next(new $e203200498571e93$exports("There is no user with that email address.", 404));
    // 2) Create a random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({
        validateBeforeSave: false
    });
    // 3) Send reset token to users email
    const resetUrl = `${req.protocol}://${req.get("host")}/api/v1/users/resetPassword/${resetToken}`;
    const message = `Forgot ypur password? Submit a PATCH request with your new password and passwordConfirm to: ${resetUrl}. \nif you did not forget your password, please ignore this email.`;
    try {
        await $18c8568767daaa72$exports({
            email: user.email,
            subject: "Your password reset token (valid for 10 minutes)",
            message: message
        });
        return res.status(200).json({
            status: "success",
            message: "Reset token sent to email"
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({
            validateBeforeSave: false
        });
        return next(new $e203200498571e93$exports("There was a problem sending the email, please try again later.", 500));
    }
});
$ce487c6e3030a219$export$dc726c8e334dd814 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    // 1) Get user based on token
    const hashedToken = $bdTtH$crypto.createHash("sha256").update(req.params.token).digest("hex");
    const user = await $ca4b57b91abcd647$exports.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {
            $gt: Date.now()
        }
    });
    // 2) Set new password if token has not expired and user exists
    if (!user) return next(new $e203200498571e93$exports("Token is invalid or has expired.", 400));
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    // 3) Update changedPasswordAt property for the user
    // 4) Log the user in, send jwt
    $ce487c6e3030a219$var$createSendToken(user, 200, res);
});
$ce487c6e3030a219$export$e2853351e15b7895 = async (req, res, next)=>{
    // 1) Get the user
    const user = await $ca4b57b91abcd647$exports.findById(req.user.id).select("+password");
    // 2) Check if posted password is correct
    const { currentPassword: currentPassword, password: password, passwordConfirm: passwordConfirm } = req.body;
    if (!await user.correctPassword(currentPassword, user.password)) return next(new $e203200498571e93$exports("Your current password is wrong, Please try again.", 401));
    // 3) Update the password
    user.password = password;
    user.passwordConfirm = passwordConfirm;
    await user.save();
    // 4) Log the user in
    $ce487c6e3030a219$var$createSendToken(user, 200, res);
};


var $51546a4714e46b53$export$ab7376b1f7e52892;
var $51546a4714e46b53$export$245ece31950dd4b5;
var $51546a4714e46b53$export$241c2dc0377fb445;
var $51546a4714e46b53$export$404106671cab736f;
var $51546a4714e46b53$export$62724aaef6132503;

var $51546a4714e46b53$require$query = $bdTtH$express.query;
var $80c4170c11da2721$exports = {};



const $80c4170c11da2721$var$listingSchema = new $bdTtH$mongoose.Schema({
    title: {
        type: String,
        trim: true,
        required: [
            true,
            "A listing must have a title"
        ]
    },
    slug: {
        type: String
    },
    category: {
        type: String,
        required: [
            true,
            "Listing must have a category"
        ]
    },
    tags: [
        String
    ],
    description: {
        type: String,
        trim: true
    },
    price: {
        type: Number,
        required: [
            true,
            "product must have a price"
        ],
        min: 0
    },
    images: [
        String
    ],
    createdAt: {
        type: Date,
        default: Date.now()
    },
    ratingsAvg: {
        type: Number,
        default: 0,
        min: [
            1,
            "Rating must be above 1"
        ],
        max: [
            10,
            "Rating must be blow 10"
        ],
        set: (val)=>Math.round(val * 10) / 10
    },
    numRatings: {
        type: Number,
        default: 0
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// index the most queried fields
$80c4170c11da2721$var$listingSchema.index({
    price: 1,
    slug: 1
});
// Make a slug for the listing
$80c4170c11da2721$var$listingSchema.pre("save", function(next) {
    this.slug = $bdTtH$slugify(this.title, {
        lower: true
    });
    next();
});
// populate reviews for the current listing
$80c4170c11da2721$var$listingSchema.virtual("reviews", {
    ref: "Review",
    foreignField: "listing",
    localField: "_id"
});
const $80c4170c11da2721$var$Listing = $bdTtH$mongoose.model("Listing", $80c4170c11da2721$var$listingSchema);
$80c4170c11da2721$exports = $80c4170c11da2721$var$Listing;




var $e041bef5c19fcd3c$export$2774c37398bee8b2;
var $e041bef5c19fcd3c$export$36a479340da3c347;
var $e041bef5c19fcd3c$export$2eb5ba9a66e42816;
var $e041bef5c19fcd3c$export$3220ead45e537228;
var $e041bef5c19fcd3c$export$5d49599920443c31;


var $35c12386c6082d4c$exports = {};
class $35c12386c6082d4c$var$APIFeatures {
    constructor(query, queryStr){
        this.query = query;
        this.queryStr = queryStr;
    }
    filter() {
        const queryObj = {
            ...this.queryStr
        };
        const excludedFields = [
            "page",
            "sort",
            "fields",
            "limit"
        ];
        excludedFields.forEach((el)=>delete queryObj[el]);
        // 1b/ advanced filtering
        let queryStr = JSON.stringify(queryObj);
        queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match)=>`$${match}`);
        this.query = this.query.find(JSON.parse(queryStr));
        return this;
    }
    sort() {
        if (this.queryStr.sort) {
            const sortBy = this.queryStr.sort.split(",").join(" ");
            this.query = this.query.sort(sortBy);
        } else this.query = this.query.sort("createdAt");
        return this;
    }
    limit() {
        if (this.queryStr.fields) {
            const fields = this.queryStr.fields.split(",").join(" ");
            console.log(fields);
            this.query = this.query.select(fields);
        } else this.query = this.query.select("-__v");
        return this;
    }
    paginate() {
        const page = this.queryStr.page * 1 || 1;
        const limit = this.queryStr.limit * 1;
        const skip = (page - 1) * limit;
        this.query = this.query.skip(skip).limit(limit);
        return this;
    }
}
$35c12386c6082d4c$exports = $35c12386c6082d4c$var$APIFeatures;



var $e041bef5c19fcd3c$require$query = $bdTtH$express.query;
$e041bef5c19fcd3c$export$2774c37398bee8b2 = (Model)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        const doc = await Model.find().select("-__v");
        return res.status(200).json({
            status: "success",
            results: doc.length,
            data: {
                data: doc
            }
        });
    });
$e041bef5c19fcd3c$export$36a479340da3c347 = (Model)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        const doc = await Model.findByIdAndDelete(req.params.id);
        if (!doc) return next(new $e203200498571e93$exports("No document found with that Id", 404));
        res.status(204).json({
            status: null
        });
    });
$e041bef5c19fcd3c$export$2eb5ba9a66e42816 = (Model, populateOpt)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        let query = Model.findById(req.params.id);
        if (populateOpt) query = query.populate(populateOpt);
        const doc = await query;
        if (!doc) return next(new $e203200498571e93$exports("No document found with that Id", 404));
        res.status(200).json({
            status: "success",
            data: {
                data: doc
            }
        });
    });
$e041bef5c19fcd3c$export$2774c37398bee8b2 = (Model)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        // Allow nested GET reviews on listing
        let filter = {};
        if (req.params.listingId) filter = {
            listing: req.params.listingId
        };
        // BUID QUERY
        const features = new $35c12386c6082d4c$exports(Model.find(filter), req.query).filter().sort().limit().paginate();
        // EXECUTE QUERY
        const docs = await features.query;
        // RESPONSE
        res.status(200).json({
            status: "success",
            results: docs.length,
            data: {
                docs: docs
            }
        });
    });
$e041bef5c19fcd3c$export$3220ead45e537228 = (Model)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true
        });
        if (!doc) return next(new $e203200498571e93$exports("No document found with that Id", 404));
        res.status(200).json({
            status: "success",
            data: {
                data: doc
            }
        });
    });
$e041bef5c19fcd3c$export$5d49599920443c31 = (Model)=>$9e7a345a81ca5826$exports(async (req, res, next)=>{
        const doc = await Model.create(req.body);
        res.status(201).json({
            status: "success",
            data: {
                doc: doc
            }
        });
    });


$51546a4714e46b53$export$ab7376b1f7e52892 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const listing = await $80c4170c11da2721$exports.findById(req.params.id).populate("reviews");
    if (!listing) return next(new $e203200498571e93$exports("No listing found with that id."));
    res.status(200).json({
        status: "success",
        data: {
            listing: listing
        }
    });
});
$51546a4714e46b53$export$245ece31950dd4b5 = $e041bef5c19fcd3c$export$2774c37398bee8b2($80c4170c11da2721$exports);
$51546a4714e46b53$export$ab7376b1f7e52892 = $e041bef5c19fcd3c$export$2eb5ba9a66e42816($80c4170c11da2721$exports, {
    path: "reviews"
});
$51546a4714e46b53$export$241c2dc0377fb445 = $e041bef5c19fcd3c$export$5d49599920443c31($80c4170c11da2721$exports);
$51546a4714e46b53$export$404106671cab736f = $e041bef5c19fcd3c$export$3220ead45e537228($80c4170c11da2721$exports);
$51546a4714e46b53$export$62724aaef6132503 = $e041bef5c19fcd3c$export$36a479340da3c347($80c4170c11da2721$exports);


var $f30d307740cea5b6$exports = {};


var $e8a2407fbeb25c48$export$67cfcabed6353920;
// exports.createReview = catchAsync(async (req, res, next) => {
//   const purchases = await Invoice.find({
//     user: userId,
//     status: 'approved',
//   })?.populate({
//     path: 'listings',
//     select: 'id',
//   });
//   return res.status(401).json({
//     status: 'fail',
//     message:
//       'Unauthorized, you must purchase the product before leaving a review.',
//   });
// });
var $e8a2407fbeb25c48$export$e42a3d813dd6123f;
var $e8a2407fbeb25c48$export$98596c466f7b9045;
var $e8a2407fbeb25c48$export$c3d3086f9027c35a;
var $e8a2407fbeb25c48$export$7019c694ef9e681d;
var $e8a2407fbeb25c48$export$189a68d831f3e4ec;
var $2d4738cec793e542$exports = {};


const $2d4738cec793e542$var$reviewSchema = new $bdTtH$mongoose.Schema({
    title: {
        type: String,
        required: [
            true,
            "Areview must have a title."
        ],
        trim: true,
        maxLength: 100
    },
    content: {
        type: String,
        required: [
            true,
            "A review must have a review content."
        ]
    },
    rating: {
        type: Number,
        required: [
            true,
            "A review must have rating."
        ],
        min: 1,
        max: 10,
        default: 0
    },
    createdAt: {
        type: String,
        default: Date.now
    },
    listing: {
        type: $bdTtH$mongoose.Schema.ObjectId,
        ref: "Listing",
        required: [
            true,
            "Review must belog to listing"
        ]
    },
    user: {
        type: $bdTtH$mongoose.Schema.ObjectId,
        ref: "User",
        required: [
            true,
            "Review must belong to user."
        ]
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// restrict only ovly one review to a listing
$2d4738cec793e542$var$reviewSchema.index({
    listing: 1,
    user: 1
}, {
    unique: true
});
$2d4738cec793e542$var$reviewSchema.pre(/^find/, function(next) {
    this.populate({
        path: "user",
        select: "fullName photo"
    });
    next();
});
// Calculate averages functionality
$2d4738cec793e542$var$reviewSchema.statics.calcAvgRatings = async function(listingId) {
    const stats = await this.aggregate([
        {
            $match: {
                listing: listingId
            }
        },
        {
            $group: {
                _id: "$listing",
                numRatings: {
                    $sum: 1
                },
                avgRating: {
                    $avg: "$rating"
                }
            }
        }
    ]);
    if (stats.length > 0) await $80c4170c11da2721$exports.findByIdAndUpdate(listingId, {
        ratingsAvg: stats[0].avgRating,
        numRatings: stats[0].numRatings
    });
    else await $80c4170c11da2721$exports.findByIdAndUpdate(listingId, {
        ratingsAvg: 0,
        numRatings: 0
    });
};
// Persist the rating stats after creating the review
$2d4738cec793e542$var$reviewSchema.post("save", function() {
    this.constructor.calcAvgRatings(this.listing);
});
// Calculate the ratings after editing or deleting a review
$2d4738cec793e542$var$reviewSchema.post(/^findOneAnd/, async function(doc) {
    await doc.constructor.calcAvgRatings(doc.listing);
});
const $2d4738cec793e542$var$Review = $bdTtH$mongoose.model("Review", $2d4738cec793e542$var$reviewSchema);
$2d4738cec793e542$exports = $2d4738cec793e542$var$Review;


var $bd63069e48d1b549$exports = {};

const $bd63069e48d1b549$var$invoiceSchema = new $bdTtH$mongoose.Schema({
    user: {
        type: $bdTtH$mongoose.Schema.ObjectId,
        ref: "User",
        required: [
            true,
            "Invoice must belong to a user."
        ]
    },
    listings: {
        type: [
            $bdTtH$mongoose.Schema.ObjectId
        ],
        ref: "Listing",
        required: [
            true,
            "Invoice must have at least one listing."
        ]
    },
    totalPrice: {
        type: Number,
        default: 0,
        min: [
            0,
            "price can not be less than 0."
        ]
    },
    discount: {
        type: Number,
        min: [
            0,
            "Discount can not be less than 0."
        ],
        max: [
            1,
            "Discount can not be above 1."
        ],
        default: 0
    },
    currency: {
        type: String,
        enum: [
            "USD",
            "EUR",
            "ILS"
        ],
        default: "USD"
    },
    isPaid: {
        type: Boolean,
        default: false
    },
    status: {
        type: String,
        enum: [
            "pending",
            "canceled",
            "rejected",
            "approved"
        ],
        default: "pending"
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// Calculate total price
$bd63069e48d1b549$var$invoiceSchema.post("save", async function(doc) {
    await doc.populate({
        path: "listings",
        select: "price title"
    }).execPopulate();
    const totalListingsPrice = doc.listings.reduce((total, listing)=>total + listing.price, 0);
    doc.totalPrice = (totalListingsPrice - totalListingsPrice * doc.discount).toFixed(2);
    await $bd63069e48d1b549$var$Invoice.updateOne({
        _id: doc._id
    }, {
        totalPrice: doc.totalPrice
    });
});
const $bd63069e48d1b549$var$Invoice = $bdTtH$mongoose.model("Invoice", $bd63069e48d1b549$var$invoiceSchema);
$bd63069e48d1b549$exports = $bd63069e48d1b549$var$Invoice;




$e8a2407fbeb25c48$export$67cfcabed6353920 = (req, res, next)=>{
    //Aloow nested routes
    req.body.listing = req.params.listingId;
    req.body.user = req.user.id;
    next();
};
$e8a2407fbeb25c48$export$e42a3d813dd6123f = $e041bef5c19fcd3c$export$5d49599920443c31($2d4738cec793e542$exports);
$e8a2407fbeb25c48$export$98596c466f7b9045 = $e041bef5c19fcd3c$export$2774c37398bee8b2($2d4738cec793e542$exports);
$e8a2407fbeb25c48$export$c3d3086f9027c35a = $e041bef5c19fcd3c$export$2eb5ba9a66e42816($2d4738cec793e542$exports);
$e8a2407fbeb25c48$export$7019c694ef9e681d = $e041bef5c19fcd3c$export$3220ead45e537228($2d4738cec793e542$exports);
$e8a2407fbeb25c48$export$189a68d831f3e4ec = $e041bef5c19fcd3c$export$36a479340da3c347($2d4738cec793e542$exports);


const $f30d307740cea5b6$var$router = $bdTtH$express.Router({
    mergeParams: true
});
$f30d307740cea5b6$var$router.use($ce487c6e3030a219$export$eda7ca9e36571553);
$f30d307740cea5b6$var$router.route("/").get($e8a2407fbeb25c48$export$98596c466f7b9045);
$f30d307740cea5b6$var$router.route("/:id").post($ce487c6e3030a219$export$e1bac762c84d3b0c("user"), $e8a2407fbeb25c48$export$67cfcabed6353920, $e8a2407fbeb25c48$export$e42a3d813dd6123f).get($e8a2407fbeb25c48$export$c3d3086f9027c35a).patch($ce487c6e3030a219$export$e1bac762c84d3b0c("user"), $e8a2407fbeb25c48$export$7019c694ef9e681d).delete($ce487c6e3030a219$export$e1bac762c84d3b0c("moderator", "admin", "user"), $e8a2407fbeb25c48$export$189a68d831f3e4ec);
$f30d307740cea5b6$exports = $f30d307740cea5b6$var$router;


const $73d7888de7213739$var$router = $bdTtH$express.Router();
$73d7888de7213739$var$router.route("/").get($51546a4714e46b53$export$245ece31950dd4b5).post($ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("maintainer", "admin"), $51546a4714e46b53$export$241c2dc0377fb445);
$73d7888de7213739$var$router.route("/:id").get($51546a4714e46b53$export$ab7376b1f7e52892).patch($ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("maintainer", "admin"), $51546a4714e46b53$export$404106671cab736f).delete($ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("maintainer", "admin"), $51546a4714e46b53$export$62724aaef6132503);
$73d7888de7213739$var$router.use("/:listingId/reviews", $f30d307740cea5b6$exports);
$73d7888de7213739$exports = $73d7888de7213739$var$router;


var $d176c6f5e4f47181$exports = {};

var $9d2c5b801713c0c3$export$8ddaddf355aae59c;
// Deactivate user
var $9d2c5b801713c0c3$export$8788023029506852;
// Create users (Admin access only)
var $9d2c5b801713c0c3$export$3493b8991d49f558;
var $9d2c5b801713c0c3$export$dd7946daa6163e94;
var $9d2c5b801713c0c3$export$a52a3451f1550587;
var $9d2c5b801713c0c3$export$7cbf767827cd68ba;
var $9d2c5b801713c0c3$export$69093b9c569a5b5b;
var $9d2c5b801713c0c3$export$e3ac7a5d19605772;
var $9d2c5b801713c0c3$export$7d0f10f273c0438a;





const $9d2c5b801713c0c3$var$filterObj = function(bodyObj, allowedFieldsArr) {
    const newBodyObj = {};
    Object.keys(bodyObj).forEach((el)=>{
        if (allowedFieldsArr.includes(el)) newBodyObj[el] = bodyObj[el];
    });
    return newBodyObj;
};
$9d2c5b801713c0c3$export$8ddaddf355aae59c = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    // 1) Create an error if user posts password data
    if (req.body.password || req.body.passwordConfirm) return next(new $e203200498571e93$exports("This route is not for password update, please use /updateMyPassword.", 400));
    // 2) Filter out unwanted fields
    const filteredBody = $9d2c5b801713c0c3$var$filterObj(req.body, [
        "fullName",
        "email",
        "phone",
        "location"
    ]);
    // 3) Update user doc
    const updatedUser = await $ca4b57b91abcd647$exports.findByIdAndUpdate(req.user.id, filteredBody, {
        new: true,
        runValidators: true
    });
    res.status(200).json({
        status: "success",
        user: updatedUser
    });
});
$9d2c5b801713c0c3$export$8788023029506852 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const user = await $ca4b57b91abcd647$exports.findByIdAndUpdate(req.user.id, {
        isActive: false
    });
    res.status(204).json({
        status: "success"
    });
});
$9d2c5b801713c0c3$export$3493b8991d49f558 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const newUser = await $ca4b57b91abcd647$exports.create(req.body);
    if (!newUser) next(new $e203200498571e93$exports("Couldn't create user, please try again later.", 500));
    res.status(201).json({
        status: "success",
        data: {
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email,
                phone: newUser.phone,
                role: newUser.role
            }
        }
    });
});
$9d2c5b801713c0c3$export$dd7946daa6163e94 = (req, res, next)=>{
    req.params.id = req.user.id;
    next();
};
$9d2c5b801713c0c3$export$a52a3451f1550587 = $9e7a345a81ca5826$exports(async (req, res)=>{
    const userId = req.user._id;
    const purchases = await $bd63069e48d1b549$exports.find({
        user: userId,
        status: "approved"
    })?.populate({
        path: "listings",
        select: "price title images"
    });
    if (!purchases) return res.status(200).json({
        status: "success",
        message: "No purchases found."
    });
    return res.status(200).json({
        status: "success",
        data: {
            userId: userId,
            purchases: purchases
        }
    });
});
$9d2c5b801713c0c3$export$7cbf767827cd68ba = $e041bef5c19fcd3c$export$2eb5ba9a66e42816($ca4b57b91abcd647$exports);
$9d2c5b801713c0c3$export$69093b9c569a5b5b = $e041bef5c19fcd3c$export$2774c37398bee8b2($ca4b57b91abcd647$exports);
$9d2c5b801713c0c3$export$e3ac7a5d19605772 = $e041bef5c19fcd3c$export$3220ead45e537228($ca4b57b91abcd647$exports); // not for updating password.
$9d2c5b801713c0c3$export$7d0f10f273c0438a = $e041bef5c19fcd3c$export$36a479340da3c347($ca4b57b91abcd647$exports); // admin only or the user himself



const $d176c6f5e4f47181$var$router = $bdTtH$express.Router();
$d176c6f5e4f47181$var$router.post("/signup", $ce487c6e3030a219$export$7200a869094fec36);
$d176c6f5e4f47181$var$router.post("/login", $ce487c6e3030a219$export$596d806903d1f59e);
$d176c6f5e4f47181$var$router.post("/forgotPassword", $ce487c6e3030a219$export$66791fb2cfeec3e);
$d176c6f5e4f47181$var$router.post("/createUser", $ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("admin"), $9d2c5b801713c0c3$export$3493b8991d49f558);
$d176c6f5e4f47181$var$router.patch("/resetPassword/:token", $ce487c6e3030a219$export$dc726c8e334dd814);
$d176c6f5e4f47181$var$router.use($ce487c6e3030a219$export$eda7ca9e36571553);
$d176c6f5e4f47181$var$router.get("/me", $9d2c5b801713c0c3$export$dd7946daa6163e94, $9d2c5b801713c0c3$export$7cbf767827cd68ba);
$d176c6f5e4f47181$var$router.get("/purchaseHistory", $9d2c5b801713c0c3$export$a52a3451f1550587);
$d176c6f5e4f47181$var$router.patch("/updateMe", $9d2c5b801713c0c3$export$8ddaddf355aae59c);
$d176c6f5e4f47181$var$router.patch("/updateMyPassword", $ce487c6e3030a219$export$e2853351e15b7895);
$d176c6f5e4f47181$var$router.delete("/deleteMe", $9d2c5b801713c0c3$export$8788023029506852); // Deactivates the user
$d176c6f5e4f47181$var$router.route("/").get($9d2c5b801713c0c3$export$69093b9c569a5b5b);
$d176c6f5e4f47181$var$router.route("/:id").get($9d2c5b801713c0c3$export$7cbf767827cd68ba).patch($ce487c6e3030a219$export$e1bac762c84d3b0c("user"), $9d2c5b801713c0c3$export$e3ac7a5d19605772).delete($ce487c6e3030a219$export$e1bac762c84d3b0c("admin"), $9d2c5b801713c0c3$export$7d0f10f273c0438a);
$d176c6f5e4f47181$exports = $d176c6f5e4f47181$var$router;



var $c816f48a2d62e53c$exports = {};

var $065b738f380bbb39$export$360f4895d5ceb7fc;
var $065b738f380bbb39$export$4b747aa0b0d055dc;
var $065b738f380bbb39$export$7f91e787f240fc92;
var $065b738f380bbb39$export$7bf985859bf149af;




$065b738f380bbb39$export$360f4895d5ceb7fc = (req, res, next)=>{
    req.body.user = req.user.id;
    next();
};
$065b738f380bbb39$export$4b747aa0b0d055dc = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const invoice = await $bd63069e48d1b549$exports.create(req.body);
    if (!invoice) return next(new $e203200498571e93$exports("Couldnt create an invoice, please try again later.", 500));
    res.status(201).json({
        status: "success",
        data: {
            invoice: invoice
        }
    });
});
$065b738f380bbb39$export$7f91e787f240fc92 = $e041bef5c19fcd3c$export$2eb5ba9a66e42816($bd63069e48d1b549$exports);
$065b738f380bbb39$export$7bf985859bf149af = $e041bef5c19fcd3c$export$36a479340da3c347($bd63069e48d1b549$exports);



var $4fe263ebe2e6686d$export$2de1c5c9ead290a3;
var $4fe263ebe2e6686d$export$c61505d529d9f25;

var $4fe263ebe2e6686d$require$Buffer = $bdTtH$buffer.Buffer;





$bdTtH$dotenv.config({
    path: "./config.env"
});
const $4fe263ebe2e6686d$var$PAYPAL_CLIENT_ID, $4fe263ebe2e6686d$var$PAYPAL_CLIENT_SECRET;
const $4fe263ebe2e6686d$var$base = "https://api-m.sandbox.paypal.com";
const $4fe263ebe2e6686d$var$generateAccessToken = async ()=>{
    try {
        if (!$4fe263ebe2e6686d$var$PAYPAL_CLIENT_ID || !$4fe263ebe2e6686d$var$PAYPAL_CLIENT_SECRET) throw new Error("MISSING_API_CREDENTIALS");
        const auth = $4fe263ebe2e6686d$require$Buffer.from($4fe263ebe2e6686d$var$PAYPAL_CLIENT_ID + ":" + $4fe263ebe2e6686d$var$PAYPAL_CLIENT_SECRET).toString("base64");
        const response = await fetch(`${$4fe263ebe2e6686d$var$base}/v1/oauth2/token`, {
            method: "POST",
            body: "grant_type=client_credentials",
            headers: {
                Authorization: `Basic ${auth}`
            }
        });
        const data = await response.json();
        return data.access_token;
    } catch (error) {
        console.error("Failed to generate Access Token:", error);
    }
};
const $4fe263ebe2e6686d$var$createOrder = async (cart)=>{
    const accessToken = await $4fe263ebe2e6686d$var$generateAccessToken();
    const url = `${$4fe263ebe2e6686d$var$base}/v2/checkout/orders`;
    const payload = {
        intent: "CAPTURE",
        purchase_units: [
            {
                amount: {
                    currency_code: cart.currency,
                    value: cart.totalPrice
                }
            }
        ]
    };
    const response = await fetch(url, {
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`
        },
        method: "POST",
        body: JSON.stringify(payload)
    });
    return $4fe263ebe2e6686d$var$handleResponse(response);
};
const $4fe263ebe2e6686d$var$captureOrder = async (orderID)=>{
    const accessToken = await $4fe263ebe2e6686d$var$generateAccessToken();
    const url = `${$4fe263ebe2e6686d$var$base}/v2/checkout/orders/${orderID}/capture`;
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`
        }
    });
    return $4fe263ebe2e6686d$var$handleResponse(response);
};
async function $4fe263ebe2e6686d$var$handleResponse(response) {
    try {
        const jsonResponse = await response.json();
        return {
            jsonResponse: jsonResponse,
            httpStatusCode: response.status
        };
    } catch (err) {
        const errorMessage = await response.text();
        throw new Error(errorMessage);
    }
}
$4fe263ebe2e6686d$export$2de1c5c9ead290a3 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const cart = await $bd63069e48d1b549$exports.findById(req.params.id);
    const { jsonResponse: jsonResponse, httpStatusCode: httpStatusCode } = await $4fe263ebe2e6686d$var$createOrder(cart);
    if (!httpStatusCode || !jsonResponse) return next(new $e203200498571e93$exports("Failed to create order.", 500));
    return res.status(httpStatusCode).json(jsonResponse);
});
$4fe263ebe2e6686d$export$c61505d529d9f25 = $9e7a345a81ca5826$exports(async (req, res, next)=>{
    const { orderID: orderID, id: invoiceID } = req.params;
    const { jsonResponse: jsonResponse, httpStatusCode: httpStatusCode } = await $4fe263ebe2e6686d$var$captureOrder(orderID);
    // console.log(req.user.id);
    if (!jsonResponse || !httpStatusCode) return next(new $e203200498571e93$exports("Failed to capture order.", 500));
    if (jsonResponse?.status === "COMPLETED") await $bd63069e48d1b549$exports.updateOne({
        _id: invoiceID
    }, {
        status: "approved",
        isPaid: true
    });
    if (jsonResponse?.name === "UNPROCESSABLE_ENTITY") await $bd63069e48d1b549$exports.updateOne({
        _id: invoiceID
    }, {
        status: "canceled",
        isPaid: false
    });
    return res.status(httpStatusCode).json(jsonResponse);
});


const $c816f48a2d62e53c$var$router = $bdTtH$express.Router();
$c816f48a2d62e53c$var$router.route("/").get($ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("admin", "user"), $065b738f380bbb39$export$7f91e787f240fc92).post($ce487c6e3030a219$export$eda7ca9e36571553, $065b738f380bbb39$export$360f4895d5ceb7fc, $065b738f380bbb39$export$4b747aa0b0d055dc);
$c816f48a2d62e53c$var$router.route("/:id").delete($ce487c6e3030a219$export$eda7ca9e36571553, $ce487c6e3030a219$export$e1bac762c84d3b0c("admin"), $065b738f380bbb39$export$7bf985859bf149af);
$c816f48a2d62e53c$var$router.route("/:id/orders").post($ce487c6e3030a219$export$eda7ca9e36571553, $4fe263ebe2e6686d$export$2de1c5c9ead290a3);
$c816f48a2d62e53c$var$router.route("/:id/orders/:orderID/capture").post($ce487c6e3030a219$export$eda7ca9e36571553, $4fe263ebe2e6686d$export$c61505d529d9f25);
$c816f48a2d62e53c$exports = $c816f48a2d62e53c$var$router;


const $84a264530b3fb4fb$var$app = $bdTtH$express();
$84a264530b3fb4fb$var$app.use($bdTtH$cors());
// Set security http headers
$84a264530b3fb4fb$var$app.use($bdTtH$helmet());
// Limit too many requests from the same API
const $84a264530b3fb4fb$var$limiter = $bdTtH$expressratelimit({
    max: 200,
    windowMs: 3600000,
    message: "To many requests from this IP, please try again in an hour."
});
$84a264530b3fb4fb$var$app.use("/api", $84a264530b3fb4fb$var$limiter);
// Body parser - get the body from the request
$84a264530b3fb4fb$var$app.use($bdTtH$express.json({
    limit: "10kb"
}));
// Data sanitization against noSQL query injection
$84a264530b3fb4fb$var$app.use($bdTtH$expressmongosanitize());
// Data sanitization against cross side scripting atacks - XSS
$84a264530b3fb4fb$var$app.use($bdTtH$xssclean());
// Prevent parameter pollution - using only the last duplicate parameter
$84a264530b3fb4fb$var$app.use($bdTtH$hpp());
$84a264530b3fb4fb$var$app.use("/api/v1/listings", $73d7888de7213739$exports);
$84a264530b3fb4fb$var$app.use("/api/v1/users", $d176c6f5e4f47181$exports);
$84a264530b3fb4fb$var$app.use("/api/v1/reviews", $f30d307740cea5b6$exports);
$84a264530b3fb4fb$var$app.use("/api/v1/invoices", $c816f48a2d62e53c$exports);
$84a264530b3fb4fb$var$app.all("*", (req, res, next)=>{
    next(new $e203200498571e93$exports(`Can't find ${req.originalUrl} on this server!`, 404));
});
$84a264530b3fb4fb$var$app.use($6e01d007996f5575$exports);
$84a264530b3fb4fb$exports = $84a264530b3fb4fb$var$app;


const $2685e5b20c9f29f6$var$DB = undefined.replace("<PASSWORD>", undefined);
// Make a connection to mongoDB
$bdTtH$mongoose.connect($2685e5b20c9f29f6$var$DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true
}).then((con)=>console.log("Successfully connected to database"));
// Define port
const $2685e5b20c9f29f6$var$port = 3000;
// Run server
const $2685e5b20c9f29f6$var$server = $84a264530b3fb4fb$exports.listen($2685e5b20c9f29f6$var$port, ()=>console.log(`App is listening on port ${$2685e5b20c9f29f6$var$port}...`));
// Catch any unhandled promise rejection from the whole app
$bdTtH$process.on("unhandledRejection", (err)=>{
    console.log("UNHANDLED REJECTION! \uD83D\uDCA5 Shutting down...");
    console.log(err.name, err.message, err);
    // gracefull shutdown
    $2685e5b20c9f29f6$var$server.close(()=>{
        $bdTtH$process.exit(1);
    });
});


//# sourceMappingURL=index.js.map
