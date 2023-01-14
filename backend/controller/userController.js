const ErrorHander = require("../utils/errorHandler");
const catchAsyncErrors=require("../middleware/catchAsyncErrors");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");
const sendEmail = require("../utils/sendEmail.js");
const crypto = require("crypto");

exports.registerUser=catchAsyncErrors(async(req,res,next)=>{
    const {name,email,password} = req.body;
    const user=await User.create({
        name,email,password,
        avatar:{
            public_id:"sample",
            url:"profile"
        }
    })
    sendToken(user,201,res);


})


exports.loginUser = catchAsyncErrors(async (req, res, next) => {
    const { email, password } = req.body;
  
    // checking if user has given password and email both
  
    if (!email || !password) {
      return next(new ErrorHander("Please Enter Email & Password", 400));
    }
  
    const user = await User.findOne({ email }).select("+password");
  
    if (!user) {
      return next(new ErrorHander("Invalid email or password", 401));
    }
  
    const isPasswordMatched = await user.comparePassword(password);
  
    if (!isPasswordMatched) {
      return next(new ErrorHander("Invalid email or password", 401));
    }
    const token = user.getJWTToken();
  
    sendToken(user,200,res);
    
  });

  exports.logout = catchAsyncErrors(async(req,res,next)=>{

    res.cookie("token",null,{
        expires:new Date(Date.now()),
        httpOnly:true,
    })
    res.status(200).json({
        success:true,
        message:"Logged Out",

    })
  })

  exports.forgotPassword = catchAsyncErrors(async(req,res,next)=>{
    const user = await User.findOne({email:req.body.email});
    if(!user){
      return next(new ErrorHander("user not found"),404);
    }

    const resetToken=user.getResetPasswordToken();
    await user.save({validateBeforeSave:false});

    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/v1/password/reset/${resetToken}`;
    const message =  `Your Password reset token is :- \n\n ${resetPasswordUrl} \n\n If u have not requested please ignore `;


    try{

      await sendEmail({
          email:user.email,
          subject:`Ecommerce Password Recovery`,
          message,
      });

      res.status(200).json({
        success:true,
        message:`Email sent to ${user.email} successfully`,
      })

    }
    catch(error){
        user.resetPasswordToken=undefined;
        user.resetPasswordExpire=undefined;

        await user.save({validateBeforeSave:false});

        return next(new ErrorHander(error.message,500));
    
    }

  })


  exports.resetPassword = catchAsyncErrors(async(req,res,next)=>{
    const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire : {$gt:Date.now()},

    })

    if(!user){
      return next(new ErrorHander("Reset Pass Word token expired",400));
    }

    if(req.body.password!=req.body.confirmPassword){
      return next(new ErrorHander("Password does not match",400));
    }

    user.password=req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    sendToken(user,200,res);

  })