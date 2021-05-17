const express = require("./index");
const {check} = require('express-validator');

module.exports = {
    
  validateConfirmPassword : check('confirmpassword')
  
    // To delete leading and triling space
    .trim()
  
    // Validate minimum length of password
    // Optional for this context
    .isLength({min:4, max:16})
  
    // Custom message
    .withMessage('Password must be between 4 to 16 characters')
  
    // Custom validation
    // Validate confirmPassword
    .custom(async (confirmpassword, {req, res}) => {
      const password = req.body.password
  
      // If password and confirm password not same
      // don't allow to sign up and throw error
      if(password !== confirmpassword){
        return res.send("password does not match");
      }
    }),
}