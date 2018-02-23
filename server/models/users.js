const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//Define Model
const userSchema = new Schema({
    email: { type: String , unique : true , lowercase : true },
    password:String 

}); 

// On save hook , encrypt password

// Before saving a model , run this function
userSchema.pre('save' , function(next){
    //get access to the user model it is an instance
    const user = this;

    // generate a salt then run callback 
    bcrypt.genSalt( 10 , function(err , salt){
        if(err) { return next(err); }

        // hash our password using salt
        bcrypt.hash( user.password , salt , null , function(err , hash){
            if(err) {  return next(err); }

            //overwrite plain text password with encrypted password
            user.password = hash;
            // Go ahead and save the model
            next();
        })
    })
})

userSchema.methods.comparePassword = function ( candidatePassword , callback){
    bcrypt.compare(candidatePassword , this.password ,function(err , isMatch){
        if(err) { return callback(err);}

        callback(null , isMatch);
    })
}

//create a model class

const modelClass = mongoose.model('user' , userSchema);


//export model
module.exports = modelClass;