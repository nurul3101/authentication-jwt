const passport = require('passport');
const User = require('../models/users');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//Create local strategy Here instead of username we are using email // To verify email and passwd
const localLogin = new LocalStrategy( { usernameField : 'email'} , function(email , password , done){
    //Verify this username and pssowrd call done with user otherwise call donw with false
    User.findOne({ email : email} , function( err , user){
        if(err) { return done(err); }

        if(!user) { return done(null , false); }

        //compae paswords
        user.comparePassword( password , function(err , isMatch){
            if(err) { return done(err); }

            if(!isMatch) { return done(null , false);}

            return done(null , user);
        })

    })
})


//Setup options for jwt Strategy. Payload will have jwt but how does passport know where to look so we definr jwtOptions
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey : config.secret
}

//create jwt startegy // To check if jwt token is correct or not
//payload is decode jwt token here payload will have sub and iat
const jwtLogin = new JwtStrategy(jwtOptions , function( payload , done){
    //See if the user ID inthe payload exists in db. If it does call done else call done without user obj

    User.findById(payload.sub , function(err , user){
        if(err) { return done(err , false); }

        if(user){
            done(null ,user);
        }else{
            done(null , false); //Searched but cant find user..No error
        }
    })
})


//tell paspport to use this trategy
passport.use(jwtLogin);
passport.use(localLogin);   