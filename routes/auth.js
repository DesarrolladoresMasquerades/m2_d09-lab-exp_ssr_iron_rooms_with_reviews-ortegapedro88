const router = require("express").Router();

// ℹ️ Handles password encryption
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");

// How many rounds should bcrypt run the salt (default [10 - 12 rounds])
const saltRounds = 10;

// Require the User model in order to interact with the database
const User = require("../models/User.model");
const Room = require("../models/Room.model");

// Require necessary (isLoggedOut and isLiggedIn) middleware in order to control access to specific routes
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");
const { findById } = require("../models/User.model");



router
.route("/rooms/my-rooms/delete/:id", isLoggedIn, )
.get((req, res) => {
  const userId = req.session.user
  Room.findById(req.params.id)
  .then((room)=>{
    
    if(userId == room.owner){    
      Room.findByIdAndRemove(req.params.id)
      .then(()=>{   
          res.redirect("/auth/rooms/my-rooms")
      })
      }
    else {res.redirect("/auth/login")}})
 

})

router.route("/rooms/new-review/:id", )
.get((req,res)=>{
  roomId = req.params.id
  userId = req.session.user
  Room.findById(roomId)
    .then((room)=>{
      
      if(userId != room.owner){
    
          res.render("../views/review/create-review", room);
        }
      else {res.redirect("/auth/login")}})
})
.post((req, res)=>{
  
})


router
.route("/rooms/my-rooms/:id", isLoggedIn, )
.get((req, res) => {
  const userId = req.session.user
  
    
    Room.findById(req.params.id)
    .then((room)=>{
      
      if(userId == room.owner){
    
          res.render("../views/room/edit-room", room);
        }
      else {res.redirect("/auth/login")}})
   

  })
  .post((req, res)=>{
    const name = req.body.name
    const description = req.body.description
    const imageUrl = req.body.imageUrl
    Room.findByIdAndUpdate(req.params.id,{name, description, imageUrl},{new: true})
    .then(()=>{
      res.redirect("/auth/rooms/my-rooms")
    })
  })

  
  


router.get("/rooms/my-rooms", isLoggedIn, (req,res)=>{
  User.findById(req.session.user)
  .populate({path: "rooms",
model: "Room"})
  .then((user)=>{
    const roomsArr = user.rooms
   // console.log("///////// MY ROOMS ARRAY::", roomsArr)
    res.render("../views/room/my-rooms", {roomsArr} )
  })
})



router
  .route("/profile/create", isLoggedIn)
  .get((req, res) => {
    res.render("../views/room/create");
  })
  .post((req, res) => {
    const { name, description, imageUrl } = req.body;

    Room.findOne({ name })
      .then((found) => {
        if (found) {
          return res
            .status(400)
            .render("../views/room/create", {
              errorMessage: "Name already taken.",
            });
        }
      })
      .then(() => {
        const owner = req.session.user;
        Room.create({
          name,
          description,
          imageUrl,
          owner,
        }).then((newRoom) => {
          User.findByIdAndUpdate(
            req.session.user,
            {
              $push: { rooms: newRoom._id },
            },
            { new: true }
          ).then(() => {
            res.redirect("/");
          });
        });

        //console.log("new movie:",newMovie,"celebriti: ", cast)
      });
  });

router.get("/signup", isLoggedOut, (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", isLoggedOut, (req, res) => {
  const { email, password, name } = req.body;
  const fullName = name;

  if (!email) {
    return res
      .status(400)
      .render("auth/signup", { errorMessage: "Please provide your email." });
  }

  if (password.length < 3) {
    return res.status(400).render("auth/signup", {
      errorMessage: "Your password needs to be at least 8 characters long.",
    });
  }

  //   ! This use case is using a regular expression to control for special characters and min length
  /*
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;

  if (!regex.test(password)) {
    return res.status(400).render("signup", {
      errorMessage:
        "Password needs to have at least 8 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
  }
  */

  // Search the database for a user with the email submitted in the form
  User.findOne({ email }).then((found) => {
    // If the user is found, send the message email is taken
    if (found) {
      return res
        .status(400)
        .render("auth/signup", { errorMessage: "email already taken." });
    }

    // if user is not found, create a new user - start with hashing the password
    return bcrypt
      .genSalt(saltRounds)
      .then((salt) => bcrypt.hash(password, salt))
      .then((hashedPassword) => {
        // Create a user and save it in the database
        return User.create({
          email,
          password: hashedPassword,
          fullName,
        });
      })
      .then((user) => {
        // Bind the user to the session object
        req.session.user = user._id;
        res.redirect("/auth/login");
      })
      .catch((error) => {
        if (error instanceof mongoose.Error.ValidationError) {
          return res
            .status(400)
            .render("auth/signup", { errorMessage: error.message });
        }
        if (error.code === 11000) {
          return res.status(400).render("auth/signup", {
            errorMessage:
              "email need to be unique. The email you chose is already in use.",
          });
        }
        return res
          .status(500)
          .render("auth/signup", { errorMessage: error.message });
      });
  });
});

router.get("/login", isLoggedOut, (req, res) => {
  res.render("auth/login");
});

router.post("/login", isLoggedOut, (req, res, next) => {
  const { email, password } = req.body;

  if (!email) {
    return res
      .status(400)
      .render("auth/login", { errorMessage: "Please provide your email." });
  }

  // Here we use the same logic as above
  // - either length based parameters or we check the strength of a password
  if (password.length < 3) {
    return res.status(400).render("auth/login", {
      errorMessage: "Your password needs to be at least 8 characters long.",
    });
  }

  // Search the database for a user with the email submitted in the form
  User.findOne({ email })
    .then((user) => {
      // If the user isn't found, send the message that user provided wrong credentials
      if (!user) {
        return res
          .status(400)
          .render("auth/login", { errorMessage: "Wrong credentials." });
      }

      // If user is found based on the email, check if the in putted password matches the one saved in the database
      bcrypt.compare(password, user.password).then((isSamePassword) => {
        if (!isSamePassword) {
          return res
            .status(400)
            .render("auth/login", { errorMessage: "Wrong credentials." });
        }
        req.session.user = user._id;
        // req.session.user = user._id; // ! better and safer but in this case we saving the entire user object
        return res.redirect("/auth/profile");
      });
    })

    .catch((err) => {
      // in this case we are sending the error handling to the error handling middleware that is defined in the error handling file
      // you can just as easily run the res.status that is commented out below
      next(err);
      // return res.status(500).render("login", { errorMessage: err.message });
    });
});

router.get("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .render("auth/logout", { errorMessage: err.message });
    }
    res.redirect("/");
  });
});

router.get("/profile", isLoggedIn, (req, res) => {
  const id = req.session.user;
  User.findById(id).then((user) => {
    console.log(user);
    res.render("auth/profile", user);
  });
});


router.get("/rooms",  (req, res) => {
  Room.find()
  .populate({path: "owner", model: "User"})
 // .poputale({path: "reviews", model: "Review"})
  
  .then((rooms)=>{
    
    res.render("../views/room/all-rooms", {rooms});

  })
  });



module.exports = router;
