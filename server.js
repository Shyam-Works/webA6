const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const userService = require('./user-service.js');
const HTTP_PORT = process.env.PORT || 8080;
dotenv.config();

const { ExtractJwt, Strategy: JwtStrategy } = passportJWT;
app.use(express.json());
app.use(cors());
app.use(passport.initialize());


const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
};

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    userService.getUserById(jwt_payload._id)
        .then(user => {
            if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        })
        .catch(err => done(err, false));
});

passport.use(strategy);  



app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
    .then((msg) => {
        res.json({ "message": msg });
    }).catch((msg) => {
        res.status(422).json({ "message": msg });
    });
});

app.post('/api/user/login', (req, res) => {
    userService.checkUser(req.body)
        .then(user => {
            // Create a payload with _id and userName from the resolved user object
            const payload = { _id: user._id, userName: user.userName };
            // Sign the payload with the secret from the environment variable
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.json({
                message: 'login successful',
                token: token
            });
        })
        .catch(msg => {
            // If checkUser fails, respond with an error
            res.status(422).json({ message: msg });
        });
});


app.get("/api/user/favourites", (req, res) => {
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.getFavourites(req.user._id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }

});

app.put("/api/user/favourites/:id", (req, res) => {
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.addFavourite(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
});

app.delete("/api/user/favourites/:id", (req, res) => {
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.removeFavourite(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
});

app.get('/api/user/history', 
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.getHistory(req.user._id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.put('/api/user/history/:id', 
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.addHistory(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.delete('/api/user/history/:id', 
    passport.authenticate('jwt', { session: false }), 
    (req, res) => {
        userService.removeHistory(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

userService.connect()
.then(() => {
    app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT) });
})
.catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
});