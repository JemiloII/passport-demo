const app = require('express')();
const config = require('config');
const {ExtractJwt, Strategy: JwtStrategy} = require('passport-jwt');
const {OAuth2Strategy: GoogleStrategy} = require('passport-google-oauth');
const {json} = require('body-parser');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const uuid = require('uuid/v4');

// Fake Redis
const tokens = [];

function createAndStoreToken() {
    const token = jwt.sign({id: uuid()}, config.get('token.secret'));
    tokens.push(token);
    return token;
}

const jwtOpts = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    passReqToCallback: true,
    secretOrKey: config.get('token.secret')
};

passport.use('jwt', new JwtStrategy(jwtOpts, (req, payload, next) => {
    const {authorization} = req.headers;
    const isAuthorized = tokens.some(token => token === authorization);
    return next(null, isAuthorized && payload);
}));

const googleOpts = {
    clientID: config.get('auth.google.clientID'),
    clientSecret: config.get('auth.google.clientSecret'),
    callbackURL: "http://localhost:1337/auth/google/verify"
};

passport.use(new GoogleStrategy(googleOpts, (accessToken, refreshToken, profile, next) => next(null, profile)));

app.use(json());
app.use(passport.initialize());

app.get('/', (req, res) => res.sendFile(`${process.cwd()}/Step-3/html/index.html`));

app.get('/failed', (req, res) => res.send('Failed to login!'));

app.get('/auth/google', passport.authenticate('google', {scope: ['https://www.googleapis.com/auth/plus.login'], session: false}));

app.get('/auth/google/verify', passport.authenticate('google', {failureRedirect: '/failed', session: false}), (req, res) =>
    res.send(`<script>
        localStorage.setItem('token', '${createAndStoreToken()}');
        location.href = '/';
    </script>`));

app.get('/logout', passport.authenticate('jwt', {session: false}), (req, res) => {
    const {authorization: token} = req.headers;
    tokens.splice(tokens.indexOf(token), 1);
    res.json({message: 'Successfully logged out!'});
});

app.get('/protected', passport.authenticate('jwt', {session: false}), (req, res) => res.send({message: 'Protected message!'}));

app.listen(1337, () => console.log('http://localhost:1337'));
