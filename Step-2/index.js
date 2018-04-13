const app = require('express')();
const {ExtractJwt, Strategy: JwtStrategy} = require('passport-jwt');
const {json} = require('body-parser');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const uuid = require('uuid/v4');

// Fake Redis
const tokens = [];

function createAndStoreToken() {
    const token = jwt.sign({id: uuid()}, 'secret');
    tokens.push(token);
    return token;
}

const jwtOpts = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    passReqToCallback: true,
    secretOrKey: 'secret'
};

passport.use('jwt', new JwtStrategy(jwtOpts, (req, payload, next) => {
    const {authorization} = req.headers;
    const isAuthorized = tokens.some(token => token === authorization);
    return next(null, isAuthorized && payload);
}));

app.use(json());
app.use(passport.initialize());

app.get('/', (req, res) => res.sendFile(`${process.cwd()}/Step-2/html/index.html`));

app.get('/login', (req, res) =>
    res.send(`
        <script>
            localStorage.setItem('token', '${createAndStoreToken()}');
            location.href = '/';
        </script>
    `));

app.get('/logout', passport.authenticate('jwt', {session: false}), (req, res) => {
    const {authorization: token} = req.headers;
    tokens.splice(tokens.indexOf(token), 1);
    res.json({message: 'Successfully logged out!'});
});

app.get('/protected', passport.authenticate('jwt', {session: false}), (req, res) => res.send({message: 'Protected message!'}));

app.listen(1337, () => console.log('http://localhost:1337'));
