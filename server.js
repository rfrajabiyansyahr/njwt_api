var uuidV4      = require('uuid/v4');
var nJwt        = require('njwt');
var express     = require('express');
var bodyParser  = require('body-parser');
var mongoose    = require('mongoose');
var morgan      = require('morgan');
var cors        = require('cors');
var app         = express();
var generateKey = uuidV4();
var User        = require('./app/models/user');
var port        = process.env.PORT || 8080;
var signingKey  = generateKey;

mongoose.connect('mongodb://njwt_admin:manyanSKM@ds161742.mlab.com:61742/njwt_db');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(morgan('dev'));

app.use(cors());

app.get('/', function(req, res){
    res.send('You are awesome!');
});

var apiRoutes = express.Router();

apiRoutes.post('/signup', function(req, res){
    if(!req.body.username || !req.body.password || !req.body.name || !req.body.role){
        res.send('Please insert the user data!');
    } else {
        var newUser = new User({
            username: req.body.username,
            password: req.body.password,
            name: req.body.name,
            role: req.body.role
        })

        newUser.save(function(err){
            if(err){
                return res.send('Username already exists!')
            }
            res.send('Username ' + req.body.username + ' created!')
        });
    }
});

apiRoutes.post('/authenticate', function(req, res){
    User.findOne({
        username: req.body.username
    }, function(err, user){
        if(err) throw err;

        if(!user){
            res.send('Authentication failed! User not found');
        } else if(user){
            user.comparePassword(req.body.password, function(err, isMatch){
                if(isMatch && !err){
                    var jwt = nJwt.create(user, generateKey);
                    var token = jwt.compact();
                    res.json({
                        token: token
                    });
                } else {
                    res.send('Authentication failed! Wrong password');
                }
            });
        }
    });
});

apiRoutes.post('/verify-token', function(req, res){
    var token = req.headers.token;
    if(token){
        var verifyJwt = nJwt.verify(token, signingKey);
        res.send(verifyJwt);
    }
});

apiRoutes.get('/account-data', function(req, res){
    var token = req.headers.token;

    if (token) {
        var verifyJwt = nJwt.verify(token, signingKey);
        User.find({}, function(err, user) {
            if (err) throw err;

            if (verifyJwt.body._doc.role == 'admin') {
                res.json(user);
            } else {
                return res.status(403).send('YOU ARE FORBIDDEN');
            }
        });
    } else {
        return res.status(403).send({success: false, msg: 'Tidak ada token.'});
    }
});

getToken = function(headers){
    if(headers && headers.authorization){
        var parted = headers.authorization.split(' ');
        if(parted.length === 2) {
            return parted[1];
        } else {
            return null;
        }
    } else {
        return null;
    }
};

app.use('/api', apiRoutes);

app.listen(port);
console.log('\nSomething is happening on port: ' + port);