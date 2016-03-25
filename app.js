
var express = require('express');
var passport = require('passport');
var bodyParser = require('body-parser');

var auth = require('./auth');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

auth.configure(app, passport);


module.exports = app;
