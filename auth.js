var express = require('express');
var session = require('express-session');
var Strategy = require('passport-openidconnect').Strategy;

module.exports.configure = function configure(app, passport) {

    var identityServer = 'http://localhost:5000/identity';

    var auth = {
        authorizationURL: identityServer + '/connect/authorize',
        tokenURL: identityServer + '/connect/token',
        userInfoURL: identityServer + '/connect/userinfo',
        clientID: 'G9DFAF8C-4211-4864-8D74-19F269B7F054',
        clientSecret: '^secret',
        callbackURL: '/auth/callback',
        scope: 'openid email profile offline_access phone manageEvents'
    };

    app.use(passport.initialize());
    app.use(passport.session());


    passport.use(new Strategy(auth, function (iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified) {
        verified(null, Object.assign({}, profile, {token: accessToken}));
    }));

    passport.serializeUser(function (user, done) {
        done(null, {id: user.id, name: user.displayName, token: user.token});
    });

    passport.deserializeUser(function (user, done) {
        done(null, user);
    });

    app.get('/auth/login', passport.authenticate('openidconnect', {}));

    app.get('/auth/callback', passport.authenticate('openidconnect', {}),
        function (req, res) {
            if (!req.user) {
                throw new Error('user null');
            }
            res.redirect("/");
        }
    );

    app.get('/auth/logout',function(req, res){
        var token = req.user.token;
        req.logout();
        var uri = identityServer + '/connect/endsession?id_token=token&post_logout_redirect_uri=https://www.xxx.com';
        res.redirect(uri);
    });
};