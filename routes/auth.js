let express = require('express')
let router = express.Router()
let passport = require('passport')
let localStrategy = require('passport-local')
let crypto = require('crypto')
let db = require('../db')

passport.use(new localStrategy((username, password, done) => {
    db.get('SELECT * FROM users WHERE username=?', [username], (err, row) => {
        if(err) { return done(err);}
        if(!row) { return done(null, false, {message: 'El usuario no existe'});}

        crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', (err, hashedPassword) => {
            if(err) { return done(err)}
            if(!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
                return done(null, false, { message: 'La password es incorrecta' })
            }

            return done(null, row)
        })

    })
}))

passport.serializeUser((user, done) => {
    process.nextTick(() => {
        done(null, {id: user.id, username: user.username, name: user.name})
    })
})

passport.deserializeUser((user, done) => {
    process.nextTick(() => {
        done(null, user)
    })
})


router.get('/login', (req, res, next) => {
    res.render('login')
})

router.post('/login/password', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}))

router.post('/logout', (req, res, next) => {
    req.logout((err) => {
        if(err) { return next(err)}
        res.redirect('/')
    })
})

router.get('/signup', (req, res, next) => {
    res.render('signup')
})

router.post('/signup', (req, res, next) => {
    let salt = crypto.randomBytes(16)
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', (err, hashedPassword) => {
        if(err) { return next(err) }
        db.run('INSERT INTO users(username, hashed_password, salt) VALUES(?, ?, ?)', [req.body.username, hashedPassword, salt], (err, row) => {
            if(err) { return next(err) }
            let user = {
                id: this.lastID,
                username: req.body.username
            }

            req.login(user, (err) => {
                if(err) { return next(err)}
                res.redirect('/')
            })
        })
    })

})

module.exports = router
