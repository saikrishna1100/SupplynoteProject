const express = require('express');
const db = require('./db');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');

require('dotenv').config();

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}));

db.connect();

const port = process.env.PORT;

const authenticateUser = (req, res, next) => {
    if(!req.session.isLoggedIn)
        return res.redirect('/login');

    next();
};

// ----------------- Dashboard ------------------
app.get('/', authenticateUser, async (req, res) => {
    const query = 'SELECT * FROM links WHERE user_id = $1';
    const user = req.session.user;
    const links = await db.query(query, [ user.userId ]);

    let linkToCopy = undefined;

    if(req.query.qName) {
        linkToCopy =req.protocol + '://' + req.get('host') + `/${req.query.qName}`;
    }

    return res.render('index', { 'user': user, links, success: req.query.success, err: req.query.err, linkToCopy: linkToCopy });
});

// ------------------ Login ---------------------

app.get('/login', (req, res) => {
    if(req.session.isLoggedIn) {
        if(req.query.success)
            return res.redirect(`/?success=${req.query.success}`)
        else
            return res.redirect(`/?err=${req.query.err}`);
    }

    return res.render('login', {success: req.query.success, err: req.query.err});
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    
        if (result.rows.length > 0) {
          const user = result.rows[0];
    
          if(await bcrypt.compare(password, user.password)) {
            req.session.isLoggedIn = true;
            req.session.user = {
                userId: user.id,
                firstName: user.first_name, 
                lastName: user.last_name, 
                email: email 
            };
            
            return res.redirect('/');
          }
    
          return res.redirect('/login?err=Invalid credentials');
        } else {
            return res.redirect('/login?err=User does not exists');
        }
      } catch (error) {
        return res.redirect(`/login?err=${error}`);
      }
});


// ------------------ Logout --------------------
app.get('/logout', (req, res) => {
    if(!req.session.isLoggedIn)
        return res.redirect('/login');

    req.session.isLoggedIn = false;
    req.session.user = null;

    return res.redirect('/login?success=Logged out successfully!');
});

// ------------------ Signup --------------------

app.get('/signup', (req, res) => {
    return res.render('signup', {err: req.query.err});
});

app.post('/signup', async (req, res) => {
    const { firstName, lastName, email, password, password2 } = req.body;

    if(password != password2) {
        return res.redirect('/signup?err=Passwords did not match');
    }

    console.log(req.body);

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      await db.query(
        'INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4) RETURNING *',
        [firstName, lastName, email, hashedPassword]
      );
    } catch (error) {
        return res.redirect(`/signup?err=${error}`)
    }

    return res.redirect('/login?success=Registered successfully!');
});

// ----------------- Link -----------------------
app.get('/create-link', authenticateUser, (req, res) => {
    return res.render('createLink', {err: req.query.err});
});

app.post('/create-link', authenticateUser, async (req, res) => {
    const { linkName, longUrl } = req.body;
    
    let query =  'SELECT * FROM links WHERE link_token=$1';

    const result = await db.query(query, [linkName]);

    if(result.rows.length > 0)
        return res.redirect('/create-link?err=Link name already taken');

    query = 'INSERT INTO links (user_id, link_token, long_url, expires_at) VALUES ($1, $2, $3, $4) RETURNING *';
    const user = req.session.user;
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 48);

    let qName = undefined;

    try {
        const result = await db.query(query, [user.userId, linkName, longUrl, expiresAt]);
        qName = result.rows[0].link_token;
    } catch(err) {
        console.log(err);
        return res.redirect('/create-link?err=Internal server error, try after some time');
    }

    return res.redirect(`/?success=Link created successfully!&qName=${qName}`);
});

// ----------------- Short Link -----------------
app.get('/:linkName', async (req, res) => {
    const linkName = req.params.linkName;

    let query = 'SELECT * FROM links WHERE link_token = $1 AND expires_at > CURRENT_TIMESTAMP';

    try {
        const result = await db.query(query, [ linkName ]);

        if (result.rows.length > 0) {
            query = 'UPDATE links SET access_count = access_count + 1 WHERE id = $1';
            await db.query(query, [ result.rows[0].id ]);
            return res.redirect(result.rows[0].long_url);
        } else {
            return res.redirect('/login?err=Link not found or expired');
        }
    } catch (error) {
        console.error('Error:', error);
        return res.redirect('/login?err=Internal Server Error, try after sometime');
    }
});

app.listen(port, () => {
    console.log(`App is up and running on port ${port}, http://localhost:${port}`);
});