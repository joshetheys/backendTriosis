// Importing modules
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./config/dbconn');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
// Express app
const app = express();
app.use(express.static('views'))
// Set header
app.use((req, res, next)=>{
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader('Access-Control-Allow-Methods',"*");
    res.setHeader("Access-Control-Allow-Headers-*", "*");
    next();
});
app.use(cors({
    origin: ['http://127.0.0.1:8080', 'http://localhost:8080'],
    credentials: true
 }));
// credentials will allow you to access the cookie on your fetch(url, 
{
credentials: 'include'
}
// Express router
const router = express.Router();

// Configuration 
const port = parseInt(process.env.PORT) || 4000;
app.use(router, cors(), express.json(), cookieParser(),  bodyParser.urlencoded({ extended: true }));
app.listen(port, ()=> {console.log(`Server is running on port ${port}`)});


// REGISTER USERS
router.post('/users', bodyParser.json(),(req, res)=>{
    let emails = `SELECT email FROM users WHERE ?`;
    let email = {
        email: req.body.email
    }
    db.query(emails, email, async(err, results)=>{
        if(err) throw err
        // VALIDATION OF USER
        if (results.length > 0) {
            res.send("The email provided is already registered. Enter another email to successfully register");
            
        } else {
            const bd = req.body;
            let generateSalt = await bcrypt.genSalt();
            bd.userpassword = await bcrypt.hash(bd.userpassword, generateSalt);
            console.log(bd);
           
            // Query
            const strQry = 
            `
            INSERT INTO users(fullnames, email,  userpassword)
             VALUES(?, ?, ?);
            `
          
            
            db.query(strQry, [bd.fullnames, bd.email, bd.userpassword ], (err, results)=>{
                    if(err) throw err
                    const payload = {
                        user: {
                            fullnames: bd.fullnames, 
                            email: bd.email,  
                            userpassword: bd.userpassword
                        }
                    };

                    jwt.sign(payload, process.env.SECRET_KEY, {expiresIn: "365d"}, (err, token)=>{
                        if(err) throw err
                        res.json({
                            status: 200,
                            msg: "Registration Successful",
                            results: results,  
                            token:token
                        })  
                    })
                    // res.send(`number of affected row/s: ${results.affectedRows}`);
                })
        }
    })
});



// LOGIN
router.patch('/users', bodyParser.json(), (req, res)=> {
    const strQry = `SELECT * FROM users WHERE ? ;`;
    let user = {
        email: req.body.email
    };
    db.query(strQry, user, async(err, results)=> {
        if (err) throw err;
        if (results.length === 0) {
            res.send('Email not found. Please register')
        } else {
            const isMatch = await bcrypt.compare(req.body.userpassword, results[0].userpassword);
            if (!isMatch) {
                res.send('Password is Incorrect')
            } else {
                const payload = {
                    user: {
                      fullnames: results[0].fullnames,
                      userRole: results[0].userRole,
                      email: results[0].email,
                      userpassword: results[0].userpassword,
                      cart : results[0].cart,
                    },
                  };
                jwt.sign(payload,process.env.SECRET_KEY,{expiresIn: "365d"},(err, token) => {
                    if (err) throw err;
                    res.json({
                        results:results,
                        token:token
                    })
                  }
                );
            }
        }
    })
})


// GET ALL USERS
router.get('/users', (req, res)=> {
    // Query
    const strQry = 
    `
    SELECT id, fullnames, userRole, email, userpassword
    FROM users;
    `;
    db.query(strQry, (err, results)=> {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 200,
            users: results
        })
    })
});

// GET ONE USER
router.get('/users/:id', (req, res)=> {
     // Query
    const strQry = 
    `SELECT id, fullnames, email, userpassword, userRole, cart
    FROM users
    WHERE id = ?;
    `;
    db.query(strQry, [req.params.id], (err, results) => {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 204,
            results: (results.length < 1) ? "Unfortuanately there was no data found for the user id." : results
        })
    })
});

// Delete a user 
router.delete('/users/:id', (req, res)=> {
    const strQry = 
    `
    DELETE FROM users 
    WHERE id = ?;
    ALTER TABLE users AUTO_INCREMENT = 1;
    `;
    db.query(strQry,[req.params.id], (err)=> {
        if(err) throw err;
        res.status(200).json({msg: "You have deleted the user."});
    })
});


// Updating user
router.put('/users/:id', bodyParser.json(), (req, res)=> {
    const bd = req.body;
    if(bd.userpassword !== null || bd.userpassword !== undefined){ bd.userpassword = bcrypt.hashSync(bd.userpassword, 10);
    }
    const strQry = 
    `UPDATE users
     SET ?
     WHERE id = ?`;
    db.query(strQry,[bd, req.params.id], (err, data)=> {
        if(err) throw err;
        res.send(`number of affected record/s: ${data.affectedRows}`);
    })
});
// CREATE PRODUCT
router.post('/products', bodyParser.json(), (req, res)=> {
    const bd = req.body; 
    bd.totalamount = bd.quantity * bd.price;
    // Query
    const strQry = 
    `
    INSERT INTO products(title, category, type, description, size, imgURL, quantity, price, createdBy)
    VALUES(?, ?, ?, ?, ?, ?, ?);
    `;
    //
    db.query(strQry, 
        [bd.title, bd.category, bd.type, bd.description, bd.size, bd.imgURL, bd.quantity, bd.price, bd.created_by],
        (err, results)=> {
            if(err) throw err;
            res.status(201).send(`number of affected row/s: ${results.affectedRows}`);
        })
});





// GET ALL PRODUCTS
router.get('/products', (req, res)=> {
    // Query
    const strQry = 
    `
    SELECT productId, title, category, type, description, size, imgURL, quantity, price, createdBy
    FROM products; 
    `;
    db.query(strQry, (err, results)=> {
        if(err) throw err;
        res.status(200).json({
            status: 'ok',
            products: results
        })
    })
});




// GET ONE PRODUCT
router.get('/products/:productId', (req, res)=> {
    // Query
    const strQry = 
    `SELECT productId, title, category, type, description, size, imgURL, quantity, price, createdBy
    FROM products
    WHERE productId = ?;
    `;
    db.query(strQry, [req.params.productId], (err, results)=> {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 200,
            results: (results.length <= 0) ? "Sorry, no product was found." : results
        })
    })
});

// GET CATERGORY
router.get('/productsCategory/:category', (req, res)=> {
    // Query
    const strQry = 
    `SELECT productId, title, category, type, description, size, imgURL, quantity, price, createdBy
    FROM products
    WHERE category = ?;
    `;
    db.query(strQry, [req.params.category], (err, results)=> {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 200,
            results: (results.length <= 0) ? "Sorry, no products were found." : results
        })
    })
});

// GET TYPE
router.get('/productsType/:type', (req, res)=> {
    // Query
    const strQry = 
    `SELECT productId, title, category, type, description, size, imgURL, quantity, price, createdBy
    FROM products
    WHERE type = ?;
    `;
    db.query(strQry, [req.params.type], (err, results)=> {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 200,
            results: (results.length <= 0) ? "Sorry, no products were found." : results
        })
    })
});




// UPDATE PRODUCT
router.put('/products/:productId', bodyParser.json(), (req, res)=> {
    const bd = req.body;
    // Query
    const strQry = 
    `UPDATE products
     SET ?
     WHERE productId = ?`;

     db.query(strQry, [bd, req.params.productId], (err, data)=> {
        if(err) throw err;
        res.send(`number of affected record/s: ${data.affectedRows}`);
    })
});



// DELETE PRODUCT
router.delete('/products/:productId', (req, res)=> {
    // Query
    const strQry = 
    `
    DELETE FROM products 
    WHERE productId = ?;
    ALTER TABLE products AUTO_INCREMENT = 1;
    `;
    db.query(strQry,[req.params.productId], (err, data, fields)=> {
        if(err) throw err;
        res.send(`${data.affectedRows} rows were affected`);
    })
});


//CART
//GET USER'S CART
router.get('/users/:id/cart', (req, res)=> {
//  Query
const strQry =
`
SELECT cart FROM users
WHERE id = ?;
`;
db.query(strQry,[req.params.id], (err, data, fields)=> {
    if(err) throw err;
    res.send(data[0].cart);
})
} 
);
// ADD TO CART
router.post('/users/:id/cart',bodyParser.json(), (req, res)=> {
    //  Query
    const strQry =
    `SELECT cart FROM users
     WHERE id = ?;
    `;
    db.query(strQry,[req.params.id], (err, data, fields)=> {
        if(err) throw err;
        let stan = [];
        if (data[0].cart != null) {
            stan = JSON.parse(data[0].cart)
        }
        const prod = {
            product_id: stan.length+1,
            title: "",
            category: "",
            description: "",
            image: "",
            price: 1200,
            quantity: 100
        }
        stan.push(prod)
        // res.send(stan);
        // Query
        const put =
        `
        UPDATE users SET cart = ?
        WHERE id = ?;
        `;
        db.query(put, [JSON.stringify(stan), req.params.id], (err, data, fields)=> {
            if(err) throw err;
            res.send(data);
        })
    })
  
    } 
    ); 

// DELETE WHOLE CART
router.delete('/users/:id/cart',bodyParser.json(), (req, res)=> {
    // Query
    const strQry = 
    `
        UPDATE users SET cart = null
        WHERE id = ?;
        `;
    db.query(strQry,[req.params.id], (err, data, fields)=> {
        if(err) throw err;
        res.send(`${data.affectedRows} rows were affected`);
    })
});
// DELETE SPECIFIC ITEM CART
router.delete('/users/:id/cart/:product_id',bodyParser.json(), (req, res)=> {
    // Query
    const deleteProd = 
    `
        SELECT cart FROM users 
        WHERE id =${req.params.id};
        `;
    db.query(deleteProd,[req.params.id], (err, data, fields)=> {
        if(err) throw err;
        const deleted = JSON.parse(data[0].cart).filter((cart)=>{
            return cart.product_id != req.params.product_id;
        })
        deleted.forEach((cart, i)=> {
            cart.product_id = i + 1
        });
        const end =
        `
        UPDATE users SET cart = ?
        WHERE id = ${req.params.id}
        `
        db.query(end, [JSON.stringify(deleted)], (err,results)=>{
            if(err) throw err;
            res.send(`${data.affectedRows} rows were affected`);
        })
        
    })
});
 
module.exports = {
    devServer: {
        Proxy: '*'
    }
}

