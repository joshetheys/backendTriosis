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
    res.setHeader("Access-Control-Allow-Headers", "*");
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
router.post('/users/register', bodyParser.json(),(req, res)=>{
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
             // hash(bd.userpassword, 10).then((hash) => {
                //set the password to hash value
        //         (err, result) => {
        //   if (err){
        //    return res.status(400).send({msg: err})

        //   }
        //   return res.status(201).send({msg: "hash successful"})
        //  }
        //         bd.userpassword = hash
        //       })
            let generateSalt = await bcrypt.genSalt();
            bd.userpassword = await bcrypt.hash(bd.userpassword, generateSalt);
            console.log(bd);
           
            // Query
            const strQry = 
            `
            INSERT INTO users(firstname, lastname, gender, address,  userRole, email,  userpassword)
             VALUES(?, ?, ?, ?, ?, ?, ?);
            `
          
            
            db.query(strQry, [bd.firstname, bd.lastname, bd.gender, bd.address, bd.userRole,  bd.email, bd.userpassword ], (err, results)=>{
                    if(err) throw err
                    const payload = {
                        user: {
                            firstname: bd.firstname,
                            lastname: bd.lastname, 
                            gender: bd.gender, 
                            address: bd.address,  
                            userRole: bd.userRole, 
                            email: bd.email,  
                            userpassword: bd.userpassword
                        }
                    };

                    jwt.sign(payload, process.env.SECRET_KEY, {expiresIn: "365d"}, (err, token)=>{
                        if(err) throw err
                        res.json({
                            status: 200,
                            msg: "Registration Successful",
                            user: results,  
                            token:token
                        })  
                    })
                    // res.send(`number of affected row/s: ${results.affectedRows}`);
                })
        }
    })
});



// LOGIN
router.patch('/users/login', bodyParser.json(), (req, res)=> {
    const strQry = `SELECT * FROM users WHERE ? ;`;
    let user = {
        email: req.body.email
    };

    db.query(strQry, user, async(err, results)=> {
        if (err) throw err;

        if (results.length === 0) {
            res.send('The email entered is not registered in our system. Please try to register.')
        } else {
            const isMatch = await bcrypt.compare(req.body.userpassword, results[0].userpassword);
            if (!isMatch) {
                res.send('The password entered is incorrect.')
            } else {
                const payload = {
                    user: {
                      fullname: results[0].fullname,
                      email: results[0].email,
                      userpassword: results[0].userpassword,
                      userRole: results[0].userRole,
                      phone_number: results[0].phone_number,
                      join_date: results[0].join_date,
                    },
                  };

                jwt.sign(payload,process.env.SECRET_KEY,{expiresIn: "365d"},(err, token) => {
                    if (err) throw err;
                    res.json({
                        status: 200,
                        user: results,
                        token:token
                    })  
                  }
                );  
            }
        }

    }) 
});


// GET ALL USERS
router.get('/users', (req, res)=> {
    // Query
    const strQry = 
    `
    SELECT id, firstname, lastname, gender, address, userRole, email, userPassword
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
router.get('/users/:userId', (req, res)=> {
     // Query
    const strQry = 
    `SELECT userId, fullname, email, userpassword, userRole, phone_number, join_date, cart
    FROM users
    WHERE userId = ?;
    `;
    db.query(strQry, [req.params.userId], (err, results) => {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 204,
            results: (results.length < 1) ? "Unfortuanately there was no data found for the user id." : results
        })
    })
});

// Delete a user 
router.delete('/users/:userId', (req, res)=> {
    const strQry = 
    `
    DELETE FROM users 
    WHERE userId = ?;
    `;
    db.query(strQry,[req.params.userId], (err)=> {
        if(err) throw err;
        res.status(200).json({msg: "You have deleted the user."});
    })
});


// Updating user
router.put('/users/:userId', bodyParser.json(), (req, res)=> {
    const bd = req.body;
    if(bd.userpassword !== null || bd.userpassword !== undefined){ bd.userpassword = bcrypt.hashSync(bd.userpassword, 10);
    }
    const strQry = 
    `UPDATE users
     SET ?
     WHERE userId = ?`;
    db.query(strQry,[bd, req.params.userId], (err, data)=> {
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
    INSERT INTO products(title, category, description, image, price, created_by, quantity)
    VALUES(?, ?, ?, ?, ?, ?, ?);
    `;
    //
    db.query(strQry, 
        [bd.title, bd.category, bd.description, bd.image, bd.price, bd.created_by, bd.quantity],
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
    SELECT product_id, title, category, description, image, price, created_by, quantity
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
router.get('/products/:product_id', (req, res)=> {
    // Query
    const strQry = 
    `SELECT product_id, title, category, description, image, price, created_by, quantity
    FROM products
    WHERE product_id = ?;
    `;
    db.query(strQry, [req.params.product_id], (err, results)=> {
        if(err) throw err;
        res.setHeader('Access-Control-Allow-Origin','*')
        res.json({
            status: 200,
            results: (results.length <= 0) ? "Sorry, no product was found." : results
        })
    })
});




// UPDATE PRODUCT
router.put('/products/:product_id', bodyParser.json(), (req, res)=> {
    const bd = req.body;
    // Query
    const strQry = 
    `UPDATE products
     SET ?
     WHERE product_id = ?`;

     db.query(strQry, [bd, req.params.product_id], (err, data)=> {
        if(err) throw err;
        res.send(`number of affected record/s: ${data.affectedRows}`);
    })
});



// DELETE PRODUCT
router.delete('/products/:product_id', (req, res)=> {
    // Query
    const strQry = 
    `
    DELETE FROM products 
    WHERE product_id = ?;
    `;
    db.query(strQry,[req.params.product_id], (err, data, fields)=> {
        if(err) throw err;
        res.send(`${data.affectedRows} rows were affected`);
    })
});


//CART
//GET USER'S CART
router.get('/users/:userId/cart', (req, res)=> {
//  Query
const strQry =
`
SELECT * FROM users
WHERE userID = ?;
`;
db.query(strQry,[req.params.userId], (err, data, fields)=> {
    if(err) throw err;
    res.send(data[0].cart);
})
} 
);
// ADD TO CART
router.post('/users/:userId/cart',bodyParser.json(), (req, res)=> {
    //  Query
    const strQry =
    `SELECT * FROM users
     WHERE userID = ?;
    `;
    db.query(strQry,[req.params.userId], (err, data, fields)=> {
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
        WHERE userId = ?;
        `;
        db.query(put, [JSON.stringify(stan), req.params.userId], (err, data, fields)=> {
            if(err) throw err;
            res.send(data);
        })
    })
  
    } 
    ); 

// DELETE WHOLE CART
router.delete('/users/:userId/cart',bodyParser.json(), (req, res)=> {
    // Query
    const strQry = 
    `
        UPDATE users SET cart = null
        WHERE userId = ?;
        `;
    db.query(strQry,[req.params.userId], (err, data, fields)=> {
        if(err) throw err;
        res.send(`${data.affectedRows} rows were affected`);
    })
});
// DELETE SPECIFIC ITEM CART
router.delete('/users/:userId/cart/:product_id',bodyParser.json(), (req, res)=> {
    // Query
    const deleteProd = 
    `
        SELECT cart FROM users 
        WHERE userId =${req.params.userId};
        `;
    db.query(deleteProd,[req.params.userId], (err, data, fields)=> {
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
        WHERE userId = ${req.params.userId}
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

 
