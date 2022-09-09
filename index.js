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
    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);
    `;
    //
    db.query(strQry, 
        [bd.title, bd.category, bd.type, bd.description, bd.size, bd.imgURL, bd.quantity, bd.price, bd.created_by],
        (err, results)=> {
            if(err) throw err;
            res.json({msg:"You added a new product"});
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
// router.put('/products/:productId', bodyParser.json(), (req, res)=> {
//     const bd = req.body;
//     // Query
//     const strQry = 
//     `UPDATE products
//      SET ?
//      WHERE productId = ?`;

//      db.query(strQry, [bd, req.params.productId], (err, data)=> {
//         if(err) throw err;
//         res.send(`number of affected record/s: ${data.affectedRows}`);
//     })
// });

// UPDATE PRODUCT
router.put('/products/:id', bodyParser.json(), (req, res) => {
    const editProduct = `
          UPDATE products
          SET title = ?, imgURL = ?, quantity = ?, price = ?, createdBy= ?
          WHERE productId = ${req.params.id}
      `;
  
    db.query(
      editProduct,
      [
        req.body.title,
        req.body.imgURL,
        req.body.quantity,
        req.body.price,
        req.body.createdBy
      ],
      (err, results) => {
        if (err) throw err;
        res.json({
          status: 200,
          results: "The product has been edited succesfully",
        });
      }
    );
  });

//DELETE PRODUCT
router.delete('/products/:productId', (req, res)=> {
    // Query
    const strQry = 
    `
    DELETE FROM products 
    WHERE productId = ${req.params.productId};
    ALTER TABLE products AUTO_INCREMENT = 1;
    `;
    db.query(strQry, (err, results)=> {
        if(err) throw err;
        res.json({msg:"Deleted"});
    })
});


// router.put("/products/:productId", bodyParser.json(), (req, res) => {
//     try {
//         const {
//             productId, title, category, type, description, size, imgURL, quantity, price, createdBy
//         } = req.body
//         const str = `UPDATE products SET ? WHERE productId = ${req.params.productId}`

//         const product = {
//             // bd.
//             productId, title, category, type, description, size, imgURL, quantity, price, createdBy
//         }

//         db.query(str, product, (err, results) => {
//             if (err) throw err;

//             res.json({
//                 results,
//                 msg: "updated product"
//             })
//         })
//     } catch (error) {
//         throw error
//     }
// });



//CART
//GET USER'S CART
// router.get('/users/:id/cart', (req, res)=> {
//  Query
// const strQry =
// `
// SELECT cart FROM users
// WHERE id = ?;
// `;
// db.query(strQry,[req.params.id], (err, data, fields)=> {
//     if(err) throw err;
//     res.send(data[0].cart);
// })
// } 
// );

// GET CART PRODUCTS
router.get('/users/:id/cart', (req, res)=>{
  const cart = `
      SELECT cart FROM users
      WHERE id = ${req.params.id}
  `
  db.query(cart, (err, results)=>{
      if (err) throw err
      if (results[0].cart !== null) {
          res.json({
              status: 200,
              cart: JSON.parse(results[0].cart)
          })
      } else {
          res.json({
              status: 404,
              message: 'There is no items in your cart'
          })
      }
  })
})
// ADD TO CART
// router.post('/users/:id/cart',bodyParser.json(), (req, res)=> {
    //  Query
    // const strQry =
    // `SELECT cart FROM users
    //  WHERE id = ?;
    // `;
    // db.query(strQry,[req.params.id], (err, data, fields)=> {
    //     if(err) throw err;
    //     let stan = [];
    //     if (data[0].cart != null) {
    //         stan = JSON.parse(data[0].cart)
    //     }
    //     const prod = {
    //         productId: stan.length+1,
    //         title: "",
    //         category: "",
    //         type: "",
    //         description: "",
    //         size: "",
    //         imgURL: "",
    //         quantity: 100,
    //         price: 1200
    //     }
    //     stan.push(prod)
    //     // res.send(stan);
    //     // Query
    //     const put =
    //     `
    //     UPDATE users SET cart = ?
    //     WHERE id = ?;
    //     `;
    //     db.query(put, [JSON.stringify(stan), req.params.id], (err, data, fields)=> {
    //         if(err) throw err;
    //         res.send(data);
    //     })
    // })
  
    // } 
    // ); 

    router.post('/users/:id/cart', bodyParser.json(),(req, res)=>{
        let route = req.params
        const cart = `select cart from users where id = ${route.id}`
        db.query(cart,(err, results)=>{
            if(err)throw err
            if(results.length > 0 ){
                let cart
                if(results[0].cart == null){
                    cart = []
                    
                }else{
                    cart = JSON.parse(results[0].cart)
                }
            let product = {
                //         title: "",
                //         category: "",
                //         type: "",
                //         description: "",
                //         size: "",
                //         imgURL: "",
                //         quantity: 100,
                //         price: 1200
                'cart_id' : cart.length + 1, 
                'title' : req.body.title,
                'category':  req.body.category,
                'type':  req.body.type,
                'description': req.body.description,
                'size': req.body.size,
                'imgURL': req.body.imgURL,
                'quantity': parseInt(req.body.quantity) -1,
                'price': req.body.price,
                'createdBy':req.body.createdBy
    
    
            }
            cart.push(product)
            const addCart = `update users set cart = ? where id = ${req.params.id}`
            db.query (addCart, JSON.stringify(cart), (err, results)=>{
                if(err)throw err 
                res.json ({
                    status: 200,
                    message: 'successfully added item'
                })
            })
            } else{
                res.json({
                    status: 404,
                    message: 'there is no user with that id'
                })
            }
        })
    })

// DELETE WHOLE CART
// router.delete('/users/:id/cart',bodyParser.json(), (req, res)=> {
    // Query
//     const strQry = 
//     `
//         UPDATE users SET cart = null
//         WHERE id = ?;
//         `;
//     db.query(strQry,[req.params.id], (err, data, fields)=> {
//         if(err) throw err;
//         res.send(`${data.affectedRows} rows were affected`);
//     })
// });
// DELETE SPECIFIC ITEM CART
// router.delete('/users/:id/cart/:productId',bodyParser.json(), (req, res)=> {
    // Query
//     const deleteProd = 
//     `
//         SELECT cart FROM users 
//         WHERE id =${req.params.id};
//         `;
//     db.query(deleteProd,[req.params.id], (err, data, fields)=> {
//         if(err) throw err;
//         const deleted = JSON.parse(data[0].cart).filter((cart)=>{
//             return cart.productId != req.params.productId;
//         })
//         deleted.forEach((cart, i)=> {
//             cart.productId = i + 1
//         });
//         const end =
//         `
//         UPDATE users SET cart = ?
//         WHERE id = ${req.params.id}
//         `
//         db.query(end, [JSON.stringify(deleted)], (err,results)=>{
//             if(err) throw err;
//             res.send(`${data.affectedRows} rows were affected`);
//         })
        
//     })
// });
//DELETE SINGLE CART
// router.delete('/users/:id/cart/:cartId', (req,res)=>{
//     const deleteProduct = `
//         SELECT cart FROM users 
//         WHERE id = ?
//     `
//     db.query(deleteProduct, (err,results)=>{
//         if(err) throw err;

//         if(results.length > 0){
//             if(results[0].cart != null){
//                 const result = JSON.parse(results[0].cart).filter((Cart)=>{
//                     return Cart.cart_id != req.params.cartId;
//                 })
//                 result.forEach((cart,i) => {
//                     cart.cart_id = i + 1
//                 });
//                 const query = `
//                     UPDATE users 
//                     SET cart = ? 
//                     WHERE id = ?
//                 `;

//                 db.query(query, [JSON.stringify(result)], (err,results)=>{
//                     if(err) throw err;
//                     res.json({
//                         status:200,
//                         result: "Successfully deleted the selected item from cart"
//                     });
//                 })

//             }else{
//                 res.json({
//                     status:400,
//                     result: "This user has an empty cart"
//                 })
//             }
//         }else{
//             res.json({
//                 status:400,
//                 result: "There is no user with that id"
//             });
//         }
//     })

// })

// DELETE CART
router.delete('/users/:id/cart', (req,res)=>{
    const deleteCart = `
        SELECT cart FROM users
        WHERE id = ${req.params.id}
    `
    db.query(deleteCart, (err,results)=>{
        if(err) throw err;
        if(results.length >0){
            const query = `
                UPDATE users
                SET cart = null
                WHERE id = ${req.params.id}
            `
            db.query(query,(err,results)=>{
                if(err) throw err
                res.json({
                    status:200,
                    results: `Your Cart Is Empty`
                })
            });
        }else{
            res.json({
                status:400,
                result: `There is no user with that ID`
            });
        }
    })
  })
//   router.delete('/users/:id/cart/:cartId', (req,res)=>{
//         const deleteSingleCart = `
//             SELECT cart FROM users
//             WHERE id = ${req.params.id}
//         `
//         db.query(deleteSingleCart, (err,results)=>{
//             if(err) throw err;
//             if(results.length > 0){
//                 if(results[0].cart != null){
//                     const result = JSON.parse(results[0].cart).filter((cart)=>{
//                         return cart.cart_id != req.params.cartId;
//                     })
//                     result.forEach((cart,i) => {
//                         cart.cart_id = i + 1
//                     });
//                     const query = `
//                         UPDATE users
//                         SET cart = ?
//                         WHERE id = ${req.params.id}
//                     `
//                     db.query(query, [JSON.stringify(result)], (err,results)=>{
//                         if(err) throw err;
//                         res.json({
//                             status:200,
//                             result: "Your Product Has Been Taken Out of Your Cart"
//                         });
//                     })
//                 }else{
//                     res.json({
//                         status:400,
//                         result: "You have no Products in Your Cart"
//                     })
//                 }
//             }else{
//                 res.json({
//                     status:400,
//                     result: "There is no user with that id"
//                 });
//             }
//         })
//   })
 
module.exports = {
    devServer: {
        Proxy: '*'
    }
}

