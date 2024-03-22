// const { decodeBase64 } = require("bcryptjs");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

exports.register = (req, res) => {
    console.log(req.body);

    // const name = req.body.name;
    // const email = req.body.email;
    // const password = req.body.password;
    // const passwordConfirm = req.body.passwordConfirm;

    // OR
    const {name, email, password, passwordConfirm } = req.body;

    db.query("SELECT email FROM users WHERE email = ?", [email], async (error, results) =>{
        if (error){
            console.log(error);
        }

        if(results.length > 0){
            return res.render('register', {
                message: "That email is already in use!"
            })
        }else if(password !== passwordConfirm){
            return res.render('register', {
                message: "Password do not match!"
            })
        }

        let hashedPassword = await bcrypt.hash(password, 8);
        console.log(hashedPassword);

        db.query('INSERT INTO users SET ?', {name: name, email: email, password: hashedPassword}, (error, results) =>{
            if(error){
                console.log(error);
            }else{
                console.log(results);
                return res.render('register', {
                    message: "User Registered!"
                })
            }
        })
    }) 

    // res.send("Form Submitted");
}


//LOGIN (AUTHENTICATE USER)
exports.login =  (req, res)=> {
    const email = req.body.email;
    const password = req.body.password;

    db.getConnection ( async (err, connection)=> {
     if (err) throw (err)
     const sqlSearch = "Select * from users where email = ?"
     const search_query = mysql.format(sqlSearch,[email])
     await connection.query (search_query, async (err, result) => {
      connection.release()
      
      if (err) throw (err)
      if (result.length == 0) {
       console.log("--------> User does not exist")
       res.sendStatus(404)
      } 
      else {
         const hashedPassword = result[0].password
         //get the hashedPassword from result
        if (await bcrypt.compare(password, hashedPassword)) {
        console.log("---------> Login Successful")
        return res.render('register', {
            message: "Login Successful!"
        })
        } 
        else {
        console.log("---------> Password Incorrect")
        // res.send("Password incorrect!")
        return res.render('register', {
            message: "Password Incorrect!"
        })
        } //end of bcrypt.compare()
      }//end of User exists i.e. results.length==0
     }) //end of connection.query()
    }) //end of db.connection()
    } //end of app.post()
    