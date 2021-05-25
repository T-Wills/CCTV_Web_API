require("dotenv").config();

const express = require("express");
const app = express();
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const { validationResult } = require("express-validator");
const { validateConfirmPassword } = require("./password-validation");
const {BlobServiceClient} = require("@azure/storage-blob");

//email account activation
const mailgun = require("mailgun-js");
const DOMAIN = "sandboxd31307388f914d4db3d7dac58d4795db.mailgun.org";
const mg = mailgun({ apiKey: process.env.MAILGUN_APIKEY, domain: DOMAIN });

const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING;
const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_STORAGE_CONNECTION_STRING);

//server port
const port = process.env.PORT || 3030;

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "cctvdb",
});

db.connect = (error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Database Connected!");
  }
};

//middleware
app.use(cors());
app.use(express.json());

// Parsers to POST data
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: false, limit: "20mb" }));

//Jwt middleware to verify token
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  //get token
  const token = authHeader.split(" ")[1];

  if (token == null) {
    res.send("token is needed");
  } else {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, id) => {
      if (err) {
        res.json({
          auth: false,
          message: "authentication failed",
        });
      } else {
        //save decoded id into variable, req.userid
        req.id = id;
        next();
      }
    });
  }
};


//APIs

/*................Email account Activativation on user signup ..............*/
app.post("/signup", (req, res) => {

  const {firstname,lastname,gender,dateofbirth,username,email,password,confirmpassword} = req.body;

  //check if user exists in the db
  const sqlSelect = "SELECT * FROM personinfo WHERE email = ?";
  db.query(sqlSelect, email, (err, result) => {
    const count = result.length;
    if (count > 0) {
      res.status(400).json({ message: "user with this email already exist" });
    }
    const token = jwt.sign({firstname,lastname,gender,dateofbirth,username,email,password,confirmpassword}, process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "20m",
      }
    );
    const data = {
      from: "noreply@helloworld.com",
      to: email,
      subject: "Account Activation Link",
      html: `
            <h3>Kindly click on the link to activate your account</h3>
            <p><a href="${process.env.CLIENT_URL}/authentication/activate/${email}">${token}</a></p>
        `,
    };
    mg.messages().send(data, function (error, body) {
      if (error) {
        return res.json({
          error: err.message,
        });
      }
      return res.json({
        message: "Email has been sent, please activate your account",
      });
    });
  });
});

/*................Create new user..............*/
app.post("/activateaccount/:id", [validateConfirmPassword], (req, res) => {
  //password validation
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(401);
  }

  const { token } = req.body;

  if (token) {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decodedToken) => {
      if (err) {
        res.json({
          message: "Incorrect or Expired link",
        });
      }

      const {firstname,lastname,gender,dateofbirth,username,email,password,confirmpassword} = decodedToken;
      //password encryption
      const hash = bcrypt.hashSync(password, saltRounds, 8);

      //check if user exists in the db
        const sqlSelect = "SELECT * FROM personinfo WHERE email = ?";
        db.query(sqlSelect, email, (err, result) => {
          const count = result.length;
          if (count > 0) {
            return res
              .status(400)
              .json({ message: "user with this email already exist" });
            } 

            //add new user to the db
            const sqlInsert = "INSERT INTO personinfo (firstname, lastname, gender, dateofbirth, username, email, password, confirmpassword) VALUES (?,?,?,?,?,?,?,?)";
            db.query(sqlInsert,[firstname,lastname,gender,dateofbirth,username,email,hash,hash,], (err, result) => {
                if (!err) {
                    res.json({ message: "signup successful" });
                    console.log(confirmpassword);
                } else {
                    console.log(err);
                    res.status(400), json({ error: "Error activating account" });
                }
            });
        });
    });
  } else {
    console.log(err);
    return res.json({ error: "something went wrong" });
  }
});


/* .............token verification.............. */
app.get("/verifyToken", verifyJWT, (req, res, err) => {
  if (res) {
    res.send("verified");
  }
  console.log(res);
});


/*........Check if user is authenticated.......*/
app.post("/isUserAuth", verifyJWT, (req, res, err) => {
    const id = req.id;
    //convert id to json string
    const convertedIdToString = JSON.stringify(id);
    //convert the converted string to an object
    const convertedStringIdToObject = JSON.parse(convertedIdToString);
    //store the json object into variable
    const resultId = convertedStringIdToObject.id;
    const sqlSelect = "SELECT * FROM personinfo WHERE email = ?";
    db.query(sqlSelect, resultId, (err, result) => {
        if (!err) {
            res.send("user is authenticated");
        }else {
            res.send("user is not authenticated");
       }
  });
});

/*................Login with user token for authentication...............*/
app.post("/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  //check if user exists in the db
  const sqlSelect = "SELECT * FROM personinfo WHERE email = ?;";
  db.query(sqlSelect, email, (err, result) => {
    if (err) {
      res.send({ err: err });
    }
    console.log(err);

    if (result.length > 0) {
      console.log(result);
      //compare pwd to check if inputed pwd = hashed pwd in db
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (response) {
          const id = result[0].email;
          const token = jwt.sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: 6000,
          });
          res.json({ auth: true, token: token, id, result: result });
        } else {
          res.json({ auth: false, message: "incorrect password" });
        }
      });
    } else {
      res.json({
        message: "user doesn't exist",
      });
    }
  });
});

/*................Forgot password ..............*/
app.put("/forgotpassword", (req, res) => {
    const { email } = req.body;
  
    //check if user exists in the db
    const sqlSelect = "SELECT * FROM personinfo WHERE email = ?";
    db.query(sqlSelect, email, (err, user) => {
        console.log(err)
      if (err || !user) {
        res.status(400).json({ message: "user with this email does not exist" });
      }

       const token = jwt.sign({ _id: user._id}, process.env.RESET_PASSWORD_TOKEN_SECRET, {expiresIn: "20m"});
        const data = {
        from: "noreply@helloworld.com",
        to: email,
        subject: "Reset Password Link",
        html: `
              <h3>Reset password link</h3>
              <p><a href="${process.env.CLIENT_URL}/resetpassword/${email}">${token}</a></p>
          `,
        };

        //updating user token which is a link into the db
        return db.query(`UPDATE personinfo SET resetpasswordlink="'${token}'" WHERE email = ?`, [ email ], (err, successs) => {
            if(err){
                console.log(err);
                res.status(400).json({ error: "reset password link error" });
            }else{
                mg.messages().send(data, function (error, body) {
                    if (error) {
                      return res.json({
                        error: err.message,
                      });
                    }
                    console.log(token)
                    return res.status(200).json({
                      message: "Email has been sent, please follow the instruction",
                    });
                   
                });
            }
        }
      
    )});
});

/*................Reset password ..............*/
app.put("/resetpassword", (req, res) => {
    const {  password, confirmpassword, resetpasswordlink, email } = req.body;
    const hash = bcrypt.hashSync(password, saltRounds, 8);

    //check if user exists in the db
    if (resetpasswordlink) {
        jwt.verify(resetpasswordlink, process.env.RESET_PASSWORD_TOKEN_SECRET, (error, decodedData) => {
            if (error) {
                return res.status(401).json({
                  error: "incorrect or expired token",
                });
            }
            const sqlSelect = "SELECT * FROM personinfo WHERE resetpasswordlink = ?";
            db.query(sqlSelect, resetpasswordlink, (err, result) => {
              if (err || !result) {
                res.status(400).json({ message: "user with this token does not exist" });
              }
             //update password and confirmpassword fields with new password
              db.query(`UPDATE personinfo SET password = ?, confirmpassword=? WHERE email=? `, [  hash, hash, email ], (err, result) => {
                console.log(password)
                console.log(confirmpassword)
                if(err){
                    console.log(err)
                    res.status(400).json({ error: "reset password error" });
                  }else{
                        console.log(result)
                        res.status(200).json({
                           message: "Your password has been changed",
                        });
                    }
              })
            
            })
        })
      }else{
        res.status(400).json({error: "authentication error" });
    }
});

/*................Get blob Videos ..............*/
app.get("/getblobvideos", (req, res)=>{
  const blobServiceClient = new BlobServiceClient(
    `https://teeblob.blob.core.windows.net/videos`,
    AZURE_STORAGE_CONNECTION_STRING
  );

  const containerName = "videos";
  const blobName = "teeblob";

  async function main(){
    const containerClient = blobServiceClient.getContainerClient(containerName);
    const blobClient = containerClient.getBlobClient(blobName);
  
    // Get blob content from position 0 to the end
    // In Node.js, get downloaded data by accessing downloadBlockBlobResponse.readableStreamBody
    const downloadBlockBlobResponse = await blobClient.download();
    const downloaded = (
      await streamToBuffer(downloadBlockBlobResponse.readableStreamBody)
    ).toString();
    res.status(200).json({
      message:`download successful, ${downloaded}`
    })
    console.log("Downloaded blob content:", downloaded);

    // [Node.js only] A helper method used to read a Node.js readable stream into a Buffer
   /*  async function streamToBuffer(readableStream) {
      return new Promise((resolve, reject) => {
        const chunks = [];
        readableStream.on("data", (data) => {
          chunks.push(data instanceof Buffer ? data : Buffer.from(data));
        });
        readableStream.on("end", () => {
          resolve(Buffer.concat(chunks));
        });
        readableStream.on("error", reject);
      });
    } */
  }

  main();
})





/* ..............Server Setup.............. */
app.listen(port, () => {
  console.log("running on port 3030");
});
