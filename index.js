const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");

const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");

// Create an express server
const app = express();

// Initialise the DB
const db = new JsonDB(new Config("2factorDB", true, false, "/"));

// To get data in JSON format
app.use(express.json());

// Test route
app.get("/api", async (req, res) => {
  return res.json({ success: true, message: "API Running" });
});

// Register user and create a temp secret
app.post("/api/register", async (req, res) => {
  const id = uuid.v4();

  try {
    const path = `/user/${id}`;
    const temp_secret = speakeasy.generateSecret();
    db.push(path, { id, temp_secret });

    return res.json({ id, secret: temp_secret.base32 });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Verify token and make secret permanent
app.post("/api/verify", async (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });
    console.log(verified, secret, userId, token);
    if (verified) {
      // Update user data
      db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});

// Validate tokens
app.post("/api/validate", (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user });
    const { base32: secret } = user.secret;
    // Returns true if the token matches
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });
    if (tokenValidates) {
      res.json({ validated: true });
    } else {
      res.json({ validated: false });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error retrieving user" });
  }
});

// Starting the server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
