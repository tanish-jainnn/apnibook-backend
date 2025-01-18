const connectToMongo = require('./db');
connectToMongo();
const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.port || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Available Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/notes', require('./routes/notes'));

// Starting the server
app.listen(port, () => {
  console.log(`iNotebook Backend listening on port ${port}`);
});
