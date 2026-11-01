
import express from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import {
  findByUsername,
  findById,
  getWatchlist,
  addMovie,
  updateMovie,
  deleteMovie
} from "./utils/db.js";

import { authenticate } from "./middleware/authenticate.js";
import { authorizeModification } from "./middleware/authorize.js";

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();

app.use(helmet());
app.use(express.json());

// HOME ROUTE
app.get("/", (req, res) => {
  res.send("Family Movie Watchlist API");
});

// Resolve numeric or string user IDs
function resolveUserId(rawId) {
  if (findById(rawId)) {
    return rawId;
  }

  const numericId = Number(rawId);

  if (
    rawId.trim() !== "" &&
    Number.isFinite(numericId) &&
    findById(numericId)
  ) {
    return numericId;
  }

  return rawId;
}

// LOGIN ROUTE
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required."
    });
  }

  const user = findByUsername(username);

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials."
    });
  }

  const validPassword = await bcrypt.compare(
    password,
    user.passwordHash
  );

  if (!validPassword) {
    return res.status(401).json({
      error: "Invalid credentials."
    });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({
      error: "JWT secret is not configured."
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );

  return res.status(200).json({ token });
});

// AUTHENTICATION FOR ALL WATCHLIST ROUTES
app.use("/api/watchlist", authenticate);

// GET WATCHLIST
app.get("/api/watchlist/:userId", (req, res) => {
  const userId = resolveUserId(req.params.userId);

  const watchlist = getWatchlist(userId);

  if (watchlist === null) {
    return res.status(404).json({
      error: "User not found."
    });
  }

  return res.status(200).json(watchlist);
});

// ADD MOVIE
app.post(
  "/api/watchlist/:userId/movies",
  authorizeModification,
  (req, res) => {
    const userId = resolveUserId(req.params.userId);

    const movie = addMovie(userId, req.body);

    if (movie === null) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    return res.status(201).json(movie);
  }
);

// UPDATE MOVIE
app.put(
  "/api/watchlist/:userId/movies/:movieId",
  authorizeModification,
  (req, res) => {
    const userId = resolveUserId(req.params.userId);
    const movieId = Number(req.params.movieId);

    const movie = updateMovie(
      userId,
      movieId,
      req.body
    );

    if (movie === null) {
      return res.status(404).json({
        error: "Movie not found."
      });
    }

    return res.status(200).json(movie);
  }
);

// DELETE MOVIE
app.delete(
  "/api/watchlist/:userId/movies/:movieId",
  authorizeModification,
  (req, res) => {
    const userId = resolveUserId(req.params.userId);
    const movieId = Number(req.params.movieId);

    const deleted = deleteMovie(userId, movieId);

    if (deleted === null) {
      return res.status(404).json({
        error: "Movie not found."
      });
    }

    return res.status(200).json({
      message: "Movie deleted successfully."
    });
  }
);

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}...`);
});
