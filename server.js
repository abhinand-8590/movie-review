const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;

const Movie = require("./models/movie");
const Review = require("./models/review");
const User = require("./models/user");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(express.static(__dirname + "/pics"));
app.use(
  session({
    name: "cinescope.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "sessions",
      ttl: 60 * 60 * 24, // 1 day
    }),
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB connected successfully!");
  })
  .catch((error) => {
    console.error("MongoDB connection failed:", error.message);
  });

// Homepage
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/home", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.get("/admin", (req, res) => {
  res.sendFile(__dirname + "/public/admin.html");
});


async function requireAdmin(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "Please log in first."
      });
    }

    const user = await User.findById(req.session.userId)
      .select("role");

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        message: "Admin access required."
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      message: "Unable to verify admin access."
    });
  }
}

// Keep /api/me consistent with the admin page
app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "Not logged in."
      });
    }

    const user = await User.findById(req.session.userId)
      .select("name email role");

    if (!user) {
      return res.status(401).json({
        message: "User account not found."
      });
    }

    res.json({
      loggedIn: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Unable to check login status."
    });
  }
});
// REGISTER API
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Please provide your name, email and password.",
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 100) {
      return res.status(400).json({
        message: "Name must be between 2 and 100 characters.",
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    // bcrypt uses a maximum input length of 72 bytes
    if (
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        message: "Password must be at least 8 characters and no more than 72 UTF-8 bytes.",
      });
    }

    if (
      confirmPassword !== undefined &&
      password !== confirmPassword
    ) {
      return res.status(400).json({
        message: "Passwords do not match.",
      });
    }

    const existingUser = await User.findOne({ email: cleanEmail });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: cleanName,
      email: cleanEmail,
      password: hashedPassword,
      role: "user"
    });

    return res.status(201).json({
      message: "Registration successful! You can now log in.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      message: "Registration failed. Please try again." + error.message,
    });
  }
});

// LOGIN API
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const user = await User.findOne({ email: cleanEmail })
      .select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    // Regenerate session ID after authentication
    req.session.regenerate((error) => {
      if (error) {
        console.error("Session error:", error.message);

        return res.status(500).json({
          message: "Unable to start your session.",
        });
      }

      req.session.userId = user._id.toString();

      // Save before returning the response
      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);

          return res.status(500).json({
            message: "Unable to save your session.",
          });
        }

        return res.status(200).json({
          message: "Login successful.",
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
          },
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "Unable to log in. Please try again.",
    });
  }
});

// CHECK LOGIN STATUS API
app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "You are not logged in.",
      });
    }

    const user = await User.findById(req.session.userId).select(
      "name email"
    );

    if (!user) {
      return req.session.destroy(() => {
        res.clearCookie("cinescope.sid", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "lax",
          path: "/",
        });

        res.status(401).json({
          message: "Session expired. Please log in again.",
        });
      });
    }

    return res.json({
      loggedIn: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Session check error:", error.message);

    return res.status(500).json({
      message: "Unable to check login status.",
    });
  }
});

// LOGOUT API
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        message: "Unable to log out. Please try again.",
      });
    }

    res.clearCookie("cinescope.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return res.json({
      message: "Logged out successfully.",
    });
  });
});

// Recalculate a movie's statistics
async function updateMovieStats(title) {
  const matchingReviews = await Review.find({ movieTitle: title });

  const count = matchingReviews.length;
  const average = count
    ? matchingReviews.reduce((sum, review) => sum + review.rating, 0) / count
    : 0;

  await Movie.updateOne(
    { title },
    {
      $set: {
        reviewCount: count,
        averageRating: Number(average.toFixed(2))
      }
    }
  );
}


// Submit a review
app.post("/api/reviews", async (req, res) => {
  try {
    const {
      movieTitle,
      reviewerName,
      genre,
      year,
      poster,
      rating,
      reviewText
    } = req.body;

    // Save the review
    const review = await Review.create({
      movieTitle,
      reviewerName,
      genre,
      year,
      poster,
      rating,
      reviewText
    });

    // Update the corresponding movie's statistics
    const stats = await updateMovieStats(movieTitle);

    res.status(201).json({
      message: "Review submitted successfully!",
      review,
      stats
    });

  } catch (error) {
    console.error("Error saving review:", error);

    res.status(500).json({
      message: "Failed to save review.",
      error: error.message
    });

  }
});

// Fetch all reviews
app.get("/api/reviews", async (req, res) => {
  try {
    const reviews = await Review.find().sort({ createdAt: -1 });

    res.status(200).json(reviews);

  } catch (error) {
    console.error("Error fetching reviews:", error);

    res.status(500).json({
      message: "Failed to fetch reviews",
      error: error.message
    });

  }
});

app.get("/api/reviews/count", async (req, res) => {
  try {
    const count = await Review.countDocuments();

    res.status(200).json({
      count: count
    });

  } catch (error) {
    console.error("Error counting reviews:", error);

    res.status(500).json({
      message: "Failed to count reviews",
      error: error.message
    });
  }
});
// Fetch all movies with updated statistics
app.get("/api/movies", async (req, res) => {
  try {
    const movies = await Movie.find();

    res.status(200).json(movies);


  } catch (error) {
    console.error("Error fetching movies:", error);

    res.status(500).json({
      message: "Failed to fetch movies",
      error: error.message
    });

  }
});

// Protect every admin endpoint using the current session
async function requireAdmin(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "Please log in first."
      });
    }

    const user = await User.findById(req.session.userId)
      .select("role");

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        message: "Admin access required."
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      message: "Unable to verify admin access."
    });
  }
}

// Keep /api/me consistent with the admin page
app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "Not logged in."
      });
    }

    const user = await User.findById(req.session.userId)
      .select("name email role");

    if (!user) {
      return res.status(401).json({
        message: "User account not found."
      });
    }

    res.json({
      loggedIn: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Unable to check login status."
    });
  }
});

// Recalculate stored movie rating/count from matching reviews.
// Your schemas associate reviews with movies by title.
async function updateMovieStats(title) {
  const matchingReviews = await Review.find({ movieTitle: title });

  const count = matchingReviews.length;
  const average = count
    ? matchingReviews.reduce((sum, review) => sum + review.rating, 0) / count
    : 0;

  await Movie.updateOne(
    { title },
    {
      $set: {
        reviewCount: count,
        averageRating: Number(average.toFixed(2))
      }
    }
  );
}

// ---------------- MOVIE CRUD ----------------

// GET all movies
app.get("/api/admin/movies", requireAdmin, async (req, res) => {
  try {
    const movies = await Movie.find().sort({ createdAt: -1 });

    res.json({ movies });
  } catch (error) {
    res.status(500).json({ message: "Failed to load movies." });
  }
});

// ADD movie
app.post("/api/admin/movies", requireAdmin, async (req, res) => {
  try {
    const { title, description, genre, releaseYear, language } = req.body;

    if (
      typeof title !== "string" || !title.trim() ||
      typeof description !== "string" || !description.trim()
    ) {
      return res.status(400).json({
        message: "Title and description are required."
      });
    }

    const movie = await Movie.create({
      title: title.trim(),
      description: description.trim(),
      genre: Array.isArray(genre)
        ? genre
        : typeof genre === "string"
          ? genre.split(",").map(g => g.trim()).filter(Boolean)
          : [],
      releaseYear: releaseYear === "" || releaseYear == null
        ? undefined : Number(releaseYear),
      language: language?.trim() || "Malayalam"
    });

    res.status(201).json({
      message: "Movie added successfully.",
      movie
    });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to add movie."
    });
  }
});

// UPDATE movie
app.put("/api/admin/movies/:id", requireAdmin, async (req, res) => {
  try {
    const { title, description, genre, releaseYear, language } = req.body;

    if (
      typeof title !== "string" || !title.trim() ||
      typeof description !== "string" || !description.trim()
    ) {
      return res.status(400).json({
        message: "Title and description are required."
      });
    }

    const movie = await Movie.findById(req.params.id);

    if (!movie) {
      return res.status(404).json({ message: "Movie not found." });
    }

    const oldTitle = movie.title;

    movie.title = title.trim();
    movie.description = description.trim();
    movie.genre = Array.isArray(genre)
      ? genre
      : typeof genre === "string"
        ? genre.split(",").map(g => g.trim()).filter(Boolean)
        : [];
    movie.releaseYear = releaseYear === "" || releaseYear == null
      ? undefined : Number(releaseYear);
    movie.language = language?.trim() || "Malayalam";

    await movie.save();

    // Keep existing title-based reviews associated after a rename.
    if (oldTitle !== movie.title) {
      await Review.updateMany(
        { movieTitle: oldTitle },
        { $set: { movieTitle: movie.title } }
      );

      await updateMovieStats(oldTitle);
      await updateMovieStats(movie.title);
    } else {
      await updateMovieStats(movie.title);
    }

    res.json({
      message: "Movie updated successfully.",
      movie
    });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to update movie."
    });
  }
});

// DELETE movie and its title-linked reviews
app.delete("/api/admin/movies/:id", requireAdmin, async (req, res) => {
  try {
    const movie = await Movie.findById(req.params.id);

    if (!movie) {
      return res.status(404).json({ message: "Movie not found." });
    }

    await Review.deleteMany({ movieTitle: movie.title });
    await movie.deleteOne();

    res.json({
      message: "Movie and its associated reviews deleted."
    });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to delete movie."
    });
  }
});

// ---------------- REVIEW CRUD ----------------

// GET all reviews
app.get("/api/admin/reviews", requireAdmin, async (req, res) => {
  try {
    const reviews = await Review.find().sort({ createdAt: -1 });

    res.json({ reviews });
  } catch (error) {
    res.status(500).json({ message: "Failed to load reviews." });
  }
});

// ADD review
app.post("/api/admin/reviews", requireAdmin, async (req, res) => {
  try {
    const review = new Review(req.body);
    await review.save();

    await updateMovieStats(review.movieTitle);

    res.status(201).json({
      message: "Review added successfully.",
      review
    });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to add review."
    });
  }
});

// UPDATE review
app.put("/api/admin/reviews/:id", requireAdmin, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return res.status(404).json({ message: "Review not found." });
    }

    const oldTitle = review.movieTitle;

    const allowedFields = [
      "movieTitle", "reviewerName", "genre",
      "year", "poster", "rating", "reviewText"
    ];

    for (const key of allowedFields) {
      if (req.body[key] !== undefined) {
        review.set(key, req.body[key]);
      }
    }

    await review.save();

    await updateMovieStats(oldTitle);

    if (review.movieTitle !== oldTitle) {
      await updateMovieStats(review.movieTitle);
    }

    res.json({
      message: "Review updated successfully.",
      review
    });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to update review."
    });
  }
});

// DELETE review
app.delete("/api/admin/reviews/:id", requireAdmin, async (req, res) => {
  try {
    const review = await Review.findById(req.params.id);

    if (!review) {
      return res.status(404).json({ message: "Review not found." });
    }

    const title = review.movieTitle;

    await review.deleteOne();
    await updateMovieStats(title);

    res.json({ message: "Review deleted successfully." });
  } catch (error) {
    res.status(400).json({
      message: error.message || "Failed to delete review."
    });
  }
});


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
