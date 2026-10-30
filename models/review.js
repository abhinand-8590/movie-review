const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    movieTitle: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },

    reviewerName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 60
    },

    genre: {
      type: String,
      required: true,
      enum: [
        "Action",
        "Drama",
        "Sci-Fi",
        "Thriller",
        "Adventure",
        "Comedy",
        "Romance",
        "Animation"
      ]
    },

    year: {
      type: Number,
      required: true,
      min: 1888,
      max: 2100
    },

    poster: {
      type: String,
      trim: true,
      default: ""
    },

    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5
    },

    reviewText: {
      type: String,
      required: true,
      trim: true,
      minlength: 5,
      maxlength: 1500
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("Review", reviewSchema);