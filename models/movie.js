const mongoose = require("mongoose");

const movieSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true
    },

    description: {
      type: String,
      required: true
    },

    genre: {
      type: [String],
      default: []
    },

    releaseYear: {
      type: Number
    },

    language: {
      type: String,
      default: "Malayalam"
    },

    averageRating: {
      type: Number,
      default: 0
    },

    reviewCount: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("movie", movieSchema);