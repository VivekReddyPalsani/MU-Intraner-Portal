const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    facultyName: { type: String, required: true },
    // Change required: true to required: false
    facultyId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: false },
    rating: { type: Number, required: true, min: 1, max: 5 },
    reviewText: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Review", reviewSchema);