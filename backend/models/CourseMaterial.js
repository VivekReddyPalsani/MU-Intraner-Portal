const mongoose = require('mongoose');

const CourseMaterialSchema = new mongoose.Schema({
    subjectCode: String,
    subjectName: String,
    facultyId: String,
    facultyName: String,
    filename: String,
    filepath: String,
    uploadDate: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('CourseMaterial', CourseMaterialSchema);
