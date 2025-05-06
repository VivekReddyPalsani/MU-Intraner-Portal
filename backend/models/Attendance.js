const mongoose = require("mongoose");

const attendanceSchema = new mongoose.Schema({
  date: { type: String, required: true },
  subject: { type: String, required: true },
  time: { type: String, required: true },
  classroom: { type: String, required: true },
  branch: { type: String, required: true },
  year: { type: Number, required: true },
  facultyEmail: { type: String, required: true },
  presentStudents: [{ type: String }] // array of roll numbers
});
// ✅ Add compound unique index
attendanceSchema.index({
    facultyEmail: 1,
    date: 1,
    subject: 1,
    time: 1,
    classroom: 1,
    branch: 1,
    year: 1
  }, { unique: true });
  
module.exports = mongoose.model("Attendance", attendanceSchema);
