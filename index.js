import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

import { createClient as createSupabaseClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
const port = process.env.X_ZOHO_CATALYST_LISTEN_PORT || process.env.PORT;

/*const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();*/

// Initialize Supabase client
const supabase = createSupabaseClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // Allow all origins (for testing)
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.status(204).send(); // Respond to preflight request
  }

  next();
});
app.get(``, async (req, res) => {
  console.log("Welcome page");

  res.json("Hello");
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    console.log("No token provided"); // Log if no token is found
    return res.sendStatus(403); // Forbidden if no token
  }

  // Strip the "Bearer " prefix
  const tokenWithoutBearer = token.split(" ")[1];

  if (!tokenWithoutBearer) {
    console.log("Token format is incorrect"); // Log incorrect token format
    return res.sendStatus(403); // Forbidden if token format is incorrect
  }

  // Log the token being passed
  console.log("Token received:", tokenWithoutBearer);

  jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Token verification failed:", err); // Log token verification failure
      return res.sendStatus(403); // Forbidden if verification fails
    }

    // Log the decoded token
    console.log("Decoded user:", user);

    req.user = user;
    next();
  });
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role }, // Payload with user data
    process.env.JWT_SECRET, // Secret key (ensure this is set in .env)
    { expiresIn: "1h" } // Token expiration time
  );
}

// 1. User Registration
app.post(`/register`, async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    // Inserting data into the 'Users' table
    const { data, error } = await supabase
      .from("users")
      .insert([{ username, password: hashedPassword, role }])
      .select("id"); // You need to select the 'id' after inserting

    if (error) {
      throw error; // If there's an error, throw it
    }

    // Return the user ID in the response
    res.status(201).json({ id: data[0].id });
    res.header("Access-Control-Allow-Origin", req.headers.origin);
  } catch (err) {
    // Handle any errors that might occur
    res.status(400).json({ error: err.message });
  }
});

// 2. User Login
app.post(`/login`, async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validate username with the database
    const { data, error } = await supabase
      .from("users") // Replace with your actual table name
      .select("*")
      .eq("username", username) // Check if the username matches
      .single(); // Get only a single user if matched

    if (error) {
      throw error; // Handle the error if user is not found or any other error
    }

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, data.password);
    if (isMatch) {
      // Generate a JWT token with user id and role
      const token = generateToken(data);

      // Send response with token, id, and role
      res.status(200).json({
        token,
        id: data.id,
        role: data.role,
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// 3. Create Quiz Question (Teacher Only)
app.post(`/quiz`, authenticateToken, async (req, res) => {
  if (req.user.role !== "Teacher")
    return res.status(403).json({ message: "Access denied" });

  const { question, option_a, option_b, option_c, option_d, correct_option } =
    req.body;
  const teacherId = req.user.id;

  try {
    // Insert the question data into the "Questions" table
    const { data: result, error } = await supabase
      .from("questions") // The name of your table in Supabase
      .insert([
        {
          question,
          option_a,
          option_b,
          option_c,
          option_d,
          correct_option,
          teacher_id: teacherId, // Ensure column names match exactly
        },
      ])
      .select("id"); // Fetch only the "id" field

    if (error) {
      throw error; // Handle any error
    }

    // Send response with the id of the inserted question
    res.status(201).json({ id: result[0].id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 4. Get Quiz Questions (For Students)
app.get(`/quiz/questions`, async (req, res) => {
  try {
    // Fetch 5 random questions from the "Questions" table
    const { data, error } = await supabase
      .from("questions") // The name of your table in Supabase
      .select("*") // Select all columns
      .order("id", { ascending: true }) // Ensuring order by a column first
      .limit(5); // Limit to 5 questions

    if (error) {
      throw error; // Handle any error from Supabase
    }

    // Send the response with the randomly selected questions
    res.json(data);
  } catch (err) {
    console.error("Error fetching quiz questions:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch quiz questions. Please try again." });
  }
});

// 5. Submit Quiz and Get Results (For Students)
app.post(`/submit`, authenticateToken, async (req, res) => {
  const { answers } = req.body;
  let score = 0;

  try {
    // Fetch questions based on the answers' IDs using Supabase
    const { data: questions, error: questionsError } = await supabase
      .from("questions")
      .select("*")
      .in(
        "id",
        answers.map((ans) => ans.id)
      ); // Fetch questions with IDs in the provided answers

    if (questionsError) {
      throw questionsError; // Handle any error while fetching questions
    }

    // Iterate through answers and check if they are correct
    answers.forEach((ans) => {
      const question = questions.find((q) => q.id === ans.id);
      if (question && question.correct_option === ans.selectedOption) {
        score += 1;
      }
    });

    // Insert the result in the Results table
    const { error: resultError } = await supabase.from("results").insert([
      {
        student_id: req.user.id, // Assuming the logged-in user's ID is available in req.user.id
        score,
      },
    ]);

    if (resultError) {
      throw resultError; // Handle any error while inserting the result
    }

    // Send the score back in the response
    res.json({ score });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all students
async function getStudents() {
  try {
    // Fetch users with role 'Student' from Supabase
    const { data: students, error } = await supabase
      .from("users") // Specify the table
      .select("id, username") // Select only the id and username columns
      .eq("role", "Student"); // Filter by role 'Student'

    if (error) {
      throw error; // Handle any error
    }

    return students; // Return the fetched student data
  } catch (err) {
    console.error("Error fetching students:", err);
    throw new Error("Unable to fetch students");
  }
}

app.get(`/teacher-dashboard`, async (req, res) => {
  try {
    // Fetch students and top student data from your database
    const students = await getStudents(); // Replace with actual DB call

    res.json({ students });
  } catch (err) {
    console.error("Error in /teacher-dashboard route:", err);
    res.status(500).json({ error: "Unable to fetch teacher dashboard data" });
  }
});

// Add new question route
app.post(`/add-question`, async (req, res) => {
  const {
    question,
    option_a,
    option_b,
    option_c,
    option_d,
    correct_option,
    teacher_id,
  } = req.body;

  console.log(teacher_id);

  if (!teacher_id) {
    return res.status(400).json({ error: "Teacher ID is required." });
  }

  try {
    // Insert the new question into the 'questions' table in Supabase
    const { data, error } = await supabase
      .from("questions") // Specify the 'questions' table
      .insert([
        {
          question,
          option_a,
          option_b,
          option_c,
          option_d,
          correct_option,
          teacher_id,
        },
      ])
      .single(); // Use .single() to return only one row

    // Check for errors
    if (error) {
      throw error;
    }

    res.json({ question: data }); // Return the inserted question data
  } catch (err) {
    console.error("Error adding question:", err);
    res.status(500).send("Server Error");
  }
});

app.get(`/questions`, authenticateToken, async (req, res) => {
  try {
    // Check if the user is a Teacher
    if (req.user.role !== "Teacher") {
      console.log("Unauthorized role:", req.user.role); // Log unauthorized role
      return res
        .status(403)
        .json({ error: "You are not authorized to view the questions." });
    }

    console.log("Fetching questions for teacher ID:", req.user.id); // Log teacher ID

    // Fetch the questions from Supabase for the authenticated teacher
    const { data, error } = await supabase
      .from("questions") // Specify the 'questions' table
      .select(
        "id, question, option_a, option_b, option_c, option_d, correct_option"
      ) // Select the necessary columns
      .eq("teacher_id", req.user.id); // Filter by teacher_id

    // Check for errors
    if (error) {
      console.error("Error fetching questions:", error);
      return res.status(500).json({ error: "Unable to fetch questions" });
    }

    console.log("Fetched questions:", data); // Log the fetched questions

    res.json(data); // Return the fetched questions
  } catch (err) {
    console.error("Error fetching questions:", err);
    res.status(500).json({ error: "Unable to fetch questions" });
  }
});

app.put(`/update-question/:id`, async (req, res) => {
  const { id } = req.params;
  const { question, option_a, option_b, option_c, option_d, correct_option } =
    req.body;

  try {
    // Update the question in the database using Supabase
    const { data, error } = await supabase
      .from("questions") // Specify the 'questions' table
      .update({
        question,
        option_a,
        option_b,
        option_c,
        option_d,
        correct_option,
      })
      .eq("id", id) // Filter by question ID
      .single(); // Only return the updated row

    // Check for errors
    if (error) {
      console.error("Error updating question:", error);
      return res.status(500).json({ error: "Unable to update question" });
    }

    res.json(data); // Return the updated question
  } catch (err) {
    console.error("Error updating question:", err);
    res.status(500).json({ error: "Unable to update question" });
  }
});

app.delete(`/delete-question/:id`, async (req, res) => {
  const { id } = req.params;

  try {
    // Delete the question from the 'questions' table using Supabase
    const { data, error } = await supabase
      .from("questions") // Specify the 'questions' table
      .delete()
      .eq("id", id); // Filter by question ID

    // Check for errors
    if (error) {
      console.error("Error deleting question:", error);
      return res.status(500).json({ error: "Unable to delete question" });
    }

    // Check if the question was found and deleted
    if (data.length === 0) {
      return res.status(404).json({ message: "Question not found" });
    }

    res.status(200).json({ message: "Question deleted successfully" });
  } catch (err) {
    console.error("Error deleting question:", err);
    res.status(500).json({ error: "Unable to delete question" });
  }
});

app.get(`/quiz/questions`, authenticateToken, async (req, res) => {
  try {
    // Check if the user is a Student
    if (req.user.role !== "Student") {
      return res
        .status(403)
        .json({ error: "Only students can attempt quizzes." });
    }

    // Fetch random questions for a quiz from the 'questions' table
    const { data, error } = await supabase
      .from("questions") // Table name in Supabase
      .select("id, question, option_a, option_b, option_c, option_d") // Columns to fetch
      .order("RANDOM") // Order by random
      .limit(5); // Limit to 5 questions

    // Handle errors
    if (error) {
      console.error("Error fetching quiz questions:", error);
      return res.status(500).json({ error: "Unable to fetch quiz questions" });
    }

    // Send the fetched questions in the response
    res.json(data);
  } catch (err) {
    console.error("Error fetching quiz questions:", err);
    res.status(500).json({ error: "Unable to fetch quiz questions" });
  }
});

app.post(`/quiz/submit`, authenticateToken, async (req, res) => {
  const { answers } = req.body; // Array of { questionId, selectedOption }
  const studentId = req.user.id;

  try {
    let score = 0;

    // Validate and calculate score
    for (const answer of answers) {
      const { questionId, selectedOption } = answer;

      // Fetch correct option for the question from the 'questions' table
      const { data: questionData, error: questionError } = await supabase
        .from("questions")
        .select("correct_option")
        .eq("id", questionId)
        .single(); // Fetch a single row

      if (questionError || !questionData) {
        return res.status(400).json({ error: "Invalid question ID" });
      }

      const correctOption = questionData.correct_option;
      const isCorrect = correctOption === selectedOption;
      if (isCorrect) score++;

      // Insert the result into the 'results' table
      const { error: insertError } = await supabase.from("results").upsert(
        {
          student_id: studentId,
          question_id: questionId,
          selected_option: selectedOption,
          is_correct: isCorrect,
          score: score,
          quiz_id: 1, // Adjust as needed (this can be dynamic based on the quiz context)
        },
        { onConflict: ["student_id", "question_id"] } // Prevent inserting duplicate results for the same question
      );

      if (insertError) {
        console.error("Error inserting result:", insertError);
        return res.status(500).json({ error: "Unable to submit quiz result" });
      }
    }

    res.json({ message: "Quiz submitted successfully", score });
  } catch (err) {
    console.error("Error submitting quiz:", err);
    res.status(500).json({ error: "Unable to submit quiz" });
  }
});

// Express route for checking quiz status
app.get(`/quiz/status`, authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id; // Assuming you have user authentication logic

    // Fetch the quiz completion status for the user
    const { data, error } = await supabase
      .from("users") // Table name
      .select("quiz_completed") // Column to check
      .eq("id", userId) // Filter by the user ID
      .single(); // Only expecting a single row

    if (error) {
      throw error; // Handle any errors from Supabase
    }

    if (data && data.quiz_completed) {
      res.json({ quizCompleted: true });
    } else {
      res.json({ quizCompleted: false });
    }
  } catch (error) {
    console.error("Error checking quiz status:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Backend (Node.js + Express) - Example of how you can update the quiz completion status
app.post(`/quiz/complete`, async (req, res) => {
  const { userId } = req.body; // Ensure you're passing the user ID (from the token or session)

  try {
    // Update the quiz_completed field for the user
    const { data, error } = await supabase
      .from("users") // The table you're working with
      .update({ quiz_completed: true }) // Set quiz_completed to true
      .eq("id", userId); // Identify the user by their ID

    // Check for errors in the update
    if (error) {
      throw error; // If there's an error, throw it to be handled by the catch block
    }

    // If successful, send a success response
    res.status(200).json({ message: "Quiz completion status updated." });
  } catch (err) {
    console.error("Error updating quiz status:", err);
    res.status(500).json({ error: "Failed to update quiz status." });
  }
});

app.get(`/student-performance`, async (req, res) => {
  try {
    // Fetch results and user details separately
    const { data: results, error: resultsError } = await supabase
      .from("results")
      .select("student_id, is_correct, updated_at, users(username)")
      .eq("users.role", "Student")
      .order("student_id", { ascending: true });

    if (resultsError) {
      throw resultsError;
    }

    // Manually aggregate the data
    const studentPerformance = results.reduce((acc, result) => {
      const { student_id, is_correct, updated_at, users } = result;
      const username = users.username;

      if (!acc[student_id]) {
        acc[student_id] = {
          username, // Username included here
          total_score: 0,
          last_attempt: updated_at,
        };
      }

      // Aggregate score
      acc[student_id].total_score += is_correct ? 1 : 0;

      // Track the latest attempt
      if (new Date(updated_at) > new Date(acc[student_id].last_attempt)) {
        acc[student_id].last_attempt = updated_at;
      }

      return acc;
    }, {});

    // Convert to array format to send as JSON
    const resultArray = Object.values(studentPerformance);

    // Send aggregated results, which include username
    res.json(resultArray);
  } catch (err) {
    console.error("Error fetching student performance:", err);
    res.status(500).send("Server error");
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
