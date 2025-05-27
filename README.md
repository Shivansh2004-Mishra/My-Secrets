# Secrets Web Application

A secure web application for sharing and managing secrets, built with Node.js, Express, MongoDB, EJS, and JWT authentication. This project demonstrates robust authentication, secure session management, and best practices in web security.

---

## Features

- **User Registration:**  
  - Sign up with name, email, and password  
  - Email and password format validation  
  - Passwords securely hashed with bcrypt

- **Login & Authentication:**  
  - Secure login with JWT-based authentication  
  - HttpOnly cookies for session management  
  - Protected routes for authenticated users

- **Secrets Management:**  
  - Submit multiple secrets per user  
  - View and delete your secrets  
  - User profile with editable profile photo

- **Security:**  
  - JWT for stateless authentication  
  - Secure, HttpOnly cookies  
  - Input validation and error handling

- **UI:**  
  - Responsive and modern UI with Bootstrap and Font Awesome  
  - Clean, user-friendly design

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v16 or higher recommended)
- [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) account (or local MongoDB)

### Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Shivansh2004-Mishra/My-Secrets
   cd My-Secrets
   ```

2. **Install dependencies:**
   ```sh
   npm install
   ```

3. **Set up environment variables:**  
   Create a `.env` file in the root directory:
   ```
   MONGO_URL=your_mongodb_atlas_connection_string
   JWT_SECRET=your_jwt_secret
   PORT=5000
   ```

4. **Run the application:**
   ```sh
   npm start
   ```
   or
   ```sh
   node index.js
   ```

5. **Visit in your browser:**  
   [http://localhost:5000](http://localhost:5000)

---

## Folder Structure

```
├── public/
│   └── css/
│       └── style.css
├── views/
│   ├── partials/
│   ├── login.ejs
│   ├── register.ejs
│   ├── secrets.ejs
│   ├── profile.ejs
│   └── submit.ejs
├── .env
├── .gitignore
├── index.js
└── README.md
```

---

## Deployment

- **Live Demo:** [https://my-secrets-ublk.onrender.com/](https://my-secrets-ublk.onrender.com/)
- Deployable on [Render](https://render.com/) 

---,

## Security Notes

- Never commit your `.env` file or secrets to version control.
- Use strong values for `JWT_SECRET`.
- Restrict MongoDB Atlas IP whitelist in production.

---

## License

This project is licensed for educational purposes.

---

## Author

- [Shivansh Mishra](https://github.com/Shivansh2004-Mishra)

