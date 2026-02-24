# 🏦 VaultSecure Banking — RBAC Demo

A **Role-Based Access Control (RBAC) Banking System** built using Flask.
This project demonstrates secure authentication, authorization, and controlled resource access inside a banking-style application.

It includes:

* JWT authentication
* Role-based permissions
* Account management
* Transaction handling
* Admin controls
* Audit logging
* Modern dashboard UI

This project is ideal for learning **access control systems**, **backend security**, and **full-stack Flask applications**.



## 🚀 Features

### 🔐 Authentication & Security

* JWT-based authentication
* Password hashing using bcrypt
* Session expiration
* Protected API routes
* Account freeze protection

### 👤 Role-Based Access Control (RBAC)

The system supports multiple roles with different permissions:

| Role             | Description              |
| ---------------- | ------------------------ |
| **Super Admin**  | Full system control      |
| **Bank Manager** | User & branch management |
| **Teller**       | Process transactions     |
| **Auditor**      | Read-only audit access   |
| **Customer**     | Personal account access  |

Permissions include:

* View accounts
* Manage users
* Process transactions
* Freeze accounts
* Approve loans
* View reports
* Access audit logs



### 💳 Banking Features

* User registration & login
* Account balance tracking
* Money transfer between accounts
* Transaction history
* Loan approval simulation
* Account freezing/unfreezing



### 🛠 Admin Controls

* Add users
* Delete users
* Change roles
* Freeze accounts
* View all accounts
* View audit logs



### 📊 Dashboard

* Real-time stats
* Transaction records
* Role-based UI views
* Activity logs
* Account overview



## 🏗 Project Structure

```
project/
│
├── app.py        # Main Flask application
└── README.md     # Project documentation
```

Everything (backend + frontend UI) runs from a single file.



## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <repo-name>
```

### 2. Install dependencies

```bash
pip install flask flask-cors bcrypt pyjwt
```

### 3. Run the application

```bash
python app.py
```

Server runs on:

```
http://localhost:5000
```



## 🔑 Default Demo Accounts

The system comes with seeded users:

| Username   | Password  | Role         |
| ---------- | --------- | ------------ |
| superadmin | super123  | Super Admin  |
| manager1   | mgr123    | Bank Manager |
| teller1    | teller123 | Teller       |
| auditor1   | audit123  | Auditor      |
| alice      | alice123  | Customer     |
| bob        | bob123    | Customer     |
| carol      | carol123  | Customer     |

Use these for testing.



## 🔌 API Endpoints

### Authentication

* `POST /api/login` → Login
* `POST /api/register` → Register new user

### User

* `GET /api/me` → User profile
* `GET /api/my-account` → Account details
* `GET /api/stats` → Dashboard stats

### Transactions

* `POST /api/transfer` → Transfer money
* `GET /api/transactions` → All transactions

### Admin

* `POST /api/admin/add-user`
* `POST /api/admin/delete-user`
* `POST /api/admin/change-role`
* `POST /api/freeze-account`

### Audit & Loans

* `GET /api/audit-logs`
* `GET /api/loan-applications`
* `POST /api/approve-loan`



## 🔐 How Authorization Works

1. User logs in → receives JWT token
2. Token is sent in request header:

```
Authorization: Bearer <token>
```

3. Server verifies:

   * Token validity
   * User role
   * Required permissions

4. Access granted or denied accordingly.



## 🎯 Learning Objectives

This project demonstrates:

* Role-Based Access Control (RBAC)
* Secure authentication with JWT
* Password hashing
* API authorization middleware
* Backend security patterns
* Flask full-stack architecture



## ⚠️ Notes

* Uses **in-memory storage** (data resets when server restarts)
* Designed for learning/demo purposes
* Not production-ready



## 📌 Future Improvements

* Database integration (PostgreSQL / MongoDB)
* Persistent audit logs
* Email verification
* Rate limiting
* Multi-factor authentication
* Production deployment setup
