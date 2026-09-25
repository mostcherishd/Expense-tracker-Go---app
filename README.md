# devscale_expense

DevScale Expense — a demo expense tracker built in Go.

Users log in (or register), log everyday expenses by category, and use the
12-month savings planner: enter what you currently have saved, how much more
you want to save, and how much you plan to spend over the next year, and get
a suggested monthly/weekly budget with tailored recommendations.

No real accounts or payments — this is a demo application with in-memory storage.

## Run

```
go run .
```

Then open http://localhost:8080

Demo login: username `dapo`, password `welcome+1` (see the login page for the full list).

## Features

- Sign in / register (demo, in-memory accounts)
- Log expenses with category, amount, and an optional note
- Dashboard with totals and a spend-by-category breakdown
- Savings planner: enter current savings, savings goal, and planned spend for
  the next 12 months to get a status (on track / tight / at risk), a monthly
  savings target, a monthly/weekly spend budget, and a projected 12-month
  balance with specific recommendations
# Expense-tracker-Go---app
