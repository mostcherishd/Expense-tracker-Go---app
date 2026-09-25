package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// User holds a demo account
type User struct {
	Username  string
	Password  string
	FirstName string
	LastName  string
}

// Session holds an authenticated session entry
type Session struct {
	Username  string
	ExpiresAt time.Time
}

// Expense represents a single logged expense entry
type Expense struct {
	ID       string
	Username string
	Category string
	Note     string
	Amount   float64
	Date     time.Time
}

// Plan represents a saved savings/spend plan for a user
type Plan struct {
	Username       string
	CurrentSavings float64
	SavingsGoal    float64
	PlannedSpend   float64
	CreatedAt      time.Time
}

const demoPassword = "welcome+1"

var users = map[string]User{
	"dapo": {
		Username:  "dapo",
		Password:  demoPassword,
		FirstName: "Dapo",
		LastName:  "",
	},
	"iyiola": {
		Username:  "iyiola",
		Password:  demoPassword,
		FirstName: "Iyiola",
		LastName:  "Olakunle",
	},
	"abayomi": {
		Username:  "abayomi",
		Password:  demoPassword,
		FirstName: "Abayomi",
		LastName:  "Akinyemi",
	},
	"chimezie": {
		Username:  "chimezie",
		Password:  demoPassword,
		FirstName: "Chimezie",
		LastName:  "Ogbu",
	},
}

var expenseCategories = []string{
	"Housing", "Food & Groceries", "Transport", "Utilities",
	"Health", "Entertainment", "Savings & Investments", "Other",
}

var (
	sessions = map[string]Session{}
	expenses = []Expense{}
	plans    = map[string]Plan{} // keyed by username, one active plan per user
	nextID   = 1

	mu   sync.RWMutex
	tmpl *template.Template

	appLog *log.Logger
)

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return r.RemoteAddr
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// formatMoney formats a float64 as a US dollar string e.g. $450,000.00
func formatMoney(amount float64) string {
	neg := amount < 0
	if neg {
		amount = -amount
	}
	s := fmt.Sprintf("%.2f", amount)
	parts := strings.SplitN(s, ".", 2)
	intPart := parts[0]
	decimals := parts[1]

	var result []byte
	n := len(intPart)
	for i := 0; i < n; i++ {
		if i > 0 && (n-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, intPart[i])
	}
	out := "$" + string(result) + "." + decimals
	if neg {
		out = "-" + out
	}
	return out
}

func initials(firstName, lastName string) string {
	var b strings.Builder
	if len(firstName) > 0 {
		b.WriteString(strings.ToUpper(firstName[:1]))
	}
	if len(lastName) > 0 {
		b.WriteString(strings.ToUpper(lastName[:1]))
	}
	return b.String()
}

func fullName(firstName, lastName string) string {
	if lastName == "" {
		return firstName
	}
	return firstName + " " + lastName
}

func getSession(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return User{}, false
	}
	mu.RLock()
	session, ok := sessions[cookie.Value]
	mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		return User{}, false
	}
	user, exists := users[session.Username]
	return user, exists
}

// loginHandler handles GET / (render login) and POST / (authenticate)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if _, ok := getSession(r); ok {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.ExecuteTemplate(w, "login.html", nil); err != nil {
			log.Printf("Login template error: %v", err)
		}
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	mu.RLock()
	user, ok := users[username]
	mu.RUnlock()

	if !ok || subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) != 1 {
		appLog.Printf("LOGIN_FAILED username=%q ip=%s", username, clientIP(r))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error": "Invalid username or password. Please try again.",
		})
		return
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	mu.Lock()
	sessions[token] = Session{
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	appLog.Printf("LOGIN_SUCCESS username=%q ip=%s", username, clientIP(r))

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// registerHandler handles GET /register (render form) and POST /register (create account)
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := getSession(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.ExecuteTemplate(w, "register.html", nil); err != nil {
			log.Printf("Register template error: %v", err)
		}
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))

	renderErr := func(msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
			"Error": msg,
		})
	}

	if username == "" || password == "" || firstName == "" || lastName == "" {
		renderErr("All fields are required.")
		return
	}
	if len(username) < 3 {
		renderErr("Username must be at least 3 characters long.")
		return
	}
	if len(password) < 6 {
		renderErr("Password must be at least 6 characters long.")
		return
	}
	if password != confirmPassword {
		renderErr("Passwords do not match.")
		return
	}

	mu.RLock()
	_, exists := users[username]
	mu.RUnlock()
	if exists {
		renderErr("Username already exists. Please choose a different username.")
		return
	}

	mu.Lock()
	users[username] = User{
		Username:  username,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
	}
	mu.Unlock()

	appLog.Printf("REGISTER username=%q ip=%s", username, clientIP(r))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "register.html", map[string]interface{}{
		"Success": true,
	})
}

// PlanResult holds the computed suggestion shown after the planner form is submitted
type PlanResult struct {
	CurrentSavings       float64
	SavingsGoal          float64
	PlannedSpend         float64
	MonthlySavingsTarget float64
	MonthlySpendBudget   float64
	WeeklySpendBudget    float64
	ProjectedEndBalance  float64
	Status               string // "on-track", "tight", "at-risk"
	StatusLabel          string
	Headline             string
	Advice               []string
}

func buildPlan(currentSavings, savingsGoal, plannedSpend float64) PlanResult {
	res := PlanResult{
		CurrentSavings: currentSavings,
		SavingsGoal:    savingsGoal,
		PlannedSpend:   plannedSpend,
	}

	res.MonthlySavingsTarget = savingsGoal / 12
	res.MonthlySpendBudget = plannedSpend / 12
	res.WeeklySpendBudget = plannedSpend / 52
	res.ProjectedEndBalance = currentSavings + savingsGoal - plannedSpend

	requiredOutflow := savingsGoal + plannedSpend

	switch {
	case currentSavings <= 0 && requiredOutflow > 0:
		res.Status = "at-risk"
	case requiredOutflow > currentSavings*3:
		res.Status = "at-risk"
	case requiredOutflow > currentSavings*1.2:
		res.Status = "tight"
	default:
		res.Status = "on-track"
	}

	switch res.Status {
	case "on-track":
		res.StatusLabel = "On Track"
		res.Headline = "Your plan looks comfortably achievable."
		res.Advice = []string{
			fmt.Sprintf("Set aside about %s per month toward your savings goal — a fixed automatic transfer works best.", formatMoney(res.MonthlySavingsTarget)),
			fmt.Sprintf("Keep everyday spending near %s per month (roughly %s per week) and you'll stay inside your %s budget for the year.", formatMoney(res.MonthlySpendBudget), formatMoney(res.WeeklySpendBudget), formatMoney(plannedSpend)),
			"Since your current savings comfortably cover this plan, consider directing any surplus into an emergency fund or a low-risk investment.",
		}
	case "tight":
		res.StatusLabel = "Tight — Manageable With Discipline"
		res.Headline = "This plan is achievable, but leaves little room for surprises."
		res.Advice = []string{
			fmt.Sprintf("Automate a transfer of %s per month so your savings goal doesn't compete with daily spending decisions.", formatMoney(res.MonthlySavingsTarget)),
			fmt.Sprintf("Cap discretionary spending at roughly %s per month (about %s per week) — track it weekly so you notice drift early.", formatMoney(res.MonthlySpendBudget), formatMoney(res.WeeklySpendBudget)),
			"Build a small buffer (5-10% of your monthly budget) for unplanned costs so one surprise expense doesn't derail the whole year.",
			"Look for one or two recurring costs (subscriptions, dining out, transport) you could trim to create breathing room.",
		}
	default:
		res.StatusLabel = "At Risk — Needs Adjustment"
		res.Headline = "As entered, this plan asks for more than your current savings can comfortably support."
		gap := requiredOutflow - currentSavings
		res.Advice = []string{
			fmt.Sprintf("Your savings goal plus planned spending is %s, which is %s more than what you currently have set aside.", formatMoney(requiredOutflow), formatMoney(gap)),
			"Consider lowering the savings goal, stretching it beyond a year, or reducing planned spending so the numbers line up with income you expect to earn along the way.",
			fmt.Sprintf("If you do expect regular income this year, make sure it covers at least %s per month to fund both spending and savings.", formatMoney(res.MonthlySavingsTarget+res.MonthlySpendBudget)),
			"Prioritize an emergency cushion first — even a small one reduces the risk of debt if plans slip.",
		}
	}

	return res
}

// plannerHandler handles GET /planner (show form + last result) and POST /planner (compute suggestion)
func plannerHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		data := map[string]interface{}{"User": user}
		mu.RLock()
		if plan, exists := plans[user.Username]; exists {
			data["Result"] = buildPlan(plan.CurrentSavings, plan.SavingsGoal, plan.PlannedSpend)
		}
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.ExecuteTemplate(w, "planner.html", data); err != nil {
			log.Printf("Planner template error: %v", err)
		}
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	renderErr := func(msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.ExecuteTemplate(w, "planner.html", map[string]interface{}{
			"User":  user,
			"Error": msg,
		})
	}

	currentSavings, err1 := strconv.ParseFloat(strings.TrimSpace(r.FormValue("current_savings")), 64)
	savingsGoal, err2 := strconv.ParseFloat(strings.TrimSpace(r.FormValue("savings_goal")), 64)
	plannedSpend, err3 := strconv.ParseFloat(strings.TrimSpace(r.FormValue("planned_spend")), 64)

	if err1 != nil || err2 != nil || err3 != nil {
		renderErr("Please enter valid numbers for all three fields.")
		return
	}
	if currentSavings < 0 || savingsGoal < 0 || plannedSpend < 0 {
		renderErr("Amounts can't be negative.")
		return
	}

	mu.Lock()
	plans[user.Username] = Plan{
		Username:       user.Username,
		CurrentSavings: currentSavings,
		SavingsGoal:    savingsGoal,
		PlannedSpend:   plannedSpend,
		CreatedAt:      time.Now(),
	}
	mu.Unlock()

	appLog.Printf("PLAN username=%q savings=%.2f goal=%.2f spend=%.2f ip=%s",
		user.Username, currentSavings, savingsGoal, plannedSpend, clientIP(r))

	result := buildPlan(currentSavings, savingsGoal, plannedSpend)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "planner.html", map[string]interface{}{
		"User":   user,
		"Result": result,
	})
}

// dashboardHandler renders the expense dashboard
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	type ExpenseView struct {
		Expense
		AmountFormatted string
		DateFormatted   string
	}

	mu.RLock()
	var userExpenses []Expense
	for _, e := range expenses {
		if e.Username == user.Username {
			userExpenses = append(userExpenses, e)
		}
	}
	plan, hasPlan := plans[user.Username]
	mu.RUnlock()

	sort.Slice(userExpenses, func(i, j int) bool {
		return userExpenses[i].Date.After(userExpenses[j].Date)
	})

	var views []ExpenseView
	var total float64
	byCategory := map[string]float64{}
	for _, e := range userExpenses {
		views = append(views, ExpenseView{
			Expense:         e,
			AmountFormatted: formatMoney(e.Amount),
			DateFormatted:   e.Date.Format("Jan 2, 2006"),
		})
		total += e.Amount
		byCategory[e.Category] += e.Amount
	}

	type CategoryTotal struct {
		Category  string
		Amount    float64
		Formatted string
		Percent   float64
	}
	var catTotals []CategoryTotal
	for cat, amt := range byCategory {
		pct := 0.0
		if total > 0 {
			pct = (amt / total) * 100
		}
		catTotals = append(catTotals, CategoryTotal{
			Category:  cat,
			Amount:    amt,
			Formatted: formatMoney(amt),
			Percent:   pct,
		})
	}
	sort.Slice(catTotals, func(i, j int) bool { return catTotals[i].Amount > catTotals[j].Amount })

	data := map[string]interface{}{
		"User":       user,
		"Expenses":   views,
		"Total":      formatMoney(total),
		"Count":      len(views),
		"Categories": expenseCategories,
		"ByCategory": catTotals,
		"HasPlan":    hasPlan,
	}
	if hasPlan {
		data["Plan"] = plan
		data["PlanResult"] = buildPlan(plan.CurrentSavings, plan.SavingsGoal, plan.PlannedSpend)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("Dashboard template error: %v", err)
	}
}

// addExpenseHandler processes POST /expenses/add
func addExpenseHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	category := strings.TrimSpace(r.FormValue("category"))
	note := strings.TrimSpace(r.FormValue("note"))
	amount, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("amount")), 64)
	if err != nil || amount <= 0 || category == "" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	mu.Lock()
	expenses = append(expenses, Expense{
		ID:       fmt.Sprintf("e%d", nextID),
		Username: user.Username,
		Category: category,
		Note:     note,
		Amount:   amount,
		Date:     time.Now(),
	})
	nextID++
	mu.Unlock()

	appLog.Printf("EXPENSE_ADD username=%q category=%q amount=%.2f ip=%s", user.Username, category, amount, clientIP(r))

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// deleteExpenseHandler processes POST /expenses/delete
func deleteExpenseHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	id := r.FormValue("id")

	mu.Lock()
	for i, e := range expenses {
		if e.ID == id && e.Username == user.Username {
			expenses = append(expenses[:i], expenses[i+1:]...)
			break
		}
	}
	mu.Unlock()

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// logoutHandler destroys the session and redirects to login
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		mu.Lock()
		session, ok := sessions[cookie.Value]
		delete(sessions, cookie.Value)
		mu.Unlock()
		if ok {
			appLog.Printf("LOGOUT username=%q ip=%s", session.Username, clientIP(r))
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	appLog = log.New(&logWriter{}, "", log.Ldate|log.Ltime)

	var err error
	tmpl, err = template.New("").Funcs(template.FuncMap{
		"initials":    initials,
		"fullName":    fullName,
		"formatMoney": formatMoney,
		"addOne":      func(i int) int { return i + 1 },
	}).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v\nMake sure you run this from the project root directory.", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/dashboard", dashboardHandler)
	mux.HandleFunc("/planner", plannerHandler)
	mux.HandleFunc("/expenses/add", addExpenseHandler)
	mux.HandleFunc("/expenses/delete", deleteExpenseHandler)
	mux.HandleFunc("/logout", logoutHandler)

	port := ":8080"
	fmt.Println("============================================")
	fmt.Println("  DevScale Expense Tracker")
	fmt.Println("============================================")
	fmt.Printf("  Server running at http://0.0.0.0%s\n", port)
	fmt.Println("  Open your browser: http://localhost:8080")
	fmt.Println("  Demo login: username is <your username> and password is welcome+1")
	fmt.Println("============================================")
	log.Fatal(http.ListenAndServe(port, mux))
}

// logWriter writes app log lines to stdout
type logWriter struct{}

func (w *logWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
