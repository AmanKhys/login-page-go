package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/amankhys/login-page-go/crypt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// setting global variables to be used
var (
	SessionIDLength = 56

	ErrValueTooLong        = errors.New("cookie value too long")
	ErrInvalidValue        = errors.New("cookie value is invalid")
	ErrCookieAlreadyExists = errors.New("cookie already exists.")

	db *sql.DB
)

// user modal to take and send data to users table
type User struct {
	ID        int
	Username  string
	Password  string
	SessionID string
}

// init function to establish db connection
func init() {
	var err error
	log.Println("entering init()")
	db, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection successfully initialized")
}

func main() {
	// db logic
	defer db.Close()

	// backend logic
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/admin", adminHandler)
	mux.HandleFunc("/signup-page", signupPageHandler)
	mux.HandleFunc("/signup", signupHandler)

	log.Print("Listenting on: 4444...")
	err := http.ListenAndServe(":4444", mux)
	if err != nil {
		log.Fatal(err)
	}
}

// ////////////////////
// Handler functions
// ////////////////////
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore favicon requests
	if r.URL.Path == "/favicon.ico" {
		return
	}

	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	users := getUsers(db)
	data := struct {
		Users []User
	}{
		Users: users,
	}

	tmpl := template.Must(template.ParseFiles("./static/admin.html"))
	tmpl.Execute(w, data)
}
func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	cookie, err := readCookie(r, "SessionID")
	if cookie == nil {
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if err != nil {
		log.Println("error while reading cookie: ", err)
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	value, err := crypt.Decrypt(cookie.Value)
	fmt.Printf("cookie sessionID: %s ", value)
	if err != nil {
		log.Printf("%v", fmt.Errorf("error while decrypting value from cookie.Value: %w", err))
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	fmt.Println("cookie value decrpted from /: ", value)
	if checkSession(value) {
		fmt.Println("check session_id from db: session is valid ")
		home, err := os.ReadFile("./static/home.html")
		if err != nil {
			log.Println("error while reading home.html: ", err)
			http.Error(w, "error while reading home file", http.StatusInternalServerError)
			return
		}
		user := getUserBySessionID(cookie.Value)
		log.Printf("successfully served home page for user: %v\n", user.Username)
		w.Write([]byte(home))
		return
	} else {
		fmt.Println("sessionid is not in  db.")
		http.ServeFile(w, r, "./static/index.html")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	//login handler logic
	var users = getUsers(db)
	var SessionID string
	var rUser User
	rUser.Username, rUser.Password = r.FormValue("username"), r.FormValue("password")
	rUser.Username = strings.ToLower(rUser.Username)
	var flag bool
	for _, user := range users {
		fmt.Printf("user: %s pw: %s sid: %s\n", user.Username, user.Password, user.SessionID)
		if rUser.Username == user.Username && rUser.Password == user.Password {
			flag = true
			SessionID = getCustomID()
			saveSessionId(user, SessionID)
		} else if rUser.Username == user.Username && rUser.Password != user.Password {
			http.Error(w, "entered incorrect password", http.StatusBadRequest)
		}
	}

	if flag {
		encryptedID, err := crypt.Encrypt(SessionID)
		if err != nil {
			fmt.Println("error while encrypting SessionID to send as cookie.Value:", err)
		}
		writeCookie(w, encryptedID)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "SessionID")
	if err == ErrInvalidValue {
		http.Error(w, "cookie has been alterned/changed without permission.", http.StatusBadRequest)
	}
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	log.Println("deleted cookie:", cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	var users []User
	user.Username, user.Password = r.FormValue("username"), r.FormValue("password")
	//  make the entered Username as case-insensitive
	user.Username = strings.ToLower(user.Username)

	users = getUsers(db)
	for _, v := range users {
		if v.Username == user.Username {
			str := fmt.Sprintf("User already exists. You can't Sign up as the user: %v\n", user.Username)
			http.Error(w, str, http.StatusBadRequest)
		}
	}
	query := "insert into users (username, password) values (?, ?);"
	_, err := db.Exec(query, user.Username, user.Password)
	if err != nil {
		log.Println("error while inserting values: ", err)
	}

	SessionID := getCustomID()
	user = getUser(user.Username)
	saveSessionId(user, SessionID)
	cryptedID, err := crypt.Encrypt(SessionID)
	if err != nil {
		log.Println("error while converting SessionID to encryptedID to write on cookie in sign-up.", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	writeCookie(w, cryptedID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func signupPageHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	cookie, err := readCookie(r, "SessionID")
	if err != nil {
		log.Println(err)
	}
	if cookie != nil {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	http.ServeFile(w, r, "./static/signup.html")
}

// //////////////
// db functions
// //////////////

func getUsers(db *sql.DB) []User {
	var users []User
	rows, err := db.Query("select * from users;")
	if err != nil {
		log.Println("cannot take row from db users", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.SessionID)
		if err != nil {
			log.Println(err)
			break
		}
		users = append(users, user)
	}
	return users
}

func getUser(username string) User {
	var user User
	query := "select * from users where username = ?;"
	row := db.QueryRow(query, username)
	row.Scan(&user.ID, &user.Username, &user.Password, &user.SessionID)
	return user
}

func getUserBySessionID(SessionID string) User {
	var user User
	query := "select * from users where session_id = ?;"
	row := db.QueryRow(query, SessionID)
	row.Scan(&user, &user.Username, &user.Password, &user.SessionID)
	return user
}

// //////////////////
// Session functions
// //////////////////

// SessionID authenticating function
func checkSession(SessionID string) bool {
	var users []User
	var ids []string
	var check bool
	users = getUsers(db)

	for _, user := range users {
		ids = append(ids, user.SessionID)
	}
	for i := 0; i < len(ids); i++ {
		if SessionID == ids[i] {
			check = true
		}
	}
	return check
}

// save SessionID to database after being created on login/signup
func saveSessionId(user User, SessionID string) {
	query := "update users set session_id = ? where username = ?;"
	result, err := db.Exec(query, SessionID, user.Username)
	k, errRows := result.RowsAffected()
	if errRows != nil {
		log.Printf("error while taking number of rows affected: %v\n", err)
		return
	}
	if err != nil {
		log.Printf("unable to update SessionID: %s for id: %d\n%v\n", SessionID, user.ID, err)
	}
	if k != 1 {
		log.Println("db error: more than 1 rows affected while updating session_id;")
	}
}

// Write SessionID cookie function
func writeCookie(w http.ResponseWriter, SessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "SessionID",
		Value:    SessionID,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Reead SessionID cookie function
func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookie, err := r.Cookie(name)

	if cookie == nil {
		log.Println("cookie does not exist.")
		return nil, http.ErrNoCookie
	}

	// SessionID length is checked for 2 times it since it has been decoded to hex format before sending
	if len(cookie.Value) != SessionIDLength*2 {
		log.Printf("invalid cookie value.\n")
		return nil, ErrInvalidValue
	}
	if err != nil {
		log.Println("unable to read the cookie.")
		return nil, err
	}
	return cookie, nil
}

// Random SessionID generator
func getCustomID() string {
	currentTime := time.Now().UnixNano()
	uniqueID := uuid.New()
	return fmt.Sprintf("%d-%s", currentTime, uniqueID)
}
