package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/amankhys/login-page-go/crypt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// setting global variables to be used
var (
	sessionIDLength = 56

	ErrValueTooLong        = errors.New("cookie value too long")
	ErrInvalidValue        = errors.New("cookie value is invalid")
	ErrCookieAlreadyExists = errors.New("cookie already exists.")

	db *sql.DB
)

// user modal to take and send data to users table
type User struct {
	id        int
	username  string
	password  string
	sessionID string
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
func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore favicon requests
	if r.URL.Path == "/favicon.ico" {
		return
	}

	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	cookie, err := readCookie(r, "sessionID")
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
	if err != nil {
		log.Printf("%v", fmt.Errorf("error while decrypting value from cookie.Value: %w", err))
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	fmt.Println("cookie value decrpted from /: ", value)
	if checkSession(value) {
		home, err := os.ReadFile("./static/home.html")
		if err != nil {
			log.Println("error while reading home.html: ", err)
			http.Error(w, "error while reading home file", http.StatusInternalServerError)
			return
		}
		user := getUserBySessionID(cookie.Value)
		log.Printf("successfully served home page for user: %v\n", user.username)
		w.Write([]byte(home))
		return
	} else {
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
	var sessionID string
	var rUser User
	rUser.username, rUser.password = r.FormValue("username"), r.FormValue("password")
	rUser.username = strings.ToLower(rUser.username)
	var flag bool
	for _, user := range users {
		if rUser.username == user.username && rUser.password == user.password {
			flag = true
			sessionID = getCustomID()
			saveSessionId(user, sessionID)
		} else if rUser.password == user.username && rUser.password != user.password {
			http.Error(w, "entered incorrect password", http.StatusBadRequest)
		}
	}

	if flag {
		encryptedID, err := crypt.Encrypt(sessionID)
		if err != nil {
			fmt.Println("error while encrypting sessionID to send as cookie.Value:", err)
		}
		writeCookie(w, encryptedID)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "sessionID")
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
	user.username, user.password = r.FormValue("username"), r.FormValue("password")
	//  make the entered username as case-insensitive
	user.username = strings.ToLower(user.username)

	users = getUsers(db)
	for _, v := range users {
		if v.username == user.username {
			str := fmt.Sprintf("User already exists. You can't Sign up as the user: %v\n", user.username)
			http.Error(w, str, http.StatusBadRequest)
		}
	}
	query := "insert into users (username, password) values (?, ?);"
	_, err := db.Exec(query, user.username, user.password)
	if err != nil {
		log.Println("error while inserting values: ", err)
	}

	sessionID := getCustomID()
	user = getUser(user.username)
	saveSessionId(user, sessionID)
	cryptedID, err := crypt.Encrypt(sessionID)
	if err != nil {
		log.Println("error while converting sessionID to encryptedID to write on cookie in sign-up.", err)
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
	cookie, err := readCookie(r, "sessionID")
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
		err := rows.Scan(&user.id, &user.username, &user.password, &user.sessionID)
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
	row.Scan(&user.id, &user.username, &user.password, &user.sessionID)
	return user
}

func getUserBySessionID(sessionID string) User {
	var user User
	query := "select * from users where sessionid = ?;"
	row := db.QueryRow(query, sessionID)
	row.Scan(&user.id, &user.username, &user.password, &user.sessionID)
	return user
}

// //////////////////
// Session functions
// //////////////////

// sessionID authenticating function
func checkSession(sessionID string) bool {
	var users []User
	var ids []string
	var check bool
	users = getUsers(db)

	for _, user := range users {
		ids = append(ids, user.sessionID)
	}
	for i := 0; i < len(ids); i++ {
		if sessionID == ids[i] {
			check = true
		}
	}
	return check
}

// save sessionID to database after being created on login/signup
func saveSessionId(user User, sessionID string) {
	query := "update users set sessionID = ? where id = ?;"
	result, err := db.Exec(query, sessionID, user.id)
	k, errRows := result.RowsAffected()
	if errRows != nil {
		log.Printf("error while taking number of rows affected: %v\n", err)
		return
	}
	if err != nil || k != 1 {
		log.Printf("unable to update sessionID: %s for id: %d\n%v", sessionID, user.id, err)
	}
}

// Write sessionID cookie function
func writeCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sessionID",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Reead sessionID cookie function
func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookie, err := r.Cookie(name)

	if cookie == nil {
		log.Println("cookie does not exist.")
		return nil, http.ErrNoCookie
	}

	// sessionID length is checked for 2 times it since it has been decoded to hex format before sending
	if len(cookie.Value) != sessionIDLength*2 {
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
