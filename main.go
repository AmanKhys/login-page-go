package main

import (
	"database/sql"
	"errors"
	// "fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
)

var (
	ErrValueTooLong        = errors.New("cookie value too long")
	ErrInvalidValue        = errors.New("cookie value is invalid")
	ErrCookieAlreadyExists = errors.New("cookie already exists.")

	db *sql.DB
)

type User struct {
	id        int
	username  string
	password  string
	sessionid int
}

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
	row := db.QueryRow("select * from users;")

	var id, sessionid int
	var username, password string
	err := row.Scan(&id, &username, &password, &sessionid)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Id: %d, Username: %s, Password: %s, SessionID: %d\n", id, username, password, sessionid)
	}

	// backend logic

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/signup-page", signupPageHandler)
	mux.HandleFunc("/signup", signupHandler)

	log.Print("Listenting on: 4444...")
	err = http.ListenAndServe(":4444", mux)
	if err != nil {
		log.Fatal(err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "sessionid")
	if cookie == nil {
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if err != nil {
		log.Println("error while reading cookie: ", err)
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if checkSession(cookie.Value) {
		// fmt.Println("entered to serve home.html")
		home, err := os.ReadFile("./static/home.html")
		if err != nil {
			log.Println("error while reading home.html: ", err)
			http.Error(w, "error while reading home file", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(home))
		return
	} else {
		http.ServeFile(w, r, "./static/index.html")
	}
}

func signupPageHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeFile(w, r, "./static/signup.html")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	user.username, user.password = r.FormValue("username"), r.FormValue("password")

	query := "insert into users (username, password) values (?, ?);"
	_, err := db.Exec(query, user.username, user.password)
	if err != nil {
		log.Println("error while inserting values: ", err)
	}

	sessionid := createRandomSessionId()
	user = getUser(user.username)
	saveSessionId(user, sessionid)
	writeCookie(w, sessionid)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	//login handler logic
	var users = getUsers(db)
	// fmt.Println(users)
	var sessionid int
	var rUser, rPassword string = r.FormValue("username"), r.FormValue("password")
	// fmt.Printf("ruser: %s, rpw:  %s\n", rUser, rPassword)
	var flag bool
	for _, user := range users {
		if rUser == user.username && rPassword == user.password {
			flag = true
			sessionid = createRandomSessionId()
			saveSessionId(user, sessionid)
		} else if rUser == user.username && rPassword != user.password {
			http.Error(w, "entered incorrect password", http.StatusBadRequest)
		}
	}
	// fmt.Printf("flag: %t \n", flag)
	if flag {
		writeCookie(w, sessionid)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "sessionid")
	if cookie == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err == ErrInvalidValue {
		http.Error(w, "cookie has been alterned/changed without permission.", http.StatusBadRequest)
	}
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	log.Println("set cookie to delete: ", cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func writeCookie(w http.ResponseWriter, sessionid int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sessionid",
		Value:    strconv.Itoa(sessionid),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	// read the cookie as normal
	cookie, err := r.Cookie(name)
	if err != nil {
		log.Println("unabel to read the cookie.")
		return nil, http.ErrNoCookie
	}
	value, err := strconv.Atoi(cookie.Value)
	if err != nil {
		log.Println("failed to convert from string to integer of the sessionid field from request cookie.")
	}

	if cookie == nil {
		return nil, errors.New("cookie dose not exist")
	} else if value < 1000 && value > 9999 {
		return nil, ErrInvalidValue
	} else if cookie.MaxAge > 0 {
		return nil, ErrCookieAlreadyExists
	} else if err != nil {
		return nil, err
	}
	return cookie, nil
}

func getUsers(db *sql.DB) []User {
	var users []User
	rows, err := db.Query("select * from users;")
	if err != nil {
		log.Println("cannot take row from db users", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.id, &user.username, &user.password, &user.sessionid)
		if err != nil {
			log.Println(err)
			break
		}
		users = append(users, user)
	}
	return users
}

func checkSession(sessionidStr string) bool {
	var users []User
	var ids []int
	var check bool
	// fmt.Println("ids: ", ids)
	id, err := strconv.Atoi(sessionidStr)
	if err != nil {
		log.Println("unable to convert sessionid to int to check whether sessionid exists in db.", err)
		return check
	}
	// fmt.Printf("cookie sessionid: %d\n", id)
	users = getUsers(db)

	for _, user := range users {
		ids = append(ids, user.sessionid)
	}

	for i := 0; i < len(ids); i++ {
		if id == ids[i] {
			check = true
		}
	}

	// fmt.Printf("checkSession bool: %t\n", check)
	return check
}

func createRandomSessionId() int {
	return rand.Intn(9000) + 1000
}

func saveSessionId(user User, sessionid int) {

	query := "update users set sessionid = ? where id = ?;"
	_, err := db.Exec(query, sessionid, user.id)
	if err != nil {
		log.Printf("unable to update sessionid: %d for id: %d\n%v", sessionid, user.id, err)
	}
}

func getUser(username string) User {
	var user User
	query := "select * from users where username = ?;"
	row := db.QueryRow(query, username)
	row.Scan(&user.id, &user.username, &user.password, &user.sessionid)
	return user
}
