package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/scrypt"
)

type Token struct {
	Role int
	jwt.StandardClaims
}
type Account struct {
	User  User
	Token string `json:"token"`
}

type neuteredFileSystem struct {
	fs http.FileSystem
}
type htmlform map[string]string

type AdmTopic struct {
	Topic Topic
	Word  []string
	HForm []string
}

type User struct {
	Id           int
	Username     string
	Role         int
	Class        int
	Userpassword []byte
}

type Topic struct {
	Id       int
	Name     string
	FormName string
	Count    int
	Ch1      string
	Ch2      string
	Ch3      string
}
type Word struct {
	Id   int
	Word string
}

const lenPath = len("/adm/")

var database *sql.DB
var htmlf htmlform
var hform []string
var salt []byte
var CurUser User

func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if s.IsDir() {
		index := filepath.Join(path, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, err
		}
	}
	return f, nil
}

func home(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	wp := AdmTopic{}
	wp.HForm = hform
	wp.Topic = getTopic(page)[0]
	wp.Word = getWord(page)
	ts, err := template.ParseFiles("./html/" + htmlf[wp.Topic.FormName])
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}
	err = ts.Execute(w, wp)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
	}
}

func getTopic(id string) []Topic {
	s := "SELECT * FROM topic"
	if id != "all" {
		s = "SELECT * FROM topic WHERE id = " + id
	}
	rows, err := database.Query(s)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	topics := []Topic{}
	for rows.Next() {
		p := Topic{}
		err := rows.Scan(&p.Id, &p.Name, &p.FormName, &p.Count, &p.Ch1, &p.Ch2, &p.Ch3)
		if err != nil {
			fmt.Println(err)
			continue
		}
		topics = append(topics, p)
	}
	return topics
}

func getWord(id string) []string {
	s := "SELECT * FROM words WHERE id = " + id
	rows, err := database.Query(s)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	words := []string{}
	for rows.Next() {
		p := Word{}
		err := rows.Scan(&p.Id, &p.Word)
		if err != nil {
			fmt.Println(err)
			continue
		}
		words = append(words, p.Word)
	}
	return words
}

func adm(w http.ResponseWriter, r *http.Request) {
	p := getTopic("all")
	tmpl := template.Must(template.ParseFiles("./html/admin.html"))
	tmpl.Execute(w, p)
}

func menu(w http.ResponseWriter, r *http.Request) {
	p := getTopic("all")
	tmpl := template.Must(template.ParseFiles("./html/menu.html"))
	tmpl.Execute(w, p)
}

func admTopic(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Path[lenPath:]
	wp := AdmTopic{}
	wp.HForm = hform
	if page != "New" {
		wp.Topic = getTopic(r.URL.Path[lenPath:])[0]
		wp.Word = getWord(r.URL.Path[lenPath:])
	} else {
		wp.Topic = Topic{0, "", "           ", 0, "", "", ""}
		wp.Word = []string{}
	}
	tmpl := template.Must(template.ParseFiles("./html/admTopic.html"))
	tmpl.Execute(w, wp)
}

func insertTopic(data Topic) int {
	if data.Id == 0 {
		id := 0
		database.QueryRow("insert into topic (name, formname, count, ch1, ch2, ch3) values ($1, $2, $3, $4, $5, $6) returning id", data.Name, data.FormName, data.Count, data.Ch1, data.Ch2, data.Ch3).Scan(&id)
		return id
	} else {
		_, err := database.Exec("update topic set name = $2, formname = $3, count = $4, ch1 = $5, ch2 = $6, ch3 = $7 where id = $1", data.Id, data.Name, data.FormName, data.Count, data.Ch1, data.Ch2, data.Ch3)
		if err != nil {
			fmt.Println(err)
			return 0
		}
		return data.Id
	}
}
func insertWord(arr []string, id int) {
	_, err := database.Exec("delete from words where id = $1", id)
	if err != nil {
		fmt.Println(err)
	}
	for _, value := range arr {
		_, err := database.Exec("insert into words (id, word) values ($1, $2)", id, value)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func answ(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Update words")
	r.ParseForm()
	var data Topic
	var arrWord = []string{}
	data.Id, _ = strconv.Atoi(r.FormValue("id"))
	data.Name = r.FormValue("tema")
	data.FormName = r.FormValue("form")
	data.Count, _ = strconv.Atoi(r.FormValue("count"))
	data.Ch1 = r.FormValue("ch1")
	data.Ch2 = r.FormValue("ch2")
	data.Ch3 = r.FormValue("ch3")
	arrWord = strings.Split(r.FormValue("word"), ",")
	//	arrWord = append(arrWord, r.FormValue("word"))
	fmt.Println(r.FormValue("word"))
	insertWord(arrWord, insertTopic(data))
}

func readjson() (htmlform, []string) {
	plan, _ := ioutil.ReadFile("./form.json") // filename is the JSON file to read
	var data htmlform
	var datas []string
	err := json.Unmarshal(plan, &data)
	if err != nil {
		fmt.Println(err)
	}
	for key := range data {
		datas = append(datas, key)
	}
	return data, datas
}

func getUser(name string, psw string) (User, bool) {
	s := "SELECT * FROM users WHERE username = '" + name + "'"
	rows, err := database.Query(s)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	p := User{}
	for rows.Next() {
		err := rows.Scan(&p.Id, &p.Username, &p.Role, &p.Class, &p.Userpassword)
		if err != nil {
			fmt.Println(err)
			return p, false
		}
	}
	getpsw, _ := scrypt.Key([]byte(psw), salt, 16384, 8, 1, 32)
	//	_, e := database.Exec("update users set userpassword = $2 where username = $1", p.Username, string(getpsw))

	if string(getpsw) == string(p.Userpassword) {
		return p, true

	}
	return p, false
}

func addCookie(w http.ResponseWriter, value string, ttl time.Duration) {
	cookie := http.Cookie{
		Name:     "login",
		Value:    value,
		HttpOnly: true,
		Expires:  time.Now().Add(ttl),
	}
	fmt.Println(cookie)
	http.SetCookie(w, &cookie)
}

func start(w http.ResponseWriter, r *http.Request) {
	account := &Account{}
	if r.Method == "POST" {
		addCookie(w, "", -30*time.Minute)
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
		}
		name := r.FormValue("uname")
		psw := r.FormValue("psw")
		CurUser, find := getUser(name, psw)
		if find && CurUser.Role == 1 {

			tk := &Token{Role: CurUser.Role}
			token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
			tokenString, _ := token.SignedString([]byte("token_password"))
			account.Token = tokenString
			account.User = CurUser
			account.User.Userpassword = nil
			account.User.Username = ""
			addCookie(w, tokenString, 60*time.Minute)
			//	resp := map[string]interface{}{"account": account}
			//	Respond(w, resp)
		}
	} else {
		account.Token = ""
		account.User = CurUser
	}
	tmpl := template.Must(template.ParseFiles("./html/start.html"))
	tmpl.Execute(w, account)
}

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}
func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := make(map[string]interface{})
		//	tokenHeader := r.Header.Get("Cookie") //Получение токена
		val, _ := r.Cookie("login")
		tokenHeader := val.Value
		if tokenHeader == "" { //Токен отсутствует, возвращаем  403 http-код Unauthorized
			response = Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		tk := &Token{}
		token, err := jwt.ParseWithClaims(tokenHeader, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte("token_password"), nil
		})

		if err != nil { //Неправильный токен, как правило, возвращает 403 http-код
			response = Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		if !token.Valid { //токен недействителен, возможно, не подписан на этом сервере
			response = Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		//Всё прошло хорошо, продолжаем выполнение запроса
		fmt.Println("Role %", tk.Role) //Полезно для мониторинга
		ctx := context.WithValue(r.Context(), "role", tk.Role)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Println("$PORT must be set")
	}
	//	log.Println(os.Getenv("DATABASE_URL"))
	CurUser = User{0, "", 0, 0, nil}
	db, er := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if er != nil {
		log.Println(er)
	}
	database = db
	defer db.Close()
	htmlf, hform = readjson()
	salt = []byte("asdfasdf")
	finalHandler := http.HandlerFunc(adm)
	mux := http.NewServeMux()
	mux.HandleFunc("/", start)
	mux.HandleFunc("/menu", menu)
	mux.HandleFunc("/menu/", home)
	mux.Handle("/adm", checkToken(finalHandler))
	mux.Handle("/adm/answ", checkToken(http.HandlerFunc(answ)))
	mux.Handle("/adm/", checkToken(http.HandlerFunc(admTopic)))

	fileServer := http.FileServer(neuteredFileSystem{http.Dir("./html/css/")})
	mux.Handle("/static", http.NotFoundHandler())

	//	fileServer := http.FileServer(http.Dir("./html/css/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	// Используется функция http.ListenAndServe() для запуска нового веб-сервера.
	log.Println("Запуск веб-сервера на :", port)
	err := http.ListenAndServe(":"+port, mux)
	log.Fatal(err)
}
