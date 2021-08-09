package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func answ(r *http.Request) {
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
	if r.Method == "POST" {
		fmt.Println("POST")
		answ(r)
	} else {
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
