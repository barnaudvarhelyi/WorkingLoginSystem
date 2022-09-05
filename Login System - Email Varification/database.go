package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	var err error
	dsn := MySQLusername + ":" + MySQLpassword + "@tcp(" + MySQLaddress + ":" + MySQLport + ")/login_system"

	db, err = sql.Open("mysql", dsn)

	if err != nil {
		log.Fatal(err)
		return
	}

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Connected to MySQL")
}
