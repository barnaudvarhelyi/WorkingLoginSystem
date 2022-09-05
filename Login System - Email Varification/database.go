package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	// dsn := MySQLusername + ":" + MySQLpassword + "@tcp(" + MySQLaddress + MySQLport + ")/" + dbName
	var err error

	dsn := "root:Barnabarna03@tcp(localhost:3306)/login_system"

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
