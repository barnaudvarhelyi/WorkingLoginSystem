package main

type User struct {
	ID        string
	Username  string
	Email     string
	password  string
	pswHash   string
	CreatedAt string
	Active    int
	verHash   string
	timeout   string
}

type TempData struct {
	Username   string
	Email      string
	AuthInfo   string
	ErrMessage string
	Message    string
}
