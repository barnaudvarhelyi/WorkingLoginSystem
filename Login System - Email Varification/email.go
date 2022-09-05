package main

import (
	"fmt"
	"net/smtp"
)

func (u *User) SendEmail(subject, HTMLbody string) error {
	from := "golang.emailsender@gmail.com"
	fromPw := "mdxgzfrlokotxosu"

	to := []string{u.Email}

	fmt.Println(u.Email)
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	auth := smtp.PlainAuth("", from, fromPw, smtpHost)

	msg := []byte(
		"From: <" + from + ">\r\n" +
			"To: " + u.Email + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME: MIME-version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
			"\r\n" +
			HTMLbody)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)

	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Check for sent email")
	return nil
}
