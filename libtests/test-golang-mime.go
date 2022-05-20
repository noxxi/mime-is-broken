package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	files := os.Args[1:]
	docheck := _check_eicartxt
	// docheck := _check_zipname
	for len(files) > 0 {
		f := files[0]
		files = files[1:]
		if st, err := os.Stat(f); err == nil {
			if st.IsDir() {
				if ff, _ := filepath.Glob(f + "/*"); len(ff) > 0 {
					files = append(files, ff...)
				}
			} else if !st.Mode().IsRegular() {
				log.Printf("not a file: %s", f)
			} else {
				check(f, docheck)
			}
		} else {
			log.Printf("does not exist: %s", f)
		}
	}
}

type attachment struct {
	name string
	data []byte
}
type checkfunc func(attachment) bool

func check(fname string, docheck checkfunc) {
	f, err := os.Open(fname)
	if err != nil {
		log.Printf("failed to open file %s: %s ", fname, err)
		return
	}
	m, err := mail.ReadMessage(f)
	if err != nil {
		log.Printf("failed to read file %s: %s ", fname, err)
		return
	}
	subject := []byte(m.Header.Get("subject"))
	subject = regexp.MustCompile(`\[\d\] \S+`).Find(subject)
	log.Printf("file %s - %s", fname, subject)

	boundary := _boundary(m.Header.Get("content-type"))
	if boundary == "" {
		log.Printf("%s - no multipart", subject)
		return
	}
	attachments := scan(m.Body, boundary)
	check_ok := 0
	for _, a := range attachments {
		if docheck(a) {
			check_ok++
		}
	}
	if check_ok > 0 {
		fmt.Printf("%s\n", subject)
	} else {
		log.Printf("NOT %s", subject)
	}
}

func scan(r io.Reader, boundary string) []attachment {
	mr := multipart.NewReader(r, boundary)
	attachments := make([]attachment, 1)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Printf(" --- Error in NextPart: %s", err)
			return nil
		}
		if inner_boundary := _boundary(part.Header.Get("Content-type")); inner_boundary != "" {
			scan(r, inner_boundary)
		} else if fn := part.FileName(); fn != "" {
			log.Printf(" +++ attachment %s", fn)
			data := _decode(part)
			attachments = append(attachments, attachment{fn, data})
		}
	}
	return attachments
}

func _boundary(ct string) string {
	ctx, params, err := mime.ParseMediaType(ct)
	if err != nil {
		log.Printf(" --- Error while parsing 'Content-Type: %s': %s", ct, err)
		return ""
	}
	if regexp.MustCompile(`(?i)^multipart/`).Find([]byte(ctx)) == nil {
		return ""
	}
	return params["boundary"]
}

func _decode(part *multipart.Part) []byte {
	cte := part.Header.Get("Content-Transfer-Encoding")
	var dr io.Reader = part
	if strings.EqualFold(cte, "base64") {
		dr = base64.NewDecoder(base64.StdEncoding, part)
	} else if strings.EqualFold(cte, "quoted-printable") {
		dr = quotedprintable.NewReader(part)
	} else if cte != "" {
		log.Printf(" --- Error unknown encoding %s", cte)
	}
	data, err := ioutil.ReadAll(dr)
	if err != nil {
		log.Printf(" --- Error decoding %s: %s", cte, err)
	}
	return data
}

func _check_eicartxt(a attachment) bool {
	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	return regexp.MustCompile(`(?i)\.txt$`).Find([]byte(a.name)) != nil && strings.Contains(string(a.data), eicar)
}

func _check_zipname(a attachment) bool {
	return regexp.MustCompile(`(?i)\.zip$`).Find([]byte(a.name)) != nil
}
