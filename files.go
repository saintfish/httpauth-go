package httpauth

import (
	"encoding/csv"
	"os"
)

type file struct {
	Path string
	Info os.FileInfo
	/* must be set in inherited types during initialization */
	Reload func()
}

func (f *file) ReloadIfNeeded() {
	info, err := os.Stat(f.Path)
	if err != nil {
		panic(err)
	}
	if f.Info == nil || f.Info.ModTime() != info.ModTime() {
		f.Info = info
		f.Reload()
	}
}

/*
 Structure used for htdigest file authentication. Users map realms to
 maps of users to their HA1 digests.
*/
type htdigestFile struct {
	file
	Users map[string]map[string]string
}

func reload_htdigest(hf *htdigestFile) {
	r, err := os.Open(hf.Path)
	if err != nil {
		panic(err)
	}
	csv_reader := csv.NewReader(r)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		panic(err)
	}

	hf.Users = make(map[string]map[string]string)
	for _, record := range records {
		_, exists := hf.Users[record[1]]
		if !exists {
			hf.Users[record[1]] = make(map[string]string)
		}
		hf.Users[record[1]][record[0]] = record[2]
	}
}

/*
 SecretProvider implementation based on htdigest-formated files. Will
 reload htdigest file on changes. Will panic on syntax errors in
 htdigest files.
*/
func OpenHtdigest(filename string) PasswordLookup {
	hf := &htdigestFile{file: file{Path: filename}}
	hf.Reload = func() { reload_htdigest(hf) }
	return func(user, realm string) string {
		hf.ReloadIfNeeded()
		_, exists := hf.Users[realm]
		if !exists {
			return ""
		}
		digest, exists := hf.Users[realm][user]
		if !exists {
			return ""
		}
		return digest
	}
}
