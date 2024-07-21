package utils

import (
	"io/fs"
	"os"
)

func IsFile(fpath string) bool {
	fileInfo, err := os.Stat(fpath)
	if err != nil {
		return false
	}
	return fileInfo.Mode().IsRegular()
}

func ListFilesInDir(dirpath string) ([]fs.DirEntry, error) {
	dirEntries, err := os.ReadDir(dirpath)
	if err != nil {
		return []fs.DirEntry{}, err
	}

	files := []fs.DirEntry{}
	for _, dirEntry := range dirEntries {
		if dirEntry.Type().IsRegular() {
			files = append(files, dirEntry)
		}
	}
	return files, nil
}
