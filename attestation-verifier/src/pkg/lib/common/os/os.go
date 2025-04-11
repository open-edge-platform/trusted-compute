/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package os

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// OpenFileSafe is a wapper to opens a file with the specified flags and
// permissions if it exists and checks path is not a symlink, or if it is
// a symlink, verifies the target path.  Meets SDLe requirement T572.
func OpenFileSafe(filePath string, expectedSymlinkTarget string, fileFlag int, filePerm os.FileMode) (*os.File, error) {
	// Check if the file exists
	fileInfo, err := os.Lstat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// The file doesn't exists, so attempt to create the file and return
			file, err := os.OpenFile(filePath, fileFlag|os.O_CREATE, filePerm)
			if err != nil {
				return nil, fmt.Errorf("error creating file: %w", err)
			}
			return file, nil
		}
		return nil, fmt.Errorf("error stating file: %w", err)
	}

	file, err := os.OpenFile(filePath, fileFlag, filePerm)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	// Since file exists, check if the file is a symlink
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		if expectedSymlinkTarget == "" {
			return nil, errors.New("file is a symlink but not expected to be")
		}

		// Resolve the symlink to its target
		targetPath, err := filepath.EvalSymlinks(filePath)
		if err != nil {
			return nil, fmt.Errorf("error resolving symlink: %w", err)
		}

		// Check if the symlink points to an expected path
		if targetPath != expectedSymlinkTarget {
			return nil, fmt.Errorf("symlink points to an unexpected path: %s", targetPath)
		}
	}

	// Now that checks passed we return the file handle
	return file, nil
}

// ChownR method is used to change the ownership of all the file in a directory
func ChownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}

// Copy the src file to dst. Any existing file will be overwritten and will not
// copy file attributes.
func Copy(src, dst string) error {
	in, err := OpenFileSafe(src, "", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() {
		derr := in.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	out, err := OpenFileSafe(dst, "", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		derr := out.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return nil
}

func GetDirFileContents(dir, pattern string) ([][]byte, error) {
	dirContents := make([][]byte, 0)
	//if we are passed in an empty pattern, set pattern to * to match all files
	if pattern == "" {
		pattern = "*"
	}

	err := filepath.Walk(dir, func(fPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, _ := path.Match(pattern, info.Name()); matched == true {
			if content, err := ioutil.ReadFile(fPath); err == nil {
				dirContents = append(dirContents, content)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(dirContents) == 0 {
		return nil, fmt.Errorf("did not find any files with matching pattern %s for directory %s", pattern, dir)
	}
	return dirContents, nil
}

func ChownDirForUser(serviceUserName, configDir string) error {
	svcUser, err := user.Lookup(serviceUserName)
	if err != nil {
		return errors.Wrapf(err, "Could not find service user '%s'", serviceUserName)
	}
	uid, err := strconv.Atoi(svcUser.Uid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user uid '%s'", svcUser.Uid)
	}
	gid, err := strconv.Atoi(svcUser.Gid)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service user gid '%s'", svcUser.Gid)
	}
	err = ChownR(configDir, uid, gid)
	if err != nil {
		return errors.Wrap(err, "Error while changing ownership of files inside config directory")
	}
	return nil
}
