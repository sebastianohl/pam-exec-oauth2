// Copyright © 2017 Shinichi MOTOKI
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"bufio"
	"context"

	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"

	"github.com/metal-stack/v"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// app name
const app = "pam-exec-oauth2"

// config define openid Connect parameters
// and setting for this module
type config struct {
	ClientID         string   `yaml:"client-id"`
	ClientSecret     string   `yaml:"client-secret"`
	RedirectURL      string   `yaml:"redirect-url"`
	Scopes           []string `yaml:"scopes"`
	EndpointAuthURL  string   `yaml:"endpoint-auth-url"`
	EndpointTokenURL string   `yaml:"endpoint-token-url"`
	UsernameFormat   string   `yaml:"username-format"`
	// AllowedRoles are OS level groups which must be present on the OS before
	DefaultGroups []string `yaml:"default-groups"`
	CreateUser   bool     `yaml:"createuser"`
}

type pamOAUTH struct {
	config *config
}

// main primary entry
func main() {
	p, err := newPamOAUTH()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("version: %s", v.V)

	err = p.run()
	if err != nil {
		log.Fatal(err)
	}
}

func (p *pamOAUTH) run() error {
	// pam module use variable PAM_USER to get userid
	username := os.Getenv("PAM_USER")

	pamtype := os.Getenv("PAM_TYPE")
	log.Printf("PAM_TYPE:%s", pamtype)
	if pamtype == "close_session" {
		err := deleteUser(username)
		if err != nil {
			return err
		}
		return nil
	}

	// add user here only if user is in passwd the login worked
	if p.config.CreateUser {
		err := createUser(username)
		if err != nil {
			return err
		}
	}

	password := ""
	// wait for stdin to get password from user
	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		password = s.Text()
	}

	// authentication agains oidc provider
	// load configuration from yaml config
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Scopes:       p.config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.config.EndpointAuthURL,
			TokenURL: p.config.EndpointTokenURL,
		},
		RedirectURL: p.config.RedirectURL,
	}

	// send authentication request to oidc provider
	log.Printf("call OIDC Provider and get token")

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		fmt.Sprintf(p.config.UsernameFormat, username),
		password,
	)
	if err != nil {
		return err
	}

	// check here is token vaild
	if !oauth2Token.Valid() {
		return fmt.Errorf("oauth2 authentication failed")
	}

	groups := []string{}
	groups = p.config.DefaultGroups
	err = modifyUser(username, groups)
	if err != nil {
		return fmt.Errorf("unable to add groups: %w", err)
	}

	log.Print("oauth2 authentication succeeded")
	return nil
}

func newPamOAUTH() (*pamOAUTH, error) {
	// get executable and path name
	// to determine the default config file
	ex, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exPath := filepath.Dir(ex)

	// initiate application parameters
	configFile := path.Join(exPath, app+".yaml")
	configFlg := flag.String("config", configFile, "config file to use")
	debug := false
	debugFlg := flag.Bool("debug", false, "enable debug")
	stdout := false
	stdoutFlg := flag.Bool("stdout", false, "log to stdout instead of syslog")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if stdoutFlg != nil {
		stdout = *stdoutFlg
	}

	if !stdout {
		// initiate logging
		sysLog, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, app)
		if err != nil {
			return nil, err
		}
		log.SetOutput(sysLog)
	}

	if debugFlg != nil {
		debug = *debugFlg
	}

	if configFlg != nil {
		log.Printf("using config file:%s", *configFlg)
		configFile = *configFlg
	}

	config, err := readConfig(configFile)
	if err != nil {
		return nil, err
	}
	if debug {
		log.Printf("config:%#v\n", config)
	}
	return &pamOAUTH{
		config: config,
	}, nil
}

// readConfig
// need file path from yaml and return config
func readConfig(filename string) (*config, error) {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal filecontent to config struct:%w", err)
	}
	return &c, nil
}


// createUser if it does not already exists
func createUser(username string) error {
	_, err := user.Lookup(username)
	if err != nil && err.Error() != user.UnknownUserError(username).Error() {
		return fmt.Errorf("unable to lookup user %w", err)
	}

	if err == nil {
		log.Printf("user %s already exists\n", username)
		return nil
	}

	useradd, err := exec.LookPath("/usr/sbin/useradd")

	if err != nil {
		return fmt.Errorf("useradd command was not found %w", err)
	}

	args := []string{"-m", "-s", "/bin/bash", "-c", app, username}
	cmd := exec.Command(useradd, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to create user output:%s %w", string(out), err)
	}
	return nil
}

// modifyUser add groups to the user
func modifyUser(username string, groups []string) error {
	_, err := user.Lookup(username)
	if err != nil && err.Error() != user.UnknownUserError(username).Error() {
		return fmt.Errorf("unable to lookup user %w", err)
	}

	if err != nil {
		return fmt.Errorf("user %s does not exists", username)
	}

	for _, group := range groups {
		_, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("group %s does not exists", group)
		}
	}

	usermod, err := exec.LookPath("/usr/sbin/usermod")

	if err != nil {
		return fmt.Errorf("usermod command was not found %w", err)
	}

	args := []string{"-a", "-G"}
	args = append(args, groups...)
	args = append(args, username)
	cmd := exec.Command(usermod, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to modify user output:%s %w", string(out), err)
	}
	return nil
}
func deleteUser(username string) error {
	u, err := user.Lookup(username)
	if err != nil && err.Error() != user.UnknownUserError(username).Error() {
		return fmt.Errorf("unable to lookup user %w", err)
	}

	if err != nil {
		log.Printf("user %s already deleted\n", username)
		// nolint:nilerr
		return nil
	}

	if u.Name != app {
		log.Printf("user %s was not created by %s\n", username, app)
		return nil
	}

	userdel, err := exec.LookPath("/usr/sbin/userdel")

	if err != nil {
		return fmt.Errorf("useradd command was not found %w", err)
	}

	args := []string{"-r", username}

	cmd := exec.Command(userdel, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to delete user output:%s %w", string(out), err)
	}
	return nil
}
