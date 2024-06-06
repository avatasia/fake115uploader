package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// 计算文件指定范围内的sha1值
func hashFileRange(f *os.File, signCheck string) (rangeHash string, e error) {
	defer func() {
		if err := recover(); err != nil {
			e = fmt.Errorf("hashFileRange() error: %v", err)
		}
	}()

	var start, end int64
	_, err := fmt.Sscanf(signCheck, "%d-%d", &start, &end)
	checkErr(err)
	if start < 0 || end < 0 || end < start {
		return "", fmt.Errorf("sign_check范围错误：%s", signCheck)
	}

	_, err = f.Seek(start, io.SeekStart)
	checkErr(err)
	h := sha1.New()
	_, err = io.CopyN(h, f, end-start+1)
	checkErr(err)

	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}

// 计算文件的sha1值
func hashSHA1(f *os.File) (blockHash, totalHash string, e error) {
	defer func() {
		if err := recover(); err != nil {
			e = fmt.Errorf("hashSHA1() error: %v", err)
		}
	}()

	// 计算文件最前面一个区块的sha1 hash值
	block := make([]byte, 128*1024)
	n, err := f.Read(block)
	checkErr(err)
	data := sha1.Sum(block[:n])
	blockHash = strings.ToUpper(hex.EncodeToString(data[:]))
	_, err = f.Seek(0, io.SeekStart)
	checkErr(err)

	// 计算整个文件的sha1 hash值
	h := sha1.New()
	_, err = io.Copy(h, f)
	checkErr(err)
	totalHash = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	return blockHash, totalHash, nil
}

// executeRemoteCommand executes a command on a remote server via SSH and returns the output
func executeRemoteCommand(sshClient *ssh.Client, cmd string) (string, error) {
	// 打印SSH客户端信息
	//fmt.Printf("SSH client: %v\n", sshClient)
	fmt.Printf("ssh cmd: %v\n", cmd)
	session, err := sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to run command: %v", err)
	}

	return stdoutBuf.String(), nil
}

// sha1FileRangeOnRemote computes the SHA1 of a file range on a remote server
func sha1FileRangeOnRemote(sshClient *ssh.Client, filePath string, start int64, length int64) (string, error) {
	// Check if the file exists
	existCmd := fmt.Sprintf(`[ -f "%s" ] && echo 1 || echo 0`, filePath)
	existOutput, err := executeRemoteCommand(sshClient, existCmd)
	if err != nil {
		return "", fmt.Errorf("failed to check file existence: %v", err)
	}

	exist := strings.TrimSpace(existOutput)
	if exist != "1" {
		return "", fmt.Errorf("file does not exist: %s", filePath)
	}
	// Build the remote command with the given start and length
	cmd := fmt.Sprintf(`dd if="%s" bs=1 skip=%d count=%d 2>/dev/null | sha1sum | awk '{ print $1 }'`, filePath, start, length)
	return executeRemoteCommand(sshClient, cmd)
}

func parseRange(rangeStr string) (int64, int64, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start value: %v", err)
	}

	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end value: %v", err)
	}

	if start > end {
		return 0, 0, fmt.Errorf("start value is greater than end value")
	}

	length := end - start + 1
	return start, length, nil
}
