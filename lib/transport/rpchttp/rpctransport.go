package rpchttp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/staaldraad/go-ntlm/ntlm"
	"github.com/staaldraad/rpchproxy/lib/utils"
)

var rpcInConn net.Conn
var rpcOutConn net.Conn
var rpcInR, rpcInW = io.Pipe()
var rpcOutR, rpcOutW = io.Pipe()
var rpcRespBody *bufio.Reader
var callcounter int

var httpResponses = make([][]byte, 0)
var rpcntlmsession ntlm.ClientSession
var fragged bool
var mutex = &sync.Mutex{}
var writemutex = &sync.Mutex{}

var User string
var Domain string
var Pass string
var Email string
var NTHash []byte

func setupHTTP(rpctype string, URL string, ntlmAuth bool, full bool) (net.Conn, error) {
	u, err := url.Parse(URL)
	var connection net.Conn
	if u.Scheme == "http" {
		connection, err = net.Dial("tcp", fmt.Sprintf("%s:80", u.Host))
	} else {
		conf := tls.Config{InsecureSkipVerify: true}
		connection, err = tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), &conf)
	}

	if err != nil {
		return nil, fmt.Errorf("RPC Setup Err: %s", err)
	}
	var request string

	if full == true {
		request = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", rpctype, u.String(), u.Host)
	} else {
		request = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", rpctype, u.RequestURI(), u.Host)
	}

	request = fmt.Sprintf("%sUser-Agent: MSRPC\r\n", request)
	request = fmt.Sprintf("%sCache-Control: no-cache\r\n", request)
	request = fmt.Sprintf("%sAccept: application/rpc\r\n", request)
	request = fmt.Sprintf("%sConnection: keep-alive\r\n", request)

	var authenticate *ntlm.AuthenticateMessage
	if ntlmAuth == true {

		//we should probably extract the NTLM type from the server response and use appropriate
		session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
		b, _ := session.GenerateNegotiateMessage()

		if err != nil {
			return nil, err
		}

		//add NTML Authorization header
		requestInit := fmt.Sprintf("%sAuthorization: NTLM %s\r\n", request, utils.EncBase64(b.Bytes()))
		requestInit = fmt.Sprintf("%sContent-Length: 0\r\n\r\n", requestInit)

		//send connect
		connection.Write([]byte(requestInit))
		//read response
		data := make([]byte, 2048)
		_, err = connection.Read(data)
		if err != nil {
			if full == false {
				return nil, fmt.Errorf("Failed with initial setup for %s : %s\n", rpctype, err)
			}
			//utils.Trace.Printf("Failed with initial setup for %s trying again...\n", rpctype)
			return setupHTTP(rpctype, URL, ntlmAuth, false)
		}

		parts := strings.Split(string(data), "\r\n")
		ntlmChallengeHeader := ""
		for _, v := range parts {
			if n := strings.Split(v, ": "); len(n) > 0 {
				if n[0] == "WWW-Authenticate" {
					ntlmChallengeHeader = n[1]
					break
				}
			}
		}
		//utils.Trace.Println(string(data))

		ntlmChallengeString := strings.Replace(ntlmChallengeHeader, "NTLM ", "", 1)
		challengeBytes, err := utils.DecBase64(ntlmChallengeString)
		if err != nil {
			if full == false {
				return nil, fmt.Errorf("Failed with initial setup for %s : %s\n", rpctype, err)
			}
			utils.Fail.Printf("Failed with initial setup for %s trying again...\n", rpctype)
			return setupHTTP(rpctype, URL, ntlmAuth, false)
		}

		session.SetUserInfo(User, Pass, Domain)
		if len(NTHash) > 0 {
			session.SetNTHash(NTHash)
		}

		// parse NTLM challenge
		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			return nil, err
		}
		err = session.ProcessChallengeMessage(challenge)
		if err != nil {
			return nil, err
		}
		// authenticate user
		authenticate, err = session.GenerateAuthenticateMessage()

		if err != nil {
			utils.Error.Println("Authentication Err")
			return nil, err
		}
	}

	if rpctype == "RPC_IN_DATA" {
		request = fmt.Sprintf("%sContent-Length: 1073741824\r\n", request)
	} else if rpctype == "RPC_OUT_DATA" {
		request = fmt.Sprintf("%sContent-Length: 76\r\n", request)
	}

	if ntlmAuth == true {
		request = fmt.Sprintf("%sAuthorization: NTLM %s\r\n\r\n", request, utils.EncBase64(authenticate.Bytes()))
	} else {
		if u.Host == "outlook.office365.com" {
			request = fmt.Sprintf("%sAuthorization: Basic %s\r\n\r\n", request, utils.EncBase64([]byte(fmt.Sprintf("%s:%s", Email, Pass))))
		} else {
			request = fmt.Sprintf("%sAuthorization: Basic %s\r\n\r\n", request, utils.EncBase64([]byte(fmt.Sprintf("%s\\%s:%s", Domain, User, Pass))))
		}
	}

	connection.Write([]byte(request))

	return connection, nil
}

//RPCOpen opens HTTP for RPC_IN_DATA and RPC_OUT_DATA
func RPCOpen(URL string, readySignal chan bool, errOccurred chan error) (err error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it

	rpcInConn, err = setupHTTP("RPC_IN_DATA", URL, false, true)

	if err != nil {
		readySignal <- false
		errOccurred <- err
		return err
	}

	//open the RPC_OUT_DATA channel, receive a "ready" signal when this is setup
	//this will be sent back to the caller through "readySignal", while error is sent through errOccurred
	go RPCOpenOut(URL, readySignal, errOccurred)

	select {
	case c := <-readySignal:
		if c == true {
			readySignal <- true
		} else {
			readySignal <- false
			return err
		}
	case <-time.After(time.Second * 5): // call timed out
		readySignal <- true
	}

	for {
		data := make([]byte, 2048)
		n, err := rpcInR.Read(data)
		if n > 0 {
			_, err = rpcInConn.Write(data[:n])
		}
		if err != nil && err != io.EOF {
			utils.Error.Println("RPCIN_ERROR: ", err)
			break
		}
	}
	return nil
}

//RPCOpenOut function opens the RPC_OUT_DATA channel
//starts our listening "loop" which scans for new responses and pushes
//these to our list of recieved responses
func RPCOpenOut(URL string, readySignal chan<- bool, errOccurred chan<- error) (err error) {

	rpcOutConn, err = setupHTTP("RPC_OUT_DATA", URL, false, true)
	if err != nil {
		readySignal <- false
		errOccurred <- err
		return err
	}

	scanner := bufio.NewScanner(rpcOutConn)
	scanner.Split(SplitData)

	for scanner.Scan() {
		if b := scanner.Bytes(); b != nil {
			if string(b[0:4]) == "HTTP" {
				httpResponses = append(httpResponses, b)
			}

			mutex.Lock() //lets be safe, lock the responses array before adding a new value to it
			//write to our tcp client socket
			mutex.Unlock()
		}
	}

	return nil
}

//RPCInWrite function writes to our RPC_IN_DATA channel
func RPCInWrite(data []byte) {
	callcounter++
	writemutex.Lock() //lets be safe, don't think this is strictly necessary
	rpcInW.Write(data)
	writemutex.Unlock()
	time.Sleep(time.Millisecond * 300)
}

//RPCOutWrite function writes to the RPC_OUT_DATA channel,
//this should only happen once, for ConnA1
func RPCOutWrite(data []byte) {
	if rpcOutConn != nil {
		writemutex.Lock() //lets be safe, don't think this is strictly necessary
		rpcOutConn.Write(data)
		writemutex.Unlock()
		time.Sleep(time.Millisecond * 300)
	}
}

//RPCRead function takes a call ID and searches for the response in
//our list of received responses. Blocks until it finds a response
func RPCOutRead() error {
	return nil
}

//SplitData is used to scan through the input stream and split data into individual responses
func SplitData(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	//check if HTTP response
	if string(data[0:4]) == "HTTP" {
		for k := range data {
			if bytes.Equal(data[k:k+4], []byte{0x0d, 0x0a, 0x0d, 0x0a}) {
				if bytes.Equal(data[k+4:k+5], []byte{0x31}) { //check if there is fragmentation
					fragged = true
				}
				return k + 4, data[0:k], nil //return the HTTP packet
			}
		}
	}

	if fragged {
		dbuf := []byte{}
		offset := 10 //the default offset for the location of the fragment length
		//find next 0x0d,0x0a
		for k := 0; k < len(data); k++ {
			if bytes.Equal(data[k:k+3], []byte{0x31, 0x0d, 0x0a}) { //this is a part of a fragment
				dbuf = []byte{0x05} //start the new fragment
				offset = 9          //adjust the offset, because the rest of the packet is in another fragment
				k += 4              //jump ahead to the next fragment
				continue
			} else if bytes.Equal(data[k:k+2], []byte{0x0d, 0x0a}) { //we have a fragment
				if len(data) < 12 { //check that there is enough data
					return 0, nil, nil
				}
				//get the length of the fragment
				fragLen := int(utils.DecodeUint16(data[k+offset : k+offset+2]))
				if offset == 9 { //we already have the start of the fragment, so adjust the length by 1
					fragLen--
				}

				if len(data) < fragLen { //check that there is enough data to read
					return 0, nil, nil //not enough data, restart the scan
				}

				dbuf = append(dbuf, data[k+2:k+fragLen+2]...) //get the fragment data
				if offset == 9 {                              //multiple fragments, so adjust the offset
					return k + len(dbuf) + 2, dbuf, nil
				}
				return k + len(dbuf) + 4, dbuf, nil //return the rpcpacket and the new scan position
			}
		}
	} else if !fragged && !atEOF { //there is no fragmentation
		if len(data) < 12 { //check that we have enough data
			return 0, nil, nil
		}
		fragLen := int(utils.DecodeUint16(data[8:10])) //get the length of the RPC packet

		if len(data) < fragLen { //check that we have enough data
			return 0, nil, nil
		}
		dbuf := []byte{}
		dbuf = append(dbuf, data[:fragLen]...) //read rpc packet

		return len(dbuf), dbuf, nil //return current position and rpc packet
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}
