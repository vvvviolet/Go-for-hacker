package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func check(err error) {
	if err != nil {
		fmt.Println("err")
		os.Exit(1)
	}
}
func main() {
	args := os.Args
	f, err := os.Open(args[0]) //创建文件句柄
	check(err)
	pefile, err := pe.NewFile(f) //创建pe文件对象
	check(err)
	defer f.Close()
	defer pefile.Close()
	dosHeader := make([]byte, 96)
	sizeOffset := make([]byte, 4)
	_, err = f.Read(dosHeader)
	check(err)
	fmt.Println("[-----DOS Header / Stub-----]")
	fmt.Printf("[+] Magic Value: %s%s\n", string(dosHeader[0]), string(dosHeader[1]))

	//验证PE+0+0 有效的PE格式
	pe_sig_offset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:]))
	// println(pe_sig_offset)
	f.ReadAt(sizeOffset[:], pe_sig_offset)
	fmt.Println("[-----Signature Header-----]")
	fmt.Printf("[+] LFANEN Value: %s\n", string(sizeOffset))

	//创建reader并读取COFF标头
	sr := io.NewSectionReader(f, 0, 1<<63-1)
	_, err = sr.Seek(pe_sig_offset+4, os.SEEK_SET)
	check(err)
	binary.Read(sr, binary.LittleEndian, &pefile.FileHeader)

	//打印文件表头
	fmt.Println("[-----COFF File Header-----]")
	fmt.Printf("[+] Machine Architecture(机器架构): %#x\n", pefile.FileHeader.Machine)
	fmt.Printf("[+] Number of Sections(分区数目): %#x\n", pefile.FileHeader.NumberOfSections)
	fmt.Printf("[+] Size of Optional Header(可选头大小): %#x\n", pefile.FileHeader.SizeOfOptionalHeader)
	//打印小节名称
	fmt.Println("[-----Section Offsets-----]")
	fmt.Printf("[+] Section Table Offset(分区表偏移量): %#x\n", pe_sig_offset+0xf8)

	//解析可选头
	//一个可执行二进制映像只有一个可选头，它向加载程序提供重要数据

	//获取oh大小
	var (
		sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
		sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))
		oh32                   pe.OptionalHeader32
		oh64                   pe.OptionalHeader64
	)

	//读取oh
	fmt.Println("[-----Optional Header-----]")
	switch pefile.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		// println(32)
		binary.Read(sr, binary.LittleEndian, &oh32)
	case sizeofOptionalHeader64:
		// println(64)
		binary.Read(sr, binary.LittleEndian, &oh64)
		fmt.Printf("[+] Entry Point: %#x\n", oh64.AddressOfEntryPoint)
		fmt.Printf("[+] ImageBase: %#x\n", oh64.ImageBase) //映像基址 .exe为0x400000 .dll为0x10000000
		//假如要对PE文件进行后门操作，需要ImageBase和Entry Point，以便劫持和内存跳转到shellcode的位置
		//或者由分区表条目数定义的新分区
		fmt.Printf("[+] Size of Image: %#x\n", oh64.SizeOfImage)
		fmt.Printf("[+] Sections Alignment: %#x\n", oh64.SectionAlignment)
		//将分区加载到内存的时候，Section Alignment将提供字节对齐
		fmt.Printf("[+] File Alignment: %#x\n", oh64.FileAlignment)
		//File Alignment提供原始磁盘上各分区字节对齐方式
		fmt.Printf("[+] Characteristics: %#x\n", pefile.FileHeader.Characteristics)
		fmt.Printf("[+] Size of Headers: %#x\n", oh64.SizeOfHeaders)
		fmt.Printf("[+] Checksum: %#x\n", oh64.CheckSum)
		fmt.Printf("[+] Machine: %#x\n", pefile.FileHeader.Machine)
		fmt.Printf("[+] Subsystem: %#x\n", oh64.Subsystem)
		fmt.Printf("[+] DLLCharacteristics: %#x\n", oh64.DllCharacteristics)
	}
	/*全面了解可选头：https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only*/

	//打印数据目录
	fmt.Println("[-----Data Directory-----]")
	var winnt_datadirs = []string{
		"IMAGE_DIRECTORY_ENTRY_EXPORT",
		"IMAGE_DIRECTORY_ENTRY_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_RESOURCE",
		"IMAGE_DIRECTORY_ENTRY_EXCEPTION",
		"IMAGE_DIRECTORY_ENTRY_SECURITY",
		"IMAGE_DIRECTORY_ENTRY_BASERELOC",
		"IMAGE_DIRECTORY_ENTRY_DEBUG",
		"IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
		"IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
		"IMAGE_DIRECTORY_ENTRY_TLS",
		"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
		"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_IAT",
		"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_COM_DESCRIBER",
		"IMAGE_NUMBEROF_DIRECTORY_ENTRIES",
	}

	for idx, directory := range oh64.DataDirectory {
		fmt.Printf("[!] Data Directory: %s\n", winnt_datadirs[idx])
		fmt.Printf("[+] Image Virtual Address: %#x\n", directory.VirtualAddress)
		fmt.Printf("[+] Image Size: %#x\n", directory.Size)
	}
	//解析分区表
	//分区表包含Windows可执行二进制文件中每个相关分区的详细信息
	//例如可执行代码和初始化的数据位置偏移量
	//遍历整个分区表
	fmt.Println("[-----Section Table-----]")
	for _, section := range pefile.Sections {
		fmt.Println("[+]---------------------------")
		fmt.Printf("[+] Section Name: %s\n", section.Name)
		fmt.Printf("[+] Section Characteristics): %#x\n", section.Characteristics)
		fmt.Printf("[+] Section Virtual Size: %#x\n", section.VirtualSize)
		fmt.Printf("[+] Section Virtual Offset: %#x\n", section.VirtualAddress)
		fmt.Printf("[+] Section Raw Size: %#x\n", section.Size)
		fmt.Printf("[+] Section Raw Offset to Data: %#x\n", section.Offset)
		fmt.Printf("[+] Section Append Offset(Next Section): %#x\n", section.Offset+section.Size)
	}

}
