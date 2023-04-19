e_ident 16字节
Elf32_Half和Elf64_Half都占2字节
Elf64_Word 4字节
Elf64_Addr 8字节
Elf64_Off 8字节
Elf64_Xword 8字节


entry offset = 0x18
entry = 0x1440

phoff offset = 0x20
phoff = 0x40

shoff offset = 0x28
shoff = 0x5060

插入的加密后的ELF文件大小为7030字节

e_phnum offset in elf header = 0x38
e_phnum = 0xd = 13

new entry = 0x1440 + 0x7030 = 0x8470
new phoff = 0x40 + 0x7030 = 0x7070
new shoff = 0x5060 + 0x7030 = 0xC090

struct Elf64_Phdr 的大小为 56 字节（0x38）

[segment 1]
Program Header offset = 0x7070
p_offset offset(elf64) in Program Header = 0x8
p_offset at 0x7078
p_offset = 0x40
new p_offset = 0x40 + 0x7030 = 0x7070
p_vaddr at 0x7080
p_vaddr = 0x40
new p_vaddr = 0x40 + 0x7030 = 0x7070



[segment 2]
Program Header offset = 0x70a8
p_offset offset(elf64) in Program Header = 0x8
p_offset at 0x70b0
p_offset = 0x318
new p_offset = 0x318 + 0x7030 = 0x7348

[segment 3]
Program Header offset = 
p_offset at 0x70e8
p_offset = 0x0 + 0x7030 = 0

[segment 4]
Program Header offset = 0x
p_offset at 0x7120
p_offset = 0x1000 + 0x7030 = 0x8030

[segment 5]
Program Header offset = 0x
p_offset at 0x7158
p_offset = 0x3000 + 0x7030 = 0XA030

[segment 6]
Program Header offset = 0x
p_offset at 0x7190
p_offset = 0x3CC0 + 0x7030 = 0xA030

[segment 7]
Program Header offset = 0x
p_offset at 0x71c8
p_offset = 0x3cd0 + 0x7030 = 0xAD00

[segment 8]
Program Header offset = 0x
p_offset at 0x7200
p_offset = 0x338 + 0x7030 = 0x7368

[segment 9]
Program Header offset = 0x
p_offset at 0x7238
p_offset = 0x358 + 0x7030 = 0x7388

[segment 10]
Program Header offset = 0x
p_offset at 0x7270
p_offset = 0x338 + 0x7030 = 0x7368

[segment 11]
Program Header offset = 0x
p_offset at 0x72A8
p_offset = 0x30D4 + 0x7030 = 0xA104

[segment 12]
Program Header offset = 0x
p_offset at 0x72E0
p_offset = 0x0 + 0x7030 = 0x0

[segment 13]
Program Header offset = 0x
p_offset at 0x7318
p_offset = 0x3CC0 + 0x7030 = 0xACF0
