require 'elftools'

# to-do: try https://venus.kvakil.me

# to-dos:
# move instructions to a file, load them from a file

# ideas: implement a cache for decoded instructions

# 0x98a20893 addi x17, x4, -1654
# 0x00820293 addi x5, x4, 8
# 0xb4162593 slti x11, x12, -1215
# 0x078ec813 xori x16, x29, 120
# 0xae7f6a93 ori x21, x30, -1305
# 0x593d7493 andi x9, x26, 1427
# 0x00881813 slli x16, x16, 8
# 0x0018d893 srli x17, x17, 1
# 0x405ada93 srai x21, x21, 5
# 0x003100b3 add x1, x2, x3
# 0x015807b3 add x15, x16, x21
# 0x40f80733 sub x14, x16, x15
# 0x410786b3 sub x13, x15, x16
# 0x00571633 sll x12, x14, x5
# 0x01161533 sll x10, x12, x17
# 0x00a625b3 slt x11, x12, x10
# 0x00a6b4b3 sltu x9, x13, x10
# 0x00d644b3 xor x9, x12, x13
# 0x00555433 srl x8, x10, x5
# 0x011653b3 srl x7, x12, x17
# 0x4053d333 sra x6, x7, x5
# 0x4116d5b3 sra x11, x13, x17
# 0x01186933 or x18, x16, x17
# 0x0107f9b3 and x19, x15, x16
# 0x1e900a23 sb x9, 500(x0)
# 0x1f4a0f03 lb x30, 500(x20)
# 0x1ea01c23 sh x10, 504(x0)
# 0x1ed02e23 sw x13, 508(x0)
# 0x1fc02a03 lw x20, 508(x0)
# 0x1f401b03 lh x22, 500(x0)
# 0x1f404b83 lbu x23, 500(x0)
# 0x1fc05c03 lhu x24, 508(x0)
# 0x000010b7 lui x1, 1
# 0x00000f97 auipc x31, 0
# 0x80000cb7 lui x25, 524288
# 0xfffc8c93 addi x25, x25, -1
# 0x001c8c93 addi x25, x25, 1
# 0x80000d37 lui x26, 524288
# 0x000d0d13 addi x26, x26, 0
# 0xfffd0d13 addi x26, x26, -1
# 0xfff00d93 addi x27, x0, -1
# 0x001d8d93 addi x27, x27, 1
# 0xfff00e13 addi x28, x0, -1
# 0x01ce0eb3 add, x29, x28, x28
# 0x9f400167 jalr x2, x0, -1548

def sign_extend(x, l)
  if x >> (l - 1) == 1
    return -((1 << l) - x)
  else
    return x
  end
end

def invalid_opcode(opcode)
  abort "unknown/invalid/unsupported opcode!: #{sprintf('0x%08x', opcode)}"
end

def unsigned(value)
  value & 0xffffffff
end

def print_value(value)
  if value <= (2 ** 31) - 1
    return value
  end
  -(("0b#{32.downto(0).map { |n| (~value)[n] }.join}".to_i(2) & 0x7fffffff) + 1)
end

def offset(instruction)
  imm1_4      = instruction >>  8 & 0x0f
  imm5_10     = instruction >> 25 & 0x3f
  imm11       = instruction >>  7 & 0x01
  imm12 = msb = instruction >> 31

  value = ((imm12 << 11) | (imm11 << 10) | (imm5_10 << 4) | (imm1_4)) << 1

  msb.nonzero? ?  value - 2**13 : value
end

def b_immediate(instruction)
  offset(instruction)
end

def j_type_offset(imm)
  imm20 = msb = imm & 0x80000
  imm19_12    = (imm & 0xff) << 11
  imm11       = (imm & 0x100) << 2
  imm10_1     = (imm >> 9 & 0x3ff)

  value = (imm20 | imm19_12 | imm11 | imm10_1) << 1

  msb.nonzero? ? value - 2**21 : value
end

def j_immediate(imm)
  j_type_offset(imm)
end

def abi_name(name)
  regs = {
    zero: 0,
    ra:   1,
    sp:   2,
    gp:   3,
    tp:   4,
    t0:   5,
    t1:   6,
    t2:   7,
    s0:   8,
    fp:   8,
    s1:   9,
    a0:  10,
    a1:  11,
    a2:  12,
    a3:  13,
    a4:  14,
    a5:  15,
    a6:  16,
    a7:  17,
    s2:  18,
    s3:  19,
    s4:  20,
    s5:  21,
    s6:  22,
    s7:  23,
    s8:  24,
    s9:  25,
    s10: 26,
    s11: 27,
    t3:  28,
    t4:  29,
    t5:  30,
    t6:  31,
  }.fetch(name)
end

def register(name)
  value = @registers.fetch(name.respond_to?(:to_i) ? name.to_i : abi_name(name))
  sprintf("0x%08x", value)
end

module EBreak
  MB = 2**18
  LOAD   = 0x03
  FENCE  = 0x0f
  OP_IMM = 0x13
  AUIPC  = 0x17
  STORE  = 0x23
  OP     = 0x33
  LUI    = 0x37
  BRANCH = 0x63
  JALR   = 0x67
  JAL    = 0x6f
  SYSTEM = 0x73
  ADDI = ADD = 0x00
  SLTI = SLT = 0x02
  SLTIU = SLTU = 0x03
  XORI = XOR = 0x04
  ORI  =  OR = 0x06
  ANDI = AND = 0x07
  SLLI = SLL = 0x01
  SR   = 0x05
  SRLI = SRL = 0x00
  SRAI = SRA = 0x10
  SUB  = 0x10
  SB   = LB = 0x00
  SH   = LH = 0x01
  SW   = LW = 0x02
  LBU  = 0x04
  LHU  = 0x05
  ECALL  = 0x00
  EBREAK = 0x01
  MRET   = 0x302
  BEQ  = 0x00
  BNE  = 0x01
  BLT  = 0x04
  BGE  = 0x05
  BLTU = 0x06
  BGEU = 0x07
  CSRRW  = 0x01
  CSRRS  = 0x02
  CSRRWI = 0x05
  MHARTID = 0xf14
  MEPC    = 0x341
end

module EBreak
  Instruction = Struct.new('Instruction', :word) do
    attr_reader :opcode, :funct3, :rd, :rs1
    def initialize(*args)
      super(*args)
      decode
    end
    def decode
      @opcode = word & 0x7f

      ignore = -1
      @rd = word >> 7 & 0x1f unless [BRANCH, STORE].include?(opcode)
      @rd = ignore if !@rd.nil? && @rd.zero? &&![FENCE, SYSTEM].include?(opcode)

      @funct3 = word >> 12 & 0x07 unless [AUIPC, LUI, JAL].include?(opcode)
      @rs1    = word >> 15 & 0x1f unless [AUIPC, LUI, JAL].include?(opcode)

      case @opcode
      when OP # R-type instructions
        @rs2    = word >> 20 & 0x1f
        @funct7 = word >> 26
        invalid_opcode(word) unless @funct7.zero? || @funct7 == SUB
        additional_attr_reader :rs2, :funct7
      when OP_IMM # I-type instructions
        @imm = sign_extend(word >> 20 & 0x0fff, 12)
        additional_attr_reader :imm
        case @funct3
        when SLLI
          @shamt = word >> 20 & 0x1f
          additional_attr_reader :shamt
        when SR
          @shamt  = word >> 20 & 0x1f
          @funct6 = word >> 26 & 0x3f
          invalid_opcode(word) unless [SRLI, SRAI].include?(@funct6)
          additional_attr_reader :shamt, :funct6
        end
      when LOAD, JALR # I-type instructions
        valid_load_ops = [LB, LH, LW, LBU, LHU]
        invalid_opcode(word) if @opcode == LOAD && !valid_load_ops.include?(@funct3)
        invalid_opcode(word) if @opcode == JALR && @funct3.nonzero?
        @imm = sign_extend(word >> 20 & 0x0fff, 12)
        additional_attr_reader :imm
      when STORE # S-type instructions
        @rs2    = word >> 20 & 0x1f
        @offset = ((word >> 25) << 5) | (word >> 7 & 0x1f)
        additional_attr_reader :rs2, :offset
      when BRANCH # B-type instructions
        valid_ops = [BEQ, BNE, BLT, BGE, BLTU, BGEU]
        invalid_opcode(word) unless valid_ops.include?(@funct3)
        @rs2    = word >> 20 & 0x1f
        @offset = b_immediate(word)
        additional_attr_reader :rs2, :offset
      when LUI, AUIPC # U-type instructions
        @imm = (word >> 12) << 12
        additional_attr_reader :imm
      when JAL # J-type instructions
        @offset = j_immediate(word >> 12)
        additional_attr_reader :offset
      when FENCE
        invalid_opcode(word) if @funct3.zero? && [@rd, @rs1].any?(:nonzero)
      when SYSTEM
        invalid_opcode(word) if @funct3.zero? && [@rd, @rs1].any?(:nonzero)
        invalid_opcode(word) if @funct3 == 0x4
        @funct12 = word >> 20 & 0xfff
        # to-do: set a constant for 0 and 1?
        invalid_opcode(word) if @funct3.zero? && ![ECALL, EBREAK, MRET].include?(@funct12)
        additional_attr_reader :funct12
      else
        # to-do: should raise a cpu exception for illegal instructions
        # for now, just increase the PC
        invalid_opcode(word) unless word.zero?
      end
    end
    def inspect
      sprintf("#<Instruction word=0x%08x>", word)
    end
    private
    def additional_attr_reader(*syms)
      singleton_class.class_eval { attr_reader *syms }
    end
  end
end

module EBreak
class Hart
  def initialize(file)
    # @instructions = [0x98a20893, 0x00820293, 0xb4162593, 0x078ec813, 0xae7f6a93, 0x593d7493, 0x00881813, 0x0018d893, 0x405ada93, 0x003100b3, 0x015807b3, 0x40f80733, 0x410786b3, 0x00571633, 0x01161533, 0x00a625b3, 0x00a6b4b3, 0x00d644b3, 0x00555433, 0x011653b3, 0x4053d333, 0x4116d5b3, 0x01186933, 0x0107f9b3, 0x1e900a23, 0x1f4a0f03, 0x1ea01c23, 0x1ed02e23, 0x1fc02a03, 0x1f401b03, 0x1f404b83, 0x1fc05c03, 0x000010b7, 0x00000f97, 0x9f400167---, 0x80000cb7, 0xfffc8c93, 0x001c8c93, 0x80000d37, 0x000d0d13, 0xfffd0d13]
ARGV[0]
    if !file.nil?
      elf = ELFTools::ELFFile.new(File.open(file))
      @instructions_ = elf.section_by_name('.text.init').data.scan(/.{4}/m).map { |w| w.unpack1("L<") }
      @data = elf.section_by_name('.data')
      if @data
        @data_pos = @data.header[:sh_addr].to_i
        @data_ = @data.data.scan(/.{4}/m).map { |w| w.unpack1("L<") }
      end
    end
    @instructions = [0x98a20893, 0x00820293, 0xb4162593, 0x078ec813, 0xae7f6a93, 0x593d7493, 0x00881813, 0x0018d893, 0x405ada93, 0x003100b3, 0x015807b3, 0x40f80733, 0x410786b3, 0x00571633, 0x01161533, 0x00a625b3, 0x00a6b4b3, 0x00d644b3, 0x00555433, 0x011653b3, 0x4053d333, 0x4116d5b3, 0x01186933, 0x0107f9b3, 0x1e900a23, 0x1f4a0f03, 0x1ea01c23, 0x1ed02e23, 0x1fc02a03, 0x1f401b03, 0x1f404b83, 0x1fc05c03, 0x000010b7, 0x00000f97, 0x80000cb7, 0xfffc8c93, 0x001c8c93, 0x80000d37, 0x000d0d13, 0xfffd0d13, 0xfff00d93, 0x001d8d93, 0xfff00e13, 0x01ce0eb3, 0x9f400167]
    if !file.nil?
      @instructions = @instructions_
      @memory_map = true
    end
    @memory_map = false if file.nil?
    @registers = Array.new(32 + 1, 0)
    @registers[0] = 0
    @memory = Array.new(1 * MB, 0x00000000)
    # hack, remove...
    i = 0
    @instructions.each { |word| @memory[i] = word; i += 1 }
    @pc = @memory_map ? 0x80000000 : 0
    # to-do: I think I'm going to need to wrap the csr values to have ro,rw flags, etc
    @csr = Array.new(4096, 0x00000000)
    @csr[MHARTID] = 0x0
    # hack, remove...
    i = 0
    if @data
      abort "memory issue" if @data_pos < 0x80000000
      location = (@data_pos - 0x80000000) / 4
      abort "memory issue" if location > @memory.length
      @data_.each { |word| @memory[location + i] = word; i += 1 }
    end
  end
  def fetch_instruction
    if @memory_map
      Instruction.new(read_memory(@pc))
    else
      Instruction.new(@memory[@pc / 4] || 0x0) # to-do: fix
    end
  end
  def read_memory(addr)
    return @memory[addr / 4] unless @memory_map
    pos = addr - 0x80000000
    @memory[pos / 4]
  end
  def store_byte(addr, byte)
    pos = addr - 0x80000000
    mem = @memory[pos / 4]
    m = addr % 4
    mask = ((0xffffffff >> (m + 1) * 8) << (m + 1) * 8) | (0xffffffff >> (4 - m) * 8)
    @memory[pos / 4] = (mem & mask) | (byte << m * 8)
  end
  def store_hw(addr, half_word)
    abort "#{addr}: address misaligned" unless addr.even?
    pos = addr - 0x80000000
    mem = @memory[pos / 4]
    shamt = addr % 4 * 8
    @memory[pos / 4] = (mem & (0xffff << (shamt - 16).abs)) | (half_word << shamt)
  end
  def store_word(addr, word)
    abort "#{addr}: address misaligned" unless (addr % 4).zero?
    pos = addr - 0x80000000
    @memory[pos / 4] = word
  end
  def reset
    @i = 0
    loop do
      # stop_at 0x800001f4
      # stop_at 0x800001f8
      # stop_at 0x800001fc
      # stop_at 0x80000200
      # binding.irb if @pc == 0x80000194
      @i += 1
      puts @pc.to_s(16)
      instruction = fetch_instruction
      puts "fetch: #{sprintf('0x%08x', instruction.word)}"
      @registers[10] = -2**31 if @pc == 0x8000012c
      case instruction.opcode
      when LOAD   then load(instruction)
      when STORE  then store(instruction)
      when OP_IMM then op_imm(instruction)
      when OP     then op(instruction)
      when FENCE  then fence(instruction)
      when SYSTEM then system(instruction)
      when BRANCH then branch(instruction)
      when LUI    then lui(instruction)
      when AUIPC  then auipc(instruction)
      when JAL    then jal(instruction)
      when JALR   then jalr(instruction)
      else
        # to-do: remove else once decode don't return 0x00 instructions
        puts "warning: null instruction" if instruction.word.zero?
        dump_all unless instruction.word.zero?
        invalid_opcode(instruction) unless instruction.word.zero?
        break if instruction.word.zero?
      end
    end
    dump_all
  end
  def op_imm(instruction)
    i = instruction
    case i.funct3
    when ADDI then @registers[i.rd] = (@registers[i.rs1] + i.imm) & 0xffffffff
    when SLTI then @registers[i.rd] = sign_extend(@registers[i.rs1], 32) < sign_extend(i.imm, 12) ? 1 : 0
    when XORI then @registers[i.rd] = (@registers[i.rs1] ^ i.imm) & 0xffffffff
    when ORI  then @registers[i.rd] = (@registers[i.rs1] | i.imm) & 0xffffffff
    when ANDI then @registers[i.rd] = @registers[i.rs1] & i.imm
    when SLTIU then @registers[i.rd] = @registers[i.rs1] < (sign_extend(i.imm, 32) & 0xffffffff) ? 1 : 0
    when SLLI then @registers[i.rd] = (@registers[i.rs1] << i.shamt) & 0xffffffff
    when SR
      case i.funct6
      when SRLI then @registers[i.rd] = unsigned(@registers[i.rs1]) >> i.shamt
      when SRAI
        shift = @registers[i.rs1] >> i.shamt
        @registers[i.rd] = if (@registers[i.rs1] & 0x80000000).zero?
          shift
        else
          (((2 ** i.shamt) - 1) << (32 - i.shamt)) | shift
        end
      end
    end
    @pc += 4
  end
  def load(instruction)
    i = instruction
    addr = @registers[i.rs1] + i.imm
    case i.funct3
    when LB
      byte = ((read_memory(addr) & (0xff << addr % 4 * 8)) >> addr % 4 * 8)
      @registers[i.rd] = sign_extend(byte, 8) & 0xffffffff
    when LBU
      byte = ((read_memory(addr) & (0xff << addr % 4 * 8)) >> addr % 4 * 8)
      @registers[i.rd] = sign_extend(byte, 8) & 0xff
    when LH
      abort "#{addr}: address misaligned" unless addr.even?
      @registers[i.rd] = sign_extend(((read_memory(addr) & (0xffff << addr % 4 * 8)) >> addr % 4 * 8), 16) & 0xffffffff
    when LHU
      abort "#{addr}: address misaligned" unless addr.even?
      @registers[i.rd] = ((read_memory(addr) & (0xffff << addr % 4 * 8)) >> addr % 4 * 8) & 0xffff
    when LW
      abort "#{addr}: address misaligned" unless (addr % 4).zero?
      @registers[i.rd] = read_memory(addr)
    end
    @pc += 4
  end
  def store(instruction)
    i = instruction
    addr = @registers[i.rs1] + sign_extend(i.offset, 12)
    case i.funct3
    when SB
      store_byte(addr, @registers[i.rs2] & 0xff)
    when SH
      store_hw(addr, @registers[i.rs2] & 0xffff)
    when SW
      store_word(addr, @registers[i.rs2])
    end
    @pc += 4
  end
  def op(instruction)
    i = instruction
    case i.funct3
    when ADD
      case i.funct7
      when ADD
        @registers[i.rd] = (@registers[i.rs1] + @registers[i.rs2]) & 0xffffffff
      when SUB
        @registers[i.rd] = (@registers[i.rs1] - @registers[i.rs2]) & 0xffffffff
      end
    when SLL
      @registers[i.rd] = (@registers[i.rs1] << (@registers[i.rs2] & 0x1f)) & 0xffffffff
    when SLT
      @registers[i.rd] = sign_extend(@registers[i.rs1], 32) < sign_extend(@registers[i.rs2], 32) ? 1 : 0
    when SLTU
      @registers[i.rd] = unsigned(@registers[i.rs1]) < unsigned(@registers[i.rs2]) ? 1 : 0
    when XOR
      @registers[i.rd] = (@registers[i.rs1] ^ @registers[i.rs2]) & 0xffffffff
    when SR
      case i.funct7
      when SRL
        @registers[i.rd] = unsigned(@registers[i.rs1]) >> (@registers[i.rs2] & 0x1f)
      when SRA
        shamt = @registers[i.rs2] & 0x1f
        shift = @registers[i.rs1] >> shamt
        @registers[i.rd] = if (@registers[i.rs1] & 0x80000000).zero?
          shift
        else
          (((2 ** shamt) - 1) << (32 - shamt)) | shift
        end
      end
    when OR
      @registers[i.rd] = @registers[i.rs1] | @registers[i.rs2]
    when AND
      @registers[i.rd] = @registers[i.rs1] & @registers[i.rs2]
    end
    @pc += 4
  end
  def fence(instruction)
    nop
  end
  def nop
    @pc += 4
  end
  def system(instruction)
    i = instruction
    return csr(instruction) if i.funct3.nonzero?

    case i.funct12
    when ECALL
      # https://www.robalni.org/riscv/linux-syscalls-64.html
      case @registers[17] # a7
      when 0x5d
        value = @registers[10]
        puts "test case #{(value - 1) / 2} failed" if value.nonzero?
        puts "retired #{@i} instructions"
        puts "exit(#{value})"
        exit(value) # a0
      else
        binding.irb
      end
    when EBREAK
      dump_all
      binding.irb
   when MRET
     # to-do: there are other things to handle in a mret instruction
     @pc = @csr[MEPC]
     return
    end
    @pc += 4 # not sure about this one
  end
  def csr(instruction)
    i = instruction
    csr = i.funct12
    case i.funct3
    # to-do: check what it means MRO for mhartid
    when CSRRS
      t = @csr[csr]
      @csr[csr] = t | @registers[i.rs1]
      @registers[i.rd] = t
    when CSRRW
      t = @csr[csr]
      @csr[csr] = @registers[i.rs1]
      # why I have to do this?
      @registers[i.rd.zero? ? -1 : i.rd] = t
    when CSRRWI
      zimm = i.rs1
      @registers[i.rd] = @csr[csr]
      @csr[csr] = zimm
    else
      invalid_opcode(i.word)
    end
    @pc += 4
  end
  def branch(instruction)
    i = instruction
    case i.funct3
    when BEQ
      @pc += @registers[i.rs1] == @registers[i.rs2] ? i.offset : 4
    when BNE
      # binding.irb if @pc == 0x8000034c
      # binding.irb if @pc == 0x80000208
      @pc += @registers[i.rs1] != @registers[i.rs2] ? i.offset : 4
    when BLT
      @pc += sign_extend(@registers[i.rs1], 32) <  sign_extend(@registers[i.rs2], 32) ? i.offset : 4
    when BGE
      @pc += sign_extend(@registers[i.rs1], 32) >= sign_extend(@registers[i.rs2], 32) ? i.offset : 4
    when BLTU
      # likely the unsigned call is not required
      @pc += unsigned(@registers[i.rs1]) < unsigned(@registers[i.rs2]) ? i.offset : 4
    when BGEU
      # likely the unsigned call is not required
      @pc += unsigned(@registers[i.rs1]) >=unsigned(@registers[i.rs2]) ? i.offset : 4
    end
  end
  def lui(instruction)
    i = instruction
    @registers[i.rd] = i.imm
    @pc += 4
  end
  def auipc(instruction)
    i = instruction
    @registers[i.rd] = @pc + sign_extend(instruction.imm, 32)
    @pc += 4
  end
  def jal(instruction)
    i = instruction
    @registers[i.rd] = @pc + 4
    @pc += i.offset
  end
  # to-do: The JAL and JALR instructions will generate a misaligned
  # instruction fetch exception if the target address is not aligned
  # to a four-byte boundary.
  def jalr(instruction)
    i = instruction
    t = @pc + 4
    @pc = (@registers[i.rs1] + i.imm) & 0xfffffffe
    @registers[i.rd] = t
  end
  def dump_all
    printf("PC: %10d (0x%08x) |\n", @pc, @pc & 0xffffffff)
    @registers[0..31].each_with_index do |reg, idx|
      printf("%02d: %10d (0x%08x) | ", idx, reg, reg & 0xffffffff)
      puts if idx.odd?
    end
    puts "-" * 60
    format = "0x%08x: %10d (0x%08x)\n"
    @memory.each_with_index do |word, idx|
      printf(format, idx * 4, word, unsigned(word)) unless word.zero?
    end
    nil
  end
  def stop_at(pc)
    instruction = fetch_instruction
    binding.irb if @pc == pc
  end
end
end




h = EBreak::Hart.new(ARGV[0])
h.reset

class AssertionError < RuntimeError
end

def assert &block
  raise AssertionError unless yield
end

i = 1
assert { i >= 0 }
# assert { 5 == 12 }

# PC:       2548 (0x000009f4) |
# 00:          0 (0x00000000) | 01:       4096 (0x00001000) | 
# 02:        144 (0x00000090) | 03:          0 (0x00000000) | 
# 04:          0 (0x00000000) | 05:          8 (0x00000008) | 
# 06:          1 (0x00000001) | 07:        328 (0x00000148) | 
# 08:       1312 (0x00000520) | 09:     -10537 (0xffffd6d7) | 
# 10:     335872 (0x00052000) | 11:         -2 (0xfffffffe) | 
# 12:      10496 (0x00002900) | 13:        -41 (0xffffffd7) | 
# 14:         41 (0x00000029) | 15:      30679 (0x000077d7) | 
# 16:      30720 (0x00007800) | 17: 2147482821 (0x7ffffcc5) | 
# 18: 2147482821 (0x7ffffcc5) | 19:      28672 (0x00007000) | 
# 20:        -41 (0xffffffd7) | 21:        -41 (0xffffffd7) | 
# 22:        -41 (0xffffffd7) | 23:        215 (0x000000d7) | 
# 24:      65495 (0x0000ffd7) | 25:          0 (0x00000000) | 
# 26:          0 (0x00000000) | 27:          0 (0x00000000) | 
# 28:          0 (0x00000000) | 29:          0 (0x00000000) | 
# 30:        -41 (0xffffffd7) | 31:        136 (0x00000088) | 
# 
# 0x000001f4:        215 (0x000000d7)
# 0x000001f8:       8192 (0x00002000)
# 0x000001fc:        -41 (0xffffffd7)

def mytests(h)
assert { h.instance_variable_get("@registers")[0].zero? }
assert { h.instance_variable_get("@registers")[1] == 4096 }
assert { h.instance_variable_get("@registers")[2] == 180 }
assert { h.instance_variable_get("@registers")[3].zero? }
assert { h.instance_variable_get("@registers")[4].zero? }
assert { h.instance_variable_get("@registers")[5] == 8 }
assert { h.instance_variable_get("@registers")[6] == 1 }
assert { h.instance_variable_get("@registers")[7] == 328 }
assert { h.instance_variable_get("@registers")[8] == 1312 }
assert { h.instance_variable_get("@registers")[9] == -10537 }
assert { h.instance_variable_get("@registers")[10] == 335872 }
assert { h.instance_variable_get("@registers")[11] == -2 }
assert { h.instance_variable_get("@registers")[12] == 10496 }
assert { h.instance_variable_get("@registers")[13] == -41 }
assert { h.instance_variable_get("@registers")[14] == 41 }
assert { h.instance_variable_get("@registers")[15] == 30679 }
assert { h.instance_variable_get("@registers")[16] == 30720 }
assert { h.instance_variable_get("@registers")[17] == 2147482821 }
assert { h.instance_variable_get("@registers")[18] == 2147482821 }
assert { h.instance_variable_get("@registers")[19] == 28672 }
assert { h.instance_variable_get("@registers")[20] == -41 }
assert { h.instance_variable_get("@registers")[21] == -41 }
assert { h.instance_variable_get("@registers")[22] == 215 }
assert { h.instance_variable_get("@registers")[23] == 215 }
assert { h.instance_variable_get("@registers")[24] == 65495}
assert { h.instance_variable_get("@registers")[25] == 0x80000000 }
assert { h.instance_variable_get("@registers")[26] == 0x7fffffff }
assert { h.instance_variable_get("@registers")[27].zero? }
assert { h.instance_variable_get("@registers")[28] == -1 }
assert { h.instance_variable_get("@registers")[29] == -2 }
assert { h.instance_variable_get("@registers")[30] == -41 }
assert { h.instance_variable_get("@registers")[31] == 132 }
assert { h.instance_variable_get("@pc") == 268433908 }
end

mytests(h) unless h.instance_variable_get("@memory_map")
