/* BPF interpreter.
 *
 * The following represents an interpreter for Berkeley Packet Filter (BPF)
 * compiled programs. It was written for educational purposes, partly to
 * familiarise myself with BPF and partly to remind myself how to write C++. It
 * most likely makes numerous faux pas as I stumble my way back to the oasis of
 * C++ after years in the desert of C.
 *
 * This code is in the public domain. Use it in any way you like.
 */

#include <cstdio>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

typedef enum : uint16_t {
    BPF_LD   = 0x00,
    BPF_LDX  = 0x01,
    BPF_ST   = 0x02,
    BPF_STX  = 0x03,
    BPF_ALU  = 0x04,
    BPF_JMP  = 0x05,
    BPF_RET  = 0x06,
    BPF_MISC = 0x07,
} class_t;

enum : uint16_t {

    BPF_W    = 0x00,
    BPF_H    = 0x08,
    BPF_B    = 0x10,

    BPF_IMM  = 0x00,
    BPF_ABS  = 0x20,
    BPF_IND  = 0x40,
    BPF_MEM  = 0x60,
    BPF_LEN  = 0x80,
    BPF_MSH  = 0xa0,

    BPF_ADD  = 0x00,
    BPF_SUB  = 0x10,
    BPF_MUL  = 0x20,
    BPF_DIV  = 0x30,
    BPF_OR   = 0x40,
    BPF_AND  = 0x50,
    BPF_LSH  = 0x60,
    BPF_RSH  = 0x70,
    BPF_NEG  = 0x80,

    BPF_JA   = 0x00,
    BPF_JEQ  = 0x10,
    BPF_JGT  = 0x20,
    BPF_JGE  = 0x30,
    BPF_JSET = 0x40,

    BPF_K    = 0x00,
    BPF_X    = 0x08,

    BPF_A    = 0x10,

    BPF_TAX  = 0x00,
    BPF_TXA  = 0x80,

};

#define INSTRUCTION_SIZE 64

class Instruction {
    public:
        uint16_t opcode;
        uint8_t jt;
        uint8_t jf;
        uint32_t k;

        class_t get_class(void) const;
};

class_t Instruction::get_class(void) const {
    return static_cast<class_t>(opcode & 0x07);
}

class InterpreterException : public std::exception {
    public:
        const Instruction *instruction;
        InterpreterException(const Instruction *i) : instruction(i) {}
};

class IllegalInstruction : public InterpreterException {
    public:
        IllegalInstruction(const Instruction *i) : InterpreterException(i) {}
};

class ProgramCounterOutOfRange : public InterpreterException {
    public:
        ProgramCounterOutOfRange() : InterpreterException(nullptr) {}
};

class MemoryAccessOutOfRange : public InterpreterException {
    public:
        MemoryAccessOutOfRange(const Instruction *i) : InterpreterException(i) {}
};

class MisalignedProgram : public InterpreterException {
    public:
        MisalignedProgram() : InterpreterException(nullptr) {}
};

static const unsigned int SCRATCH_REGISTERS = 16;

class Machine {
    public:

        Machine() : pc(0), len(0) {}
        void load(const std::vector<uint8_t> packet);
        void run(const std::vector<uint8_t> program);

        /* Outputs */
        uint32_t ret;

    private:

        /* Internal VM state */
        unsigned int pc;
        uint32_t A;
        uint32_t X;
        uint32_t M[SCRATCH_REGISTERS];

        /* Inputs */
        const uint8_t *P;
        unsigned int len;

        bool apply(const Instruction &i);
        Instruction decode(const uint8_t *data);
};

void Machine::load(const std::vector<uint8_t> packet) {
    P = packet.data();
    len = packet.size();
}

bool Machine::apply(const Instruction &i) {
    switch (i.get_class()) {

        case BPF_LD:
            switch (i.opcode) {

                case BPF_LD + BPF_W + BPF_LEN:
                    A = len;
                    break;

                case BPF_LD + BPF_IMM:
                    A = i.k;
                    break;

                case BPF_LD + BPF_MEM:
                    if (i.k >= SCRATCH_REGISTERS)
                        throw IllegalInstruction(&i);
                    A = M[i.k];
                    break;

                default:;

                    unsigned int offset;
                    switch (i.opcode) {

                        case BPF_LD + BPF_W + BPF_ABS:
                        case BPF_LD + BPF_H + BPF_ABS:
                        case BPF_LD + BPF_B + BPF_ABS:
                            offset = i.k;
                            break;

                        case BPF_LD + BPF_W + BPF_IND:
                        case BPF_LD + BPF_H + BPF_IND:
                        case BPF_LD + BPF_B + BPF_IND:
                            offset = X + i.k;
                            break;

                        default:
                            throw IllegalInstruction(&i);
                    }

                    switch (i.opcode) {

                        case BPF_LD + BPF_W + BPF_ABS:
                        case BPF_LD + BPF_W + BPF_IND:
                            if (offset > std::numeric_limits<unsigned int>::max() - 3 || offset + 3 >= len)
                                throw MemoryAccessOutOfRange(&i);
                            A = (static_cast<uint32_t>(P[offset])) |
                                      (static_cast<uint32_t>(P[offset + 1]) << 8) |
                                      (static_cast<uint32_t>(P[offset + 2]) << 16) |
                                      (static_cast<uint32_t>(P[offset + 3]) << 24);
                            break;

                        case BPF_LD + BPF_H + BPF_ABS:
                        case BPF_LD + BPF_H + BPF_IND:
                            if (offset > std::numeric_limits<unsigned int>::max() - 1 || offset + 1 >= len)
                                throw MemoryAccessOutOfRange(&i);
                            A = (static_cast<uint32_t>(P[offset])) |
                                      (static_cast<uint32_t>(P[offset + 1]) << 8);
                            break;

                        case BPF_LD + BPF_B + BPF_ABS:
                        case BPF_LD + BPF_B + BPF_IND:
                            if (offset >= len)
                                throw MemoryAccessOutOfRange(&i);
                            A = static_cast<uint32_t>(P[offset]);
                            break;

                        default:
                            throw std::logic_error("expected exhaustive case was not exhaustive");
                    }
            }
            break;

        case BPF_LDX:
            switch (i.opcode) {

                case BPF_LDX + BPF_W + BPF_IMM:
                    X = i.k;
                    break;

                case BPF_LDX + BPF_W + BPF_MEM:
                    if (i.k >= SCRATCH_REGISTERS)
                        throw IllegalInstruction(&i);
                    X = M[i.k];
                    break;

                case BPF_LDX + BPF_W + BPF_LEN:
                    X = len;
                    break;

                case BPF_LDX + BPF_B + BPF_MSH:
                    if (i.k >= len)
                        throw MemoryAccessOutOfRange(&i);
                    X = 4 * static_cast<uint32_t>(P[i.k] & 0xf);
                    break;

                default:
                    throw IllegalInstruction(&i);
            }
            break;

        case BPF_ST:
            if (i.k >= SCRATCH_REGISTERS)
                throw IllegalInstruction(&i);
            M[i.k] = A;
            break;

        case BPF_STX:
            if (i.k >= SCRATCH_REGISTERS)
                throw IllegalInstruction(&i);
            M[i.k] = X;
            break;

        case BPF_ALU:
            switch (i.opcode) {

                case BPF_ALU + BPF_ADD + BPF_K:
                    A += i.k;
                    break;

                case BPF_ALU + BPF_SUB + BPF_K:
                    A -= i.k;
                    break;

                case BPF_ALU + BPF_MUL + BPF_K:
                    A *= i.k;
                    break;

                case BPF_ALU + BPF_DIV + BPF_K:
                    A /= i.k;
                    break;

                case BPF_ALU + BPF_AND + BPF_K:
                    A &= i.k;
                    break;

                case BPF_ALU + BPF_OR + BPF_K:
                    A |= i.k;
                    break;

                case BPF_ALU + BPF_LSH + BPF_K:
                    A <<= i.k;
                    break;

                case BPF_ALU + BPF_RSH + BPF_K:
                    A >>= i.k;
                    break;

                case BPF_ALU + BPF_ADD + BPF_X:
                    A += X;
                    break;

                case BPF_ALU + BPF_SUB + BPF_X:
                    A -= X;
                    break;

                case BPF_ALU + BPF_MUL + BPF_X:
                    A *= X;
                    break;

                case BPF_ALU + BPF_DIV + BPF_X:
                    A /= X;
                    break;

                case BPF_ALU + BPF_AND + BPF_X:
                    A &= X;
                    break;

                case BPF_ALU + BPF_OR + BPF_X:
                    A |= X;
                    break;

                case BPF_ALU + BPF_LSH + BPF_X:
                    A <<= X;
                    break;

                case BPF_ALU + BPF_RSH + BPF_X:
                    A >>= X;
                    break;

                case BPF_ALU + BPF_NEG:
                    A = -A;
                    break;

                default:
                    throw IllegalInstruction(&i);
            }
            break;

        case BPF_JMP:
            switch (i.opcode) {

                case BPF_JMP + BPF_JA:
                    pc += i.k;
                    break;

                case BPF_JMP + BPF_JGT + BPF_K:
                    pc += A > i.k ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JGE + BPF_K:
                    pc += A >= i.k ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JEQ + BPF_K:
                    pc += A == i.k ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JSET + BPF_K:
                    pc += A & i.k ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JGT + BPF_X:
                    pc += A > X ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JGE + BPF_X:
                    pc += A >= X ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JEQ + BPF_X:
                    pc += A == X ? i.jt : i.jf;
                    break;

                case BPF_JMP + BPF_JSET + BPF_X:
                    pc += A & X ? i.jt : i.jf;
                    break;

                default:
                    throw IllegalInstruction(&i);
            }
            return false;

        case BPF_RET:
            switch (i.opcode) {

                case BPF_RET + BPF_A:
                    ret = A;
                    break;

                case BPF_RET + BPF_K:
                    ret = i.k;
                    break;

                default:
                    throw IllegalInstruction(&i);
            }
            pc++;
            return true;

        case BPF_MISC:
            switch (i.opcode) {

                case BPF_MISC + BPF_TAX:
                    X = A;
                    break;

                case BPF_MISC + BPF_TXA:
                    A = X;
                    break;

                default:
                    throw IllegalInstruction(&i);
            }
            break;

        default:
            throw std::domain_error("illegal instruction class");
    }
    pc++;
    return false;
}

Instruction Machine::decode(const uint8_t *data) {
    Instruction i;
    i.opcode = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
    i.jt = data[2];
    i.jf = data[3];
    i.k = static_cast<uint32_t>(data[0]) |
          (static_cast<uint32_t>(data[1]) << 8) |
          (static_cast<uint32_t>(data[2]) << 16) |
          (static_cast<uint32_t>(data[3]) << 24);
    return i;
}

void Machine::run(const std::vector<uint8_t> program) {

    if (program.size() % INSTRUCTION_SIZE != 0) 
        throw MisalignedProgram();

    Instruction i;
    do {
        if (pc >= program.size() / INSTRUCTION_SIZE)
            throw ProgramCounterOutOfRange();

        i = decode(program.data() + pc * INSTRUCTION_SIZE);

    } while (!apply(i));
}

std::vector<uint8_t> read_file(const char *filename) {
    std::ifstream s(filename, std::ios::in|std::ios::binary);
    if (!s.is_open())
        throw std::runtime_error("failed to open file");

    std::vector<uint8_t> data;
    std::copy(std::istream_iterator<uint8_t>(s),
        std::istream_iterator<uint8_t>(), std::back_inserter(data));
    
    return data;
}

int main(int argc, char **argv) {
    const char *data = nullptr;
    const char *input = nullptr;

    while (true) {
        static struct option opts[] = {
            {"data", required_argument, 0, 'd'},
            {"input", required_argument, 0, 'i'},
            {0, 0, 0, 0},
        };

        int opt_index;
        int c = getopt_long(argc, argv, "d:i:", opts, &opt_index);

        if (c == -1)
            break;

        switch (c) {
            case 'd':
                data = optarg;
                break;

            case 'i':
                input = optarg;
                break;

            default:
                return -1;
        }
    }

    if (data == nullptr || input == nullptr) {
        std::cerr << "usage: " << argv[0] <<
            " --input INPUT_FILE --data DATA_FILE" << std::endl;
        return -1;
    }

    std::vector<uint8_t> program;
    try {
        program = read_file(input);
    } catch (std::runtime_error e) {
        std::cerr << "failed to read " << input << std::endl;
        return -1;
    }

    std::vector<uint8_t> packet;
    try {
        packet = read_file(data);
    } catch (std::runtime_error e) {
        std::cerr << "failed to read " << data << std::endl;
        return -1;
    }

    if (packet.size() % INSTRUCTION_SIZE != 0) {
        std::cerr << data << " is not instruction-aligned" << std::endl;
        return -1;
    }

    Machine m;
    m.load(packet);
    try {
        m.run(program);
    } catch (InterpreterException e) {
        std::cerr << "VM exception: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
