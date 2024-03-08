from pwn import disasm
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UcError
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2

# Hexadecimal representation of ARM assembly code
arm_code_hex = "370301e3ca1203e33c164ce3732f0be3c12a4ae3010020e0020020e07d150fe39f184be3eb2c0ce3eb2e4de3010040e00200c0e0081202e3671c44e3892f0de34c214ee3010000e0020000e0ad160ce31b1442e3fb230ae3f72043e3000060e2e81806e328164fe32a2805e3c12745e3000060e2b71a05e37c114ae31e2a08e35d2f44e3000060e2701a0ee39d1d4fe3ca2003e3052141e3010080e1020080e1ba1701e3cc1743e39e290ee3982f43e3000060e2311606e3881d41e3cf210ce37a2d43e3000060e2111e01e3351d4fe303280fe3d42e40e3900100e0900200e0ba130fe3e41f4fe3372e0ae3ec2544e3900100e0900200e0111e0ee3a81a45e3b02707e357214ae3010020e0020020e0fa1c0ee395164ee30e2707e387214de3900100e0900200e0fb110de384144ee3032b04e3642347e3010000e0020000e00e1a08e3b91b43e3aa2600e3ca2743e3010040e00200c0e0321a0fe36b1b4ae352250fe3bc2647e3010020e0020020e0b91a0ae3bc1b46e3192209e3ec2445e3000060e29e1102e3d11a43e3be2608e3c52e42e3000060e2ab110be391104de3782b00e36c2344e3000060e236100ce3a91144e36e2a04e3cc2741e3010080e00200a0e0"

# Convert hexadecimal to bytes for the emulator
ARM_CODE = bytes.fromhex(arm_code_hex)

# Memory address where emulation starts
ADDRESS = 0x1000000

def emulate_arm_code():
    try:
        # Initialize emulator in ARM mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        
        # Map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        
        # Write machine code to be emulated to memory
        mu.mem_write(ADDRESS, ARM_CODE)

        # Emulate code in infinite time (0 means no timeout) and unlimited instructions
        mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE), timeout=0, count=0)
      
        # Retrieve the result from registers and print
        for reg, name in [(UC_ARM_REG_R0, "R0"), (UC_ARM_REG_R1, "R1"), (UC_ARM_REG_R2, "R2")]:
            value = mu.reg_read(reg)
            print(f"Emulated result of {name}: {hex(value)} ({value})")

    except UcError as e:
        print(f"Unicorn Error: {e}")



# Run disassembly
print(disasm(ARM_CODE, arch='arm'),"\n")

# Run the emulation
emulate_arm_code()
