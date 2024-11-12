/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/boot_info.h"

#include "hf/assert.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/std.h"
#include "hf/fdt.h"

#include "libfdt.h"

#include "hf/hob.h"
#include "hf/hob_guid.h"
#include "hf/mmram.h"
#include "hf/mpinfo.h"

#include "vmapi/hf/ffa.h"

/**
 * Initializes the ffa_boot_info_header in accordance to the specification.
 */
static void ffa_boot_info_header_init(struct ffa_boot_info_header *header,
				      size_t blob_size)
{
	assert(header != NULL);
	assert(blob_size != 0U);

	header->signature = FFA_BOOT_INFO_SIG;
	header->version = FFA_BOOT_INFO_VERSION;
	header->info_blob_size = blob_size;
	header->desc_size = sizeof(struct ffa_boot_info_desc);
	header->desc_count = 0;
	header->desc_offset =
		(uint32_t)offsetof(struct ffa_boot_info_header, boot_info);
	header->reserved = 0U;
}

static bool get_memory_region_info(void *sp_manifest, int mem_region_node,
		const char *name, uint32_t granularity,
		uint64_t *base_address, uint32_t *size)
{
	char *property;
	int node, ret;

	if (name != NULL) {
		node = fdt_subnode_offset_namelen(sp_manifest, mem_region_node,
				name, strlen(name));
		if (node < 0) {
			dlog_error("Not found '%s' region in memory regions configuration for SP.\n",
					name);
			return false;
		}
	} else {
		node = mem_region_node;
	}

	property = "base-address";
	ret = fdt_read_uint64(sp_manifest, node, property, base_address);
	if (ret < 0) {
		dlog_error("Not found property(%s) in memory region(%s).\n",
				property, name);
		return false;
	}

	property = "pages-count";
	ret = fdt_read_uint32(sp_manifest, node, property, size);
	if (ret < 0) {
		dlog_error("Not found property(%s) in memory region(%s).\n",
				property, name);
		return false;
	}

	*size = ((*size) << (PAGE_BITS + (granularity << 1)));

	return true;
}

static struct efi_hob_handoff_info_table *build_sp_boot_hob_list(
		struct mm_stage1_locked stage1_locked,
		void *sp_manifest, uintpaddr_t *hob_table_start, size_t *hob_table_size,
		struct mpool *ppool
		)
{
	struct efi_hob_handoff_info_table *hob_table;
	uintptr_t base_address;
	int mem_region_node;
	int32_t node, ret;
	const char *name;
	uint32_t granularity, size;
	uint32_t mem_region_num;
	struct efi_guid ns_buf_guid = MM_NS_BUFFER_GUID;
	struct efi_guid mmram_resv_guid = MM_PEI_MMRAM_MEMORY_RESERVE_GUID;
	struct efi_mmram_descriptor *mmram_desc_data;
	struct efi_mmram_hob_descriptor_block *mmram_hob_desc_data;
	uint32_t entry_offset;
	uint64_t load_address;
	uint64_t image_size;

	if (sp_manifest == NULL || hob_table_start == NULL || hob_table_size == NULL) {
		return NULL;
	}

	node = fdt_path_offset(sp_manifest, "/");
	if (node < 0) {
		dlog_error("Failed to get root in sp_manifest.\n");
		return NULL;
	}

	ret = fdt_read_uint32(sp_manifest, node, "xlat-granule", &granularity);
	if (ret < 0) {
		dlog_error("Not found property(xlat-granule) in sp_manifest.\n");
		return NULL;
	}

	ret = fdt_read_uint32(sp_manifest, node, "entrypoint-offset", &entry_offset);
	if (ret < 0) {
		dlog_error("Not found property(entrypoint-offset) in sp_manifest.\n");
		return NULL;
	}

	ret = fdt_read_uint64(sp_manifest, node, "load-address", &load_address);
	if (ret < 0) {
		dlog_error("Not found property(load-address) in sp_manifest.\n");
		return NULL;
	}

	ret = fdt_read_uint64(sp_manifest, node, "image-size", &image_size);
	if (ret < 0) {
		dlog_error("Not found property(image-size) in sp_manifest.\n");
		return NULL;
	}

	if (granularity > 0x02) {
		dlog_error("Invalid granularity value: 0x%x\n", granularity);
		return NULL;
	}

	mem_region_node = fdt_subnode_offset_namelen(sp_manifest, 0, "memory-regions",
			sizeof("memory-regions") - 1);
	if (node < 0) {
		dlog_error("Not found memory-region configuration for SP.\n");
		return NULL;
	}

	dlog_info("Generating PHIT_HOB...\n");

	/*
	 * Create hob list on the designated hob buffer.
	 */
	*hob_table_size = 0;
	ret = get_memory_region_info(sp_manifest, mem_region_node,
			"hob_buffer", granularity, (uint64_t*)hob_table_start, (uint32_t*)hob_table_size);
	if (!ret) {
		return NULL;
	}

	mm_identity_map(stage1_locked, pa_init(*hob_table_start),
					pa_init(*hob_table_start + *hob_table_size),
					MM_MODE_R | MM_MODE_W, ppool);

	hob_table = create_hob_list(0, 0,
			*hob_table_start, *hob_table_size);
	if (hob_table == NULL) {
		dlog_error("Failed to create Hob Table.\n");
		return NULL;
	}

	/*
	 * Create fv hob.
	 */
	base_address = entry_offset + load_address;
	size = image_size;

	ret = create_fv_hob(hob_table, base_address, size);
	if (ret < 0) {
		dlog_error("Failed to create fv hob... ret:%d\n", ret);
		return NULL;
	}

	dlog_info("Success to create FV hob(0x%lx/0x%x).\n", base_address, size);

	/*
	 * Create resource desciptor hob.
	 */
	ret = create_resource_descriptor_hob(hob_table,
			EFI_RESOURCE_SYSTEM_MEMORY,
			EFI_RESOURCE_ATTRIBUTE_PRESENT |
			EFI_RESOURCE_ATTRIBUTE_TESTED |
			EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
			EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
			EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
			EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE,
			base_address, size);
	if (ret < 0) {
		dlog_error("Failed to create resource descriptor hob... ret:%d\n", ret);
		return NULL;
	}

	/*
	 * Create Ns Buffer hob.
	 */
	ret = get_memory_region_info(sp_manifest, mem_region_node,
			"ns_comm_buffer", granularity, &base_address, &size);
	if (!ret) {
		return NULL;
	}

	ret = create_guid_hob(hob_table, &ns_buf_guid,
			sizeof(struct efi_mmram_descriptor), (void **) &mmram_desc_data);
	if (ret < 0) {
		dlog_error("Failed to create ns buffer hob\n");
		return NULL;
	}

	mmram_desc_data->physical_start = base_address;
	mmram_desc_data->physical_size = size;
	mmram_desc_data->cpu_start = base_address;
	mmram_desc_data->region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	/*
	 * Create mmram_resv hob.
	 */
	for (node = fdt_first_subnode(sp_manifest, mem_region_node), mem_region_num = 0;
			node >= 0;
			node = fdt_next_subnode(sp_manifest, node), mem_region_num++) {
		ret = get_memory_region_info(sp_manifest, node, NULL, granularity,
				&base_address, &size);
		if (!ret) {
			name = fdt_get_name(sp_manifest, node, NULL);
			dlog_error("Invalid memory region(%s) found!\n", name);
			return NULL;
		}
	}

	ret = create_guid_hob(hob_table, &mmram_resv_guid,
			(sizeof(struct efi_mmram_hob_descriptor_block) +
			 (sizeof(struct efi_mmram_descriptor) * mem_region_num)),
			(void **) &mmram_hob_desc_data);
	if (ret < 0) {
		dlog_error("Failed to create mmram_resv hob. ret: %d\n", ret);
		return NULL;
	}

	mmram_hob_desc_data->number_of_mm_reserved_regions = mem_region_num;

	for (node = fdt_first_subnode(sp_manifest, mem_region_node), mem_region_num = 0;
			node >= 0;
			node = fdt_next_subnode(sp_manifest, node), mem_region_num++) {
		get_memory_region_info(sp_manifest, node, NULL, granularity,
				&base_address, &size);
		name = fdt_get_name(sp_manifest, node, NULL);

		mmram_desc_data = &mmram_hob_desc_data->descriptor[mem_region_num];
		mmram_desc_data->physical_start = base_address;
		mmram_desc_data->physical_size = size;
		mmram_desc_data->cpu_start = base_address;

		if (!strncmp(name, "heap", sizeof("heap"))) {
			mmram_desc_data->region_state = EFI_CACHEABLE;
		} else {
			mmram_desc_data->region_state = EFI_CACHEABLE | EFI_ALLOCATED;
		}
	}

	*hob_table_size = hob_table->efi_free_memory_bottom -
		(efi_physical_address_t) hob_table;

  return hob_table;
}

static void ffa_boot_info_desc_init(struct ffa_boot_info_desc *info_desc,
				    uint8_t content_format, bool std_type,
				    uint8_t type_id, uint32_t size,
				    uint64_t content)
{
	assert(info_desc != NULL);

	/*
	 * Init name size with 0s, as it is currently unused. Data can be
	 * identified checking the type field.
	 */
	memset_s(info_desc, FFA_BOOT_INFO_NAME_LEN, 0, FFA_BOOT_INFO_NAME_LEN);

	info_desc->type = std_type == true ? FFA_BOOT_INFO_TYPE_STD
					   : FFA_BOOT_INFO_TYPE_IMPDEF;
	info_desc->type <<= FFA_BOOT_INFO_TYPE_SHIFT;
	info_desc->type |= (type_id & FFA_BOOT_INFO_TYPE_ID_MASK);

	info_desc->reserved = 0U;
	info_desc->flags =
		((content_format << FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT) &
		 FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK);
	info_desc->size = size;
	info_desc->content = content;
}

/*
 * Write initialization parameter to the boot info descriptor array.
 */
static void boot_info_write_desc(struct ffa_boot_info_header *header,
				 uint8_t content_format, bool std_type,
				 uint8_t type_id, uint32_t size,
				 uint64_t content,
				 const size_t max_info_desc_count)
{
	assert(header != NULL);

	/* Check that writing the data won't surpass the blob memory limit. */
	if (header->desc_count >= max_info_desc_count) {
		dlog_error(
			"Boot info memory is full. No space for a "
			"descriptor.\n");
		return;
	}

	ffa_boot_info_desc_init(&header->boot_info[header->desc_count],
				content_format, std_type, type_id, size,
				content);

	header->desc_count++;
}

/**
 * Looks for the FF-A manifest boot information node, and writes the
 * requested information into the boot info memory.
 */
bool ffa_boot_info_node(
			struct mm_stage1_locked stage1_locked,
			struct fdt_node *boot_info_node, vaddr_t pkg_address,
			struct sp_pkg_header *pkg_header, struct mpool *ppool)
{
	struct memiter data;
	struct ffa_boot_info_header *boot_info_header =
		(struct ffa_boot_info_header *)ptr_from_va(pkg_address);
	const size_t boot_info_size = sp_pkg_get_boot_info_size(pkg_header);
	const size_t max_boot_info_desc_count =
		(boot_info_size -
		 offsetof(struct ffa_boot_info_header, boot_info)) /
		sizeof(struct ffa_boot_info_desc);

	assert(boot_info_node != NULL);
	assert(pkg_header != NULL);
	assert(boot_info_header != NULL);

	/*
	 * FF-A v1.1 EAC0 specification states the region for the boot info
	 * descriptors, and the contents of the boot info shall be contiguous.
	 * Together they constitute the boot info blob. The are for the boot
	 * info blob is allocated in the SP's respective package.
	 * Retrieve from the SP package the size of the region for the boot info
	 * descriptors. The size of boot info contents to be incremented,
	 * depending on the info specified in the partition's FF-A manifest.
	 */
	ffa_boot_info_header_init(boot_info_header, boot_info_size);

	if (!fdt_is_compatible(boot_info_node, "arm,ffa-manifest-boot-info")) {
		dlog_verbose("The node 'boot-info' is not compatible.\n");
		return false;
	}

	dlog_verbose("  FF-A Boot Info:\n");

	if (fdt_read_property(boot_info_node, "ffa_manifest", &data) &&
	    memiter_size(&data) == 0U) {
		ipaddr_t manifest_address = ipa_init(
			va_addr(va_add(pkg_address, pkg_header->pm_offset)));

		dlog_verbose("    FF-A Manifest\n");

		uintpaddr_t hob_address;
		size_t size;

		build_sp_boot_hob_list(
			stage1_locked,
			(void*)ipa_addr(manifest_address),
			&hob_address,
			&size,
			ppool);

		boot_info_write_desc(
			boot_info_header,
			FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR, true,
			FFA_BOOT_INFO_TYPE_ID_HOB, pkg_header->pm_size,
			hob_address, max_boot_info_desc_count);

		/*
		 * Incrementing the size of the boot information blob with the
		 * size of the partition's manifest.
		 */
		boot_info_header->info_blob_size += size;

		/*
		 * Flush the data cache in case partition initializes with
		 * caches disabled.
		 */
		arch_mm_flush_dcache((void *)boot_info_header,
				     boot_info_header->info_blob_size);
		return true;
	}

	return false;
}
