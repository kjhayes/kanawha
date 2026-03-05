#ifndef __KANAWHA__NVME_IDENTIFY_H__
#define __KANAWHA__NVME_IDENTIFY_H__

#include <kanawha/endian.h>
#include <stdint.h>

#define NVME_IDENTIFY_BUFLEN (0x1000)

#define NVME_CNS_IDENTIFY_NAMESPACE (0x0)
#define NVME_CNS_IDENTIFY_CONTROLLER (0x1)

struct nvme_identify_namespace_data
{
    le64_t namespace_size;        // num LBA
    le64_t namespace_capacity;    // max num LBA possible
    le64_t namespace_utilization; // num LBA allocated
    uint8_t namespace_features;
    uint8_t num_lba_formats;
    uint8_t formatted_lba_size;
    uint8_t metadata_capabilities;
    uint8_t end_to_end_protection_capabilities;
    uint8_t end_to_end_protection_type_settings;
    uint8_t multipath_io_and_sharing_capabilities;
    uint8_t reservation_capabilities;
    uint8_t format_progress_indicator;
    uint8_t deallocate_lba_features;
    le16_t atomic_write_unit_normal;
    le16_t atomic_write_unit_power_fall;
    le16_t atomic_compare_and_write_unit;
    le16_t atomic_boundary_size;
    le16_t atomic_boundary_offset;
    le16_t atomic_boundary_size_power_fall;
    le16_t optimal_io_boundary;
    le64_t nvm_capacity_low;
    le64_t nvm_capacity_high;
    le16_t preferred_write_granularity;
    le16_t preferred_write_alignment;
    le16_t preferred_deallocate_granularity;
    le16_t preferred_deallocate_alignment;
    le16_t optimal_write_size;
    le16_t max_single_source_range_length;
    le32_t max_copy_length;
    uint8_t max_source_range_count;
    uint8_t key_per_io_status;
    uint8_t num_unique_attribute_lba_formats;
    uint8_t __resv0;
    le32_t key_per_io_data_access_alignment_and_granularity;
    uint32_t __resv1;
    le32_t ana_group_id;
    uint8_t __resv3[3];
    uint8_t namespace_attributes;
    le16_t nvm_set_id;
    le16_t endurance_group_id;
    uint8_t namespace_guid[16];
    le64_t ieee_eui64;
    union
    {
        struct
        {
            le16_t metadata_size;
            uint8_t lba_order;
            uint8_t relative_performance : 2;
        } __packed;
        le32_t raw;
    } __packed lba_formats[64];

    // Many many more...
} __packed;
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data, nvm_capacity_low, 48);
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data,
                    preferred_write_granularity,
                    64);
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data,
                    optimal_write_size,
                    72);
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data,
                    num_unique_attribute_lba_formats,
                    82);
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data,
                    namespace_attributes,
                    99);
ASSERT_FIELD_OFFSET(struct nvme_identify_namespace_data, lba_formats, 128);

struct nvme_identify_controller_data
{
    le16_t pci_vendor;
    le16_t pci_subsystem_vendor;
    uint8_t serial_number[20];
    uint8_t model_number[40];
    uint8_t firmware_revision[8];
    uint8_t rab;
    uint8_t ieee_out_id[3];
    uint8_t cmic;
    uint8_t max_data_transfer_size;
    le16_t controller_id;
    le32_t version;
    le32_t rtd3_resume_latency;
    le32_t rtd3_entry_latency;
    le32_t optional_async_events_supported;
    le32_t controller_attributes;
    le16_t read_recovery_levels_supported;
    uint8_t boot_partition_capabilities;
    uint8_t __resv0;
    le32_t nvm_subsystem_shutdown_latency;
    uint16_t __resv1;
    uint8_t power_loss_signal_info;
    uint8_t controller_type;
    uint8_t fguid[16];
    le16_t command_retry_delay_time_1;
    le16_t command_retry_delay_time_2;
    le16_t command_retry_delay_time_3;
    uint8_t controller_reachability_capabilities;
    uint8_t controller_instance_uniquifier;
    le64_t controller_instance_random_number;
    uint8_t __resv2[(239 - 144) + 1];
    uint8_t __resv3[(252 - 240) + 1];
    uint8_t nvm_subsystem_report;
    uint8_t vpd_write_cycle_info;
    uint8_t management_endpoint_capabilities;
    le16_t optional_admin_command_support;
    uint8_t abort_command_limit;
    uint8_t async_event_request_limit;
    uint8_t firmware_updates;
    uint8_t log_page_attributes;
    uint8_t error_log_pages;
    uint8_t num_power_states_supported;
    uint8_t admin_vendor_specific_command_config;
    uint8_t autonomous_power_state_transition_attributes;
    le16_t warning_composite_temperature_threshold;
    le16_t critical_composite_temperature_threshold;
    le16_t max_time_for_firmware_activation;
    le32_t host_memory_buffer_preferred_size;
    le32_t host_memory_buffer_minimum_size;
    le64_t total_nvm_capacity_low;
    le64_t total_nvm_capacity_high;
    le64_t unallocated_nvm_capacity_low;
    le64_t unallocated_nvm_capacity_high;
    le32_t replay_prot_memory_block_support;
    le16_t extended_self_test_time;
    uint8_t self_test_options;
    uint8_t firmware_update_granularity;
    le16_t keep_alive_support;
    le16_t host_controlled_thermal_management_attributes;
    le16_t minimum_thermal_management_temperature;
    le16_t maximum_thermal_management_temperature;
    le32_t santize_capabilities;
    le32_t host_memory_buffer_minimum_desc_entry_size;
    le16_t host_memory_buffer_maximum_desc_entries;
    le16_t nvm_set_id_maximum;
    le16_t endurance_group_id_maximum;
    uint8_t ana_translation_time;
    uint8_t asymmetric_namespace_access_capabilities;
    le32_t ana_group_id_maximum;
    le32_t num_ana_group_ids;
    le32_t persistent_event_log_size;
    le16_t domain_id;
    // There are so many more...
    // I give up... -KJH
} __packed;
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data,
                    controller_instance_random_number,
                    136);
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data,
                    nvm_subsystem_report,
                    253);
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data,
                    firmware_updates,
                    260);
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data,
                    total_nvm_capacity_low,
                    280);
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data,
                    keep_alive_support,
                    320);
ASSERT_FIELD_OFFSET(struct nvme_identify_controller_data, domain_id, 356);

#endif
