/** @file moal_cfgvendor.h
  *
  * @brief This file contains the CFG80211 vendor specific defines.
  *
  * Copyright (C) 2011-2017, Marvell International Ltd.
  *
  * This software file (the "File") is distributed by Marvell International
  * Ltd. under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify this File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

#ifndef _MOAL_CFGVENDOR_H_
#define _MOAL_CFGVENDOR_H_

#include    "moal_main.h"

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
#define RING_NAME_MAX 32
typedef int wifi_ring_buffer_id;

#define VALID_RING(id) (id >= 0 && id < RING_ID_MAX)

typedef struct _wifi_ring_ctrl {
	t_u32 written_bytes;
	t_u32 read_bytes;
	t_u32 written_records;
} ring_buffer_ctrl;

enum ring_state {
	RING_STOP = 0,		/*ring is not initialized */
	RING_ACTIVE,		/*ring is live and logging */
	RING_SUSPEND,		/*ring is initialized but not logging */
};

typedef struct _wifi_ring_buffer {
	wifi_ring_buffer_id ring_id;
	t_u8 name[RING_NAME_MAX];
	t_u32 ring_size;
	t_u32 wp;
	t_u32 rp;
	t_u32 log_level;
	t_u32 threshold;
	void *ring_buf;
	spinlock_t lock;
	ring_buffer_ctrl ctrl;
	enum ring_state state;
	struct delayed_work work;
	unsigned long interval;
	moal_private *priv;
} wifi_ring_buffer;

#define VERBOSE_RING_NAME "verbose"
#define EVENT_RING_NAME "event"

#define DEFAULT_RING_BUFFER_SIZE 1024

#define TLV_LOG_HEADER_LEN 4

#define WIFI_LOGGER_MEMORY_DUMP_SUPPORTED	MBIT(0)	/* Memory dump of Fw */
#define WIFI_LOGGER_PER_PACKET_TX_RX_STATUS_SUPPORT	MBIT(1)	/*PKT status */
#define WIFI_LOGGER_CONNECT_EVENT_SUPPORTED		MBIT(2)	/* connectivity event */
#define WIFI_LOGGER_POWER_EVENT_SUPPORTED	MBIT(3)	/* Power of driver */
#define WIFI_LOGGER_WAKE_LOCK_SUPPORTED		MBIT(4)	/* Wake lock of driver */
#define WIFI_LOGGER_VERBOSE_SUPPORTED	MBIT(5)	/*verbose log of Fw */
#define WIFI_LOGGER_WATCHDOG_TIMER_SUPPORTED	MBIT(6)	/*monitor the health of Fw */

/**
 * Parameters of wifi logger events are TLVs
 * Event parameters tags are defined as:
 */
#define WIFI_TAG_VENDOR_SPECIFIC    0	// take a byte stream as parameter
#define WIFI_TAG_BSSID              1	// takes a 6 bytes MAC address as parameter
#define WIFI_TAG_ADDR               2	// takes a 6 bytes MAC address as parameter
#define WIFI_TAG_SSID               3	// takes a 32 bytes SSID address as parameter
#define WIFI_TAG_STATUS             4	// takes an integer as parameter
#define WIFI_TAG_REASON_CODE        14	// take a reason code as per 802.11 as parameter
#define WIFI_TAG_RSSI               21	// take an integer as parameter
#define WIFI_TAG_CHANNEL            22	// take an integer as parameter

#define RING_ENTRY_SIZE (sizeof(wifi_ring_buffer_entry))
#define ENTRY_LENGTH(hdr) (hdr->entry_size + RING_ENTRY_SIZE)
#define READ_AVAIL_SPACE(w, r, d) ((w >= r) ? (w - r) : (d - r))

enum logger_attributes {
	ATTR_WIFI_LOGGER_INVALID = 0,
	ATTR_WIFI_LOGGER_RING_ID,
	ATTR_WIFI_LOGGER_FLAGS,
	ATTR_WIFI_LOGGER_VERBOSE_LEVEL,
	ATTR_WIFI_LOGGER_MIN_DATA_SIZE,
	ATTR_RING_BUFFER_STATUS,
	ATTR_NUM_RINGS,
	ATTR_WIFI_LOGGER_FEATURE_SET,
	ATTR_WIFI_LOGGER_MAX_INTERVAL_SEC,
	ATTR_RING_BUFFER,
	ATTR_NAME,
	ATTR_MEM_DUMP,
	ATTR_ERR_CODE,
	ATTR_RING_DATA,
	ATTR_WAKE_REASON_STAT,
	ATTR_CMD_EVENT_WAKE_ARRAY,
	ATTR_DRIVER_FW_LOCAL_WAKE_ARRAY,
	ATTR_PACKET_FATE_TX,
	ATTR_PACKET_FATE_RX,
	ATTR_PACKET_FATE_DATA,
	ATTR_WIFI_LOGGER_AFTER_LAST,
	ATTR_WIFI_LOGGER_MAX = ATTR_WIFI_LOGGER_AFTER_LAST - 1
};

/* Below events refer to the wifi_connectivity_event ring and shall be supported */
enum {
	WIFI_EVENT_ASSOCIATION_REQUESTED = 0,
	WIFI_EVENT_AUTH_COMPLETE,
	WIFI_EVENT_ASSOC_COMPLETE,
};

enum {
	RING_BUFFER_ENTRY_FLAGS_HAS_BINARY = (1 << (0)),	// set for binary entries
	RING_BUFFER_ENTRY_FLAGS_HAS_TIMESTAMP = (1 << (1))	// set if 64 bits timestamp is present
};

enum {
	ENTRY_TYPE_CONNECT_EVENT = 1,
	ENTRY_TYPE_PKT,
	ENTRY_TYPE_WAKE_LOCK,
	ENTRY_TYPE_POWER_EVENT,
	ENTRY_TYPE_DATA
};

typedef struct {
	t_u16 entry_size;	// size of payload excluding the header
	t_u8 flags;
	t_u8 type;		// entry type
	t_u64 timestamp;	// present if has_timestamp bit is set.
} __attribute__ ((packed)) wifi_ring_buffer_entry;

typedef struct _wifi_ring_buffer_status {
	t_u8 name[RING_NAME_MAX];
	t_u32 flag;
	wifi_ring_buffer_id ring_id;
	t_u32 ring_buffer_byte_size;
	t_u32 verbose_level;
	t_u32 written_bytes;
	t_u32 read_bytes;
	t_u32 written_records;
} wifi_ring_buffer_status;

typedef struct {
	u16 tag;
	u16 length;		// length of value
	u8 value[0];
} __attribute__ ((packed)) tlv_log;

typedef struct {
	u16 event;
	tlv_log tlvs[0];	// separate parameter structure per event to be provided and optional data
	// the event_data is expected to include an official android part, with some
	// parameter as transmit rate, num retries, num scan result found etc...
	// as well, event_data can include a vendor proprietary part which is
	// understood by the developer only.
} __attribute__ ((packed)) wifi_ring_buffer_driver_connectivity_event;

typedef struct _assoc_logger {
    /** vendor specific */
	t_u8 oui[3];
	t_u8 bssid[MLAN_MAC_ADDR_LENGTH];
	t_u8 ssid[MLAN_MAX_SSID_LENGTH];
	t_s32 rssi;
	t_u32 channel;
} assoc_logger_data;

int woal_ring_event_logger(moal_private *priv, int ring_id,
			   pmlan_event pmevent);

#define DEFAULT_CMD_EVENT_WAKE_CNT_SZ 32
#define DEFAULT_DRIVER_FW_LOCAL_WAKE_CNT_SZ 32

typedef struct rx_data_cnt_details_t {
	int rx_unicast_cnt;
	int rx_multicast_cnt;
	int rx_broadcast_cnt;
} RX_DATA_WAKE_CNT_DETAILS;

typedef struct rx_wake_pkt_type_classification_t {
	int icmp_pkt;
	int icmp6_pkt;
	int icmp6_ra;
	int icmp6_na;
	int icmp6_ns;
} RX_WAKE_PKT_TYPE_CLASSFICATION;

typedef struct rx_multicast_cnt_t {
	int ipv4_rx_multicast_addr_cnt;
	int ipv6_rx_multicast_addr_cnt;
    /** Rx wake packet was non-ipv4 and non-ipv6*/
	int other_rx_multicast_addr_cnt;
} RX_MULTICAST_WAKE_DATA_CNT;

typedef struct wlan_driver_wake_reason_cnt_t {
    /** Total count of cmd event wakes */
	int total_cmd_event_wake;
	int *cmd_event_wake_cnt;
	int cmd_event_wake_cnt_sz;
	int cmd_event_wake_cnt_used;

    /** Total count of drive/fw wakes, for local reasons */
	int total_driver_fw_local_wake;
	int *driver_fw_local_wake_cnt;
	int driver_fw_local_wake_cnt_sz;
	int driver_fw_local_wake_cnt_used;

    /** total data rx packets, that woke up host */
	int total_rx_data_wake;
	RX_DATA_WAKE_CNT_DETAILS rx_wake_details;
	RX_WAKE_PKT_TYPE_CLASSFICATION rx_wake_pkt_classification_info;
	RX_MULTICAST_WAKE_DATA_CNT rx_multicast_wake_pkt_info;
} WLAN_DRIVER_WAKE_REASON_CNT;

int woal_wake_reason_logger(moal_private *priv,
			    mlan_ds_hs_wakeup_reason wake_reason);

#define MD5_PREFIX_LEN             4
#define MAX_FATE_LOG_LEN           32
#define MAX_FRAME_LEN_ETHERNET     1518
#define MAX_FRAME_LEN_80211_MGMT   2352

/** packet_fate_packet_type */
typedef enum {
	PACKET_TYPE_TX,
	PACKET_TYPE_RX,
} packet_fate_packet_type;

/** packet fate frame_type */
typedef enum {
	FRAME_TYPE_UNKNOWN,
	FRAME_TYPE_ETHERNET_II,
	FRAME_TYPE_80211_MGMT,
} frame_type;

/** wifi_tx_packet_fate */
typedef enum {
    /** Sent over air and ACKed. */
	TX_PKT_FATE_ACKED,

    /** Sent over air but not ACKed. (Normal for broadcast/multicast.) */
	TX_PKT_FATE_SENT,

    /** Queued within firmware, but not yet sent over air. */
	TX_PKT_FATE_FW_QUEUED,

    /** Dropped by firmware as invalid. E.g. bad source address, bad checksum, or invalid for current
       state. */
	TX_PKT_FATE_FW_DROP_INVALID,

    /** Dropped by firmware due to lack of buffer space. */
	TX_PKT_FATE_FW_DROP_NOBUFS,

    /** Dropped by firmware for any other reason. Includes frames that were sent by driver to firmware, but
       unaccounted for by firmware. */
	TX_PKT_FATE_FW_DROP_OTHER,

    /** Queued within driver, not yet sent to firmware. */
	TX_PKT_FATE_DRV_QUEUED,

    /** Dropped by driver as invalid. E.g. bad source address, or invalid for current state. */
	TX_PKT_FATE_DRV_DROP_INVALID,

    /** Dropped by driver due to lack of buffer space. */
	TX_PKT_FATE_DRV_DROP_NOBUFS,

    /** Dropped by driver for any other reason. */
	TX_PKT_FATE_DRV_DROP_OTHER,
} wifi_tx_packet_fate;

/** wifi_rx_packet_fate */
typedef enum {
    /** Valid and delivered to network stack (e.g., netif_rx()). */
	RX_PKT_FATE_SUCCESS,

    /** Queued within firmware, but not yet sent to driver. */
	RX_PKT_FATE_FW_QUEUED,

    /** Dropped by firmware due to host-programmable filters. */
	RX_PKT_FATE_FW_DROP_FILTER,

    /** Dropped by firmware as invalid. E.g. bad checksum, decrypt failed, or invalid for current state. */
	RX_PKT_FATE_FW_DROP_INVALID,

    /** Dropped by firmware due to lack of buffer space. */
	RX_PKT_FATE_FW_DROP_NOBUFS,

    /** Dropped by firmware for any other reason. */
	RX_PKT_FATE_FW_DROP_OTHER,

    /** Queued within driver, not yet delivered to network stack. */
	RX_PKT_FATE_DRV_QUEUED,

    /** Dropped by driver due to filter rules. */
	RX_PKT_FATE_DRV_DROP_FILTER,

    /** Dropped by driver as invalid. E.g. not permitted in current state. */
	RX_PKT_FATE_DRV_DROP_INVALID,

    /** Dropped by driver due to lack of buffer space. */
	RX_PKT_FATE_DRV_DROP_NOBUFS,

    /** Dropped by driver for any other reason. */
	RX_PKT_FATE_DRV_DROP_OTHER,
} wifi_rx_packet_fate;

/** frame_info_i */
typedef struct {
	frame_type payload_type;
	u32 driver_timestamp_usec;
	u32 firmware_timestamp_usec;
	size_t frame_len;
	char *frame_content;
} frame_info_i;

/** wifi_tx_report_i */
typedef struct {
	char md5_prefix[MD5_PREFIX_LEN];
	wifi_tx_packet_fate fate;
	frame_info_i frame_inf;
} wifi_tx_report_i;

/** wifi_rx_report_i */
typedef struct {
	char md5_prefix[MD5_PREFIX_LEN];
	wifi_rx_packet_fate fate;
	frame_info_i frame_inf;
} wifi_rx_report_i;

/** packet_fate_report_t */
typedef struct packet_fate_report_t {
	union {
		wifi_tx_report_i tx_report_i;
		wifi_rx_report_i rx_report_i;
	} u;
} PACKET_FATE_REPORT;

int woal_packet_fate_monitor(moal_private *priv,
			     packet_fate_packet_type pkt_type, t_u8 fate,
			     frame_type payload_type,
			     t_u32 driver_timestamp_usec,
			     t_u32 firmware_timestamp_usec, t_u8 *data,
			     t_u32 len);

/** =========== Define Copied from apf.h START =========== */
/* Number of memory slots, see ldm/stm instructions. */
#define MEMORY_ITEMS 16
/* Upon program execution starting some memory slots are prefilled: */
/* 4*([APF_FRAME_HEADER_SIZE]&15) */
#define MEMORY_OFFSET_IPV4_HEADER_SIZE 13
/* Size of packet in bytes. */
#define MEMORY_OFFSET_PACKET_SIZE 14
/* Age since filter installed in seconds. */
#define MEMORY_OFFSET_FILTER_AGE 15

/* Leave 0 opcode unused as it's a good indicator of accidental incorrect execution (e.g. data). */
/* Load 1 byte from immediate offset, e.g. "ldb R0, [5]" */
#define LDB_OPCODE 1
/* Load 2 bytes from immediate offset, e.g. "ldh R0, [5]" */
#define LDH_OPCODE 2
/* Load 4 bytes from immediate offset, e.g. "ldw R0, [5]" */
#define LDW_OPCODE 3
/* Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5]R0" */
#define LDBX_OPCODE 4
/* Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5]R0" */
#define LDHX_OPCODE 5
/* Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5]R0" */
#define LDWX_OPCODE 6
/* Add, e.g. "add R0,5" */
#define ADD_OPCODE 7
/* Multiply, e.g. "mul R0,5" */
#define MUL_OPCODE 8
/* Divide, e.g. "div R0,5" */
#define DIV_OPCODE 9
/* And, e.g. "and R0,5" */
#define AND_OPCODE 10
/* Or, e.g. "or R0,5" */
#define OR_OPCODE 11
/* Left shift, e.g, "sh R0, 5" or "sh R0, -5" (shifts right) */
#define SH_OPCODE 12
/* Load immediate, e.g. "li R0,5" (immediate encoded as signed value) */
#define LI_OPCODE 13
/* Unconditional jump, e.g. "jmp label" */
#define JMP_OPCODE 14
/* Compare equal and branch, e.g. "jeq R0,5,label" */
#define JEQ_OPCODE 15
/* Compare not equal and branch, e.g. "jne R0,5,label" */
#define JNE_OPCODE 16
/* Compare greater than and branch, e.g. "jgt R0,5,label" */
#define JGT_OPCODE 17
/* Compare less than and branch, e.g. "jlt R0,5,label" */
#define JLT_OPCODE 18
/* Compare any bits set and branch, e.g. "jset R0,5,label" */
#define JSET_OPCODE 19
/* Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455" */
#define JNEBS_OPCODE 20
/* Immediate value is one of *_EXT_OPCODE
 * Extended opcodes. These all have an opcode of EXT_OPCODE
 * and specify the actual opcode in the immediate field.*/
#define EXT_OPCODE 21
/* Load from memory, e.g. "ldm R0,5"
 * Values 0-15 represent loading the different memory slots. */
#define LDM_EXT_OPCODE 0
/* Store to memory, e.g. "stm R0,5" *
 * Values 16-31 represent storing to the different memory slots. */
#define STM_EXT_OPCODE 16
/* Not, e.g. "not R0" */
#define NOT_EXT_OPCODE 32
/* Negate, e.g. "neg R0" */
#define NEG_EXT_OPCODE 33
/* Swap, e.g. "swap R0,R1" */
#define SWAP_EXT_OPCODE 34
/* Move, e.g. "move R0,R1" */
#define MOV_EXT_OPCODE 35

#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
#define EXTRACT_REGISTER(i) ((i)&1)
#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)
/** =========== Define Copied from apf.h END =========== */

/** =========== Define Copied from apf_interpreter.h START =========== */
/**
 * Version of APF instruction set processed by accept_packet().
 * Should be returned by wifi_get_packet_filter_info.
 */
#define APF_VERSION 2
/** =========== Define Copied from apf_interpreter.h END =========== */

/** =========== Define Copied from apf_interpreter.c START =========== */
/* Return code indicating "packet" should accepted. */
#define PASS_PACKET 1
/* Return code indicating "packet" should be dropped. */
#define DROP_PACKET 0
/* If "c" is of an unsigned type, generate a compile warning that gets promoted to an error.
 * This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
 * superfluous ">= 0" with unsigned expressions generates compile warnings. */
#define ENFORCE_UNSIGNED(c) ((c) == (uint32_t)(c))
/** =========== Define Copied from apf_interpreter.c END =========== */

/** depend on the format of skb->data */
#define APF_FRAME_HEADER_SIZE 14
#define PACKET_FILTER_MAX_LEN 1024

enum {
	PACKET_FILTER_STATE_INIT = 0,
	PACKET_FILTER_STATE_STOP,
	PACKET_FILTER_STATE_START,
};

enum wifi_attr_packet_filter {
	ATTR_PACKET_FILTER_INVALID = 0,
	ATTR_PACKET_FILTER_TOTAL_LENGTH,
	ATTR_PACKET_FILTER_PROGRAM,
	ATTR_PACKET_FILTER_VERSION,
	ATTR_PACKET_FILTER_MAX_LEN,
	ATTR_PACKET_FILTER_MAX,
};

typedef struct _packet_filter {
	spinlock_t lock;
	t_u8 state;
	t_u8 packet_filter_program[PACKET_FILTER_MAX_LEN];
	t_u8 packet_filter_len;
	t_u32 packet_filter_version;
	t_u32 packet_filter_max_len;
} packet_filter;

int woal_filter_packet(moal_private *priv, t_u8 *data, t_u32 len,
		       t_u32 filter_age);

int woal_init_wifi_hal(moal_private *priv);
int woal_deinit_wifi_hal(moal_private *priv);

#define ATTRIBUTE_U32_LEN                  (nla_total_size(NLA_HDRLEN  + 4))
#define VENDOR_ID_OVERHEAD                 ATTRIBUTE_U32_LEN
#define VENDOR_SUBCMD_OVERHEAD             ATTRIBUTE_U32_LEN
#define VENDOR_DATA_OVERHEAD               (nla_total_size(NLA_HDRLEN))

#define VENDOR_REPLY_OVERHEAD       (VENDOR_ID_OVERHEAD + \
									VENDOR_SUBCMD_OVERHEAD + \
									VENDOR_DATA_OVERHEAD)

/* Feature enums */
#define WIFI_FEATURE_INFRA              0x0001	// Basic infrastructure mode
#define WIFI_FEATURE_INFRA_5G           0x0002	// Support for 5 GHz Band
#define WIFI_FEATURE_HOTSPOT            0x0004	// Support for GAS/ANQP
#define WIFI_FEATURE_P2P                0x0008	// Wifi-Direct
#define WIFI_FEATURE_SOFT_AP            0x0010	// Soft AP
#define WIFI_FEATURE_GSCAN              0x0020	// Google-Scan APIs
#define WIFI_FEATURE_NAN                0x0040	// Neighbor Awareness Networking
#define WIFI_FEATURE_D2D_RTT            0x0080	// Device-to-device RTT
#define WIFI_FEATURE_D2AP_RTT           0x0100	// Device-to-AP RTT
#define WIFI_FEATURE_BATCH_SCAN         0x0200	// Batched Scan (legacy)
#define WIFI_FEATURE_PNO                0x0400	// Preferred network offload
#define WIFI_FEATURE_ADDITIONAL_STA     0x0800	// Support for two STAs
#define WIFI_FEATURE_TDLS               0x1000	// Tunnel directed link setup
#define WIFI_FEATURE_TDLS_OFFCHANNEL    0x2000	// Support for TDLS off channel
#define WIFI_FEATURE_EPR                0x4000	// Enhanced power reporting
#define WIFI_FEATURE_AP_STA             0x8000	// Support for AP STA Concurrency
#define WIFI_FEATURE_LINK_LAYER_STATS   0x10000	// Link layer stats collection
#define WIFI_FEATURE_LOGGER             0x20000	// WiFi Logger
#define WIFI_FEATURE_HAL_EPNO           0x40000	// WiFi PNO enhanced
#define WIFI_FEATURE_RSSI_MONITOR       0x80000	// RSSI Monitor
#define WIFI_FEATURE_MKEEP_ALIVE        0x100000	// WiFi mkeep_alive
#define WIFI_FEATURE_CONFIG_NDO         0x200000	// ND offload configure
#define WIFI_FEATURE_TX_TRANSMIT_POWER  0x400000	// Capture Tx transmit power levels
#define WIFI_FEATURE_CONTROL_ROAMING    0x800000	// Enable/Disable firmware roaming
#define WIFI_FEATURE_IE_WHITELIST       0x1000000	// Support Probe IE white listing
#define WIFI_FEATURE_SCAN_RAND          0x2000000	// Support MAC & Probe Sequence Number randomization
// Add more features here

#define MAX_CHANNEL_NUM 200

/** Wifi Band */
typedef enum {
	WIFI_BAND_UNSPECIFIED,
	/** 2.4 GHz */
	WIFI_BAND_BG = 1,
	/** 5 GHz without DFS */
	WIFI_BAND_A = 2,
	/** 5 GHz DFS only */
	WIFI_BAND_A_DFS = 4,
	/** 5 GHz with DFS */
	WIFI_BAND_A_WITH_DFS = 6,
	/** 2.4 GHz + 5 GHz; no DFS */
	WIFI_BAND_ABG = 3,
	/** 2.4 GHz + 5 GHz with DFS */
	WIFI_BAND_ABG_WITH_DFS = 7,

	/** Keep it last */
	WIFI_BAND_LAST,
	WIFI_BAND_MAX = WIFI_BAND_LAST - 1,
} wifi_band;

typedef enum wifi_attr {
	ATTR_FEATURE_SET_INVALID = 0,
	ATTR_SCAN_MAC_OUI_SET = 1,
	ATTR_FEATURE_SET = 2,
	ATTR_NODFS_VALUE = 3,
	ATTR_COUNTRY_CODE = 4,
	ATTR_CHANNELS_BAND = 5,
	ATTR_NUM_CHANNELS = 6,
	ATTR_CHANNEL_LIST = 7,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE_MAX = 8,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE = 9,
	ATTR_GET_CONCURRENCY_MATRIX_SET = 10,
	ATTR_WIFI_MAX,
} wifi_attr_t;

enum mrvl_wlan_vendor_attr_wifi_logger {
	MRVL_WLAN_VENDOR_ATTR_NAME = 10,
};

/**vendor event*/
enum vendor_event {
	event_hang = 0,
	event_rtt_result = 0x07,
	event_rssi_monitor = 0x1501,
	fw_roam_success = 0x10002,
	event_dfs_radar_detected = 0x10004,
	event_dfs_cac_started = 0x10005,
	event_dfs_cac_finished = 0x10006,
	event_dfs_cac_aborted = 0x10007,
	event_dfs_nop_finished = 0x10008,
	event_wifi_logger_ring_buffer_data = 0x1000b,
	event_wifi_logger_alert,
	event_packet_fate_monitor,
	event_max,
};

/** struct dfs_event */
typedef struct _dfs_event {
	int freq;
	int ht_enabled;
	int chan_offset;
	enum nl80211_chan_width chan_width;
	int cf1;
	int cf2;
} dfs_event;

void woal_cfg80211_dfs_vendor_event(moal_private *priv, int event,
				    struct cfg80211_chan_def *chandef);

enum ATTR_RSSI_MONITOR {
	ATTR_RSSI_MONITOR_CONTROL,
	ATTR_RSSI_MONITOR_MIN_RSSI,
	ATTR_RSSI_MONITOR_MAX_RSSI,
	ATTR_RSSI_MONITOR_CUR_BSSID,
	ATTR_RSSI_MONITOR_CUR_RSSI,
	ATTR_RSSI_MONITOR_MAX,
};
void woal_cfg80211_rssi_monitor_event(moal_private *priv, t_s16 rssi);

/**vendor sub command*/
enum vendor_sub_command {
	sub_cmd_set_drvdbg = 0,
	sub_cmd_set_roaming_offload_key = 0x0002,
	sub_cmd_dfs_capability = 0x0005,
	sub_cmd_get_correlated_time = 0x0006,
	sub_cmd_set_scan_mac_oui = 0x0007,
	sub_cmd_set_packet_filter = 0x0011,
	sub_cmd_get_packet_filter_capability,
	sub_cmd_nd_offload = 0x0100,
	SUBCMD_RTT_GET_CAPA = 0x1100,
	SUBCMD_RTT_RANGE_REQUEST,
	SUBCMD_RTT_RANGE_CANCEL,
	SUBCMD_RTT_GET_RESPONDER_INFO,
	SUBCMD_RTT_ENABLE_RESPONDER,
	SUBCMD_RTT_DISABLE_RESPONDER,
	SUBCMD_RTT_SET_LCI,
	SUBCMD_RTT_SET_LCR,
	sub_cmd_get_valid_channels = 0x1009,
	sub_cmd_get_wifi_supp_feature_set = 0x100a,
	sub_cmd_set_country_code = 0x100d,
	sub_cmd_get_fw_version = 0x1404,
	sub_cmd_get_drv_version = 0x1406,
	sub_cmd_start_logging = 0x1400,
	sub_cmd_get_wifi_logger_supp_feature_set,
	sub_cmd_get_ring_buff_data,
	sub_cmd_get_ring_buff_status,
	sub_cmd_get_wake_reason = 0x1408,
	sub_cmd_start_packet_fate_monitor,
	sub_cmd_rssi_monitor = 0x1500,
	/*Sub-command for wifi hal */
	sub_cmd_get_roaming_capability = 0x1700,
	sub_cmd_fw_roaming_enable = 0x1701,
	sub_cmd_fw_roaming_config = 0x1702,
	/*Sub-command for wpa_supplicant */
	sub_cmd_fw_roaming_support = 0x0010,
	sub_cmd_max,
};

void woal_register_cfg80211_vendor_command(struct wiphy *wiphy);
int woal_cfg80211_vendor_event(IN moal_private *priv,
			       IN int event, IN t_u8 *data, IN int len);

enum mrvl_wlan_vendor_attr {
	MRVL_WLAN_VENDOR_ATTR_INVALID = 0,
	/* Used by MRVL_NL80211_VENDOR_SUBCMD_DFS_CAPABILITY */
	MRVL_WLAN_VENDOR_ATTR_DFS = 1,
	MRVL_WLAN_VENDOR_ATTR_AFTER_LAST,

	MRVL_WLAN_VENDOR_ATTR_MAX = MRVL_WLAN_VENDOR_ATTR_AFTER_LAST - 1,
};

typedef enum {
	ATTR_ND_OFFLOAD_INVALID = 0,
	ATTR_ND_OFFLOAD_CONTROL,
	ATTR_ND_OFFLOAD_MAX,
} ND_OFFLOAD_ATTR;

int woal_roam_ap_info(IN moal_private *priv, IN t_u8 *data, IN int len);
#endif /*endif CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) */

typedef struct {
	u32 max_blacklist_size;
	u32 max_whitelist_size;
} wifi_roaming_capabilities;

typedef struct {
	u32 num_bssid;
	t_u8 mac_addr[MAX_AP_LIST][MLAN_MAC_ADDR_LENGTH];
} wifi_bssid_params;

typedef struct {
	u32 length;
	char ssid[MLAN_MAX_SSID_LENGTH];
} ssid_t;

typedef struct {
	u32 num_ssid;
	ssid_t whitelist_ssid[MAX_SSID_NUM];
} wifi_ssid_params;

/*Attribute for wifi hal*/
enum mrvl_wlan_vendor_attr_fw_roaming {
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_INVALID = 0,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_CAPA,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_CONTROL,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_CONFIG_BSSID,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_CONFIG_SSID,
	/* keep last */
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_AFTER_LAST,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_MAX =
		MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_AFTER_LAST - 1
};

/*Attribute for wpa_supplicant*/
enum mrvl_wlan_vendor_attr_roam_auth {
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_INVALID = 0,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_BSSID,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_REQ_IE,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_RESP_IE,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AUTHORIZED,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_KEY_REPLAY_CTR,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KCK,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KEK,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_SUBNET_STATUS,
	MRVL_WLAN_VENDOR_ATTR_FW_ROAMING_SUPPORT,
	/* keep last */
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AFTER_LAST,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_MAX =
		MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AFTER_LAST - 1
};

#define PROPRIETARY_TLV_BASE_ID 0x100
#define TLV_TYPE_APINFO (PROPRIETARY_TLV_BASE_ID + 249)
#define TLV_TYPE_KEYINFO (PROPRIETARY_TLV_BASE_ID + 250)
#define TLV_TYPE_ASSOC_REQ_IE (PROPRIETARY_TLV_BASE_ID + 292)

/** MrvlIEtypesHeader_t */
typedef struct MrvlIEtypesHeader {
	/** Header type */
	t_u16 type;
	/** Header length */
	t_u16 len;
} __ATTRIB_PACK__ MrvlIEtypesHeader_t;

typedef struct _key_info_tlv {
	/** Header */
	MrvlIEtypesHeader_t header;
	/** kck, kek, key_replay*/
	mlan_ds_misc_gtk_rekey_data key;
} key_info;

typedef struct _apinfo_tlv {
	/** Header */
	MrvlIEtypesHeader_t header;
	/** Assoc response buffer */
	t_u8 rsp_ie[1];
} apinfo;

enum attr_rtt {
	ATTR_RTT_INVALID = 0,
	ATTR_RTT_CAPA,
	ATTR_RTT_TARGET_NUM,
	ATTR_RTT_TARGET_CONFIG,
	ATTR_RTT_TARGET_ADDR,
	ATTR_RTT_RESULT_COMPLETE,
	ATTR_RTT_RESULT_NUM,
	ATTR_RTT_RESULT_FULL,
	ATTR_RTT_CHANNEL_INFO,
	ATTR_RTT_MAX_DUR_SEC,
	ATTR_RTT_PREAMBLE,
	ATTR_RTT_LCI_INFO,
	ATTR_RTT_LCR_INFO,

	/* keep last */
	ATTR_RTT_AFTER_LAST,
	ATTR_RTT_MAX = ATTR_RTT_AFTER_LAST
};

mlan_status woal_cfg80211_event_rtt_result(IN moal_private *priv,
					   IN t_u8 *data, IN int len);

#endif /* _MOAL_CFGVENDOR_H_ */
