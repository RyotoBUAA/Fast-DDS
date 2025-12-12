#!/usr/bin/env python3
"""
生成 RTPS 协议模糊测试种子文件
"""

import os
import struct

SEEDS_DIR = os.path.dirname(os.path.abspath(__file__))

def write_seed(filename, data):
    """写入种子文件"""
    filepath = os.path.join(SEEDS_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(data)
    print(f"Created: {filename} ({len(data)} bytes)")

def make_rtps_header(guid_prefix=None):
    """创建 RTPS 消息头"""
    header = b'RTPS'  # Magic
    header += bytes([2, 3])  # Protocol version 2.3
    header += bytes([0x01, 0x0f])  # Vendor ID (eProsima)
    if guid_prefix is None:
        guid_prefix = bytes(12)  # 12 bytes of zeros
    header += guid_prefix
    return header

def make_submessage_header(submsg_id, flags, length):
    """创建 submessage 头"""
    return struct.pack('<BBH', submsg_id, flags, length)

def make_entity_id(key, kind):
    """创建 EntityId"""
    return bytes(key) + bytes([kind])

def make_sequence_number(high, low):
    """创建序列号"""
    return struct.pack('<iI', high, low)

# ==========================================
# 创建各种种子
# ==========================================

# 1. 最小有效 RTPS 消息（只有 header）
write_seed('minimal_rtps.bin', make_rtps_header())

# 2. RTPS + PAD submessage
pad_msg = make_rtps_header()
pad_msg += make_submessage_header(0x01, 0x01, 0)  # PAD
write_seed('rtps_pad.bin', pad_msg)

# 3. RTPS + DATA submessage
data_msg = make_rtps_header()
# DATA header: flags=0x05 (E=1, D=1)
data_msg += make_submessage_header(0x15, 0x05, 28)
# DATA body
data_msg += struct.pack('<HH', 0, 16)  # extraFlags, octetsToInlineQos
data_msg += make_entity_id([0, 0, 0], 0x00)  # readerId
data_msg += make_entity_id([0, 0, 1], 0x02)  # writerId
data_msg += make_sequence_number(0, 1)  # writerSN
# Payload
data_msg += b'Hello World!'
write_seed('rtps_data.bin', data_msg)

# 4. RTPS + HEARTBEAT submessage
hb_msg = make_rtps_header()
# HEARTBEAT: flags=0x01 (E=1)
hb_msg += make_submessage_header(0x07, 0x01, 28)
# HEARTBEAT body
hb_msg += make_entity_id([0, 0, 0], 0x00)  # readerId
hb_msg += make_entity_id([0, 0, 1], 0x02)  # writerId
hb_msg += make_sequence_number(0, 1)  # firstSN
hb_msg += make_sequence_number(0, 10)  # lastSN
hb_msg += struct.pack('<i', 1)  # count
write_seed('rtps_heartbeat.bin', hb_msg)

# 5. RTPS + ACKNACK submessage
ack_msg = make_rtps_header()
# ACKNACK: flags=0x01 (E=1)
ack_msg += make_submessage_header(0x06, 0x01, 24)
# ACKNACK body
ack_msg += make_entity_id([0, 0, 1], 0x07)  # readerId
ack_msg += make_entity_id([0, 0, 0], 0x00)  # writerId
ack_msg += make_sequence_number(0, 1)  # readerSNState.base
ack_msg += struct.pack('<I', 0)  # readerSNState.numBits
ack_msg += struct.pack('<i', 1)  # count
write_seed('rtps_acknack.bin', ack_msg)

# 6. RTPS + GAP submessage
gap_msg = make_rtps_header()
# GAP: flags=0x01 (E=1)
gap_msg += make_submessage_header(0x08, 0x01, 28)
# GAP body
gap_msg += make_entity_id([0, 0, 0], 0x00)  # readerId
gap_msg += make_entity_id([0, 0, 1], 0x02)  # writerId
gap_msg += make_sequence_number(0, 1)  # gapStart
gap_msg += make_sequence_number(0, 5)  # gapList.base
gap_msg += struct.pack('<I', 0)  # gapList.numBits
write_seed('rtps_gap.bin', gap_msg)

# 7. RTPS + INFO_TS submessage
ts_msg = make_rtps_header()
# INFO_TS: flags=0x01 (E=1)
ts_msg += make_submessage_header(0x09, 0x01, 8)
# INFO_TS body
ts_msg += struct.pack('<II', 1234567890, 0)  # timestamp
write_seed('rtps_info_ts.bin', ts_msg)

# 8. RTPS + INFO_DST submessage
dst_msg = make_rtps_header()
# INFO_DST: flags=0x01 (E=1)
dst_msg += make_submessage_header(0x0e, 0x01, 12)
# INFO_DST body
dst_msg += bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])  # guidPrefix
write_seed('rtps_info_dst.bin', dst_msg)

# 9. RTPS + 多个 submessage
multi_msg = make_rtps_header()
# INFO_TS
multi_msg += make_submessage_header(0x09, 0x01, 8)
multi_msg += struct.pack('<II', 1234567890, 0)
# INFO_DST
multi_msg += make_submessage_header(0x0e, 0x01, 12)
multi_msg += bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
# DATA
multi_msg += make_submessage_header(0x15, 0x05, 32)
multi_msg += struct.pack('<HH', 0, 16)
multi_msg += make_entity_id([0, 0, 0], 0x00)
multi_msg += make_entity_id([0, 0, 1], 0x02)
multi_msg += make_sequence_number(0, 1)
multi_msg += b'Test data!!!'
# HEARTBEAT
multi_msg += make_submessage_header(0x07, 0x01, 28)
multi_msg += make_entity_id([0, 0, 0], 0x00)
multi_msg += make_entity_id([0, 0, 1], 0x02)
multi_msg += make_sequence_number(0, 1)
multi_msg += make_sequence_number(0, 1)
multi_msg += struct.pack('<i', 1)
write_seed('rtps_multi_submsg.bin', multi_msg)

# 10. SPDP 发现消息模板
spdp_msg = make_rtps_header()
# DATA with key
spdp_msg += make_submessage_header(0x15, 0x05, 100)
spdp_msg += struct.pack('<HH', 0, 16)
spdp_msg += make_entity_id([0, 1, 0], 0xc7)  # SPDP reader
spdp_msg += make_entity_id([0, 1, 0], 0xc2)  # SPDP writer
spdp_msg += make_sequence_number(0, 1)
# Serialized participant data (简化)
spdp_msg += b'\x00\x02'  # PL_CDR_LE
spdp_msg += b'\x00\x00'  # options
# PID_PARTICIPANT_GUID
spdp_msg += struct.pack('<HH', 0x50, 16)
spdp_msg += bytes(16)
# PID_BUILTIN_ENDPOINT_SET
spdp_msg += struct.pack('<HH', 0x58, 4)
spdp_msg += struct.pack('<I', 0x3f)
# PID_SENTINEL
spdp_msg += struct.pack('<HH', 0x01, 0)
write_seed('rtps_spdp.bin', spdp_msg)

# ==========================================
# 边界值和畸形种子
# ==========================================

# 11. 无效 magic
invalid_magic = b'XXXX' + bytes(16)
write_seed('invalid_magic.bin', invalid_magic)

# 12. 截断的 header
truncated = b'RTP'
write_seed('truncated_header.bin', truncated)

# 13. 无效版本
invalid_version = b'RTPS' + bytes([0, 0]) + bytes(14)
write_seed('invalid_version.bin', invalid_version)

# 14. 超大长度字段
big_length = make_rtps_header()
big_length += make_submessage_header(0x15, 0x05, 0xFFFF)  # 声称很大
big_length += b'Small payload'
write_seed('big_length_field.bin', big_length)

# 15. 零长度
zero_length = make_rtps_header()
zero_length += make_submessage_header(0x15, 0x05, 0)
write_seed('zero_length.bin', zero_length)

# 16. 未知 submessage ID
unknown_id = make_rtps_header()
unknown_id += make_submessage_header(0xFF, 0x01, 8)
unknown_id += bytes(8)
write_seed('unknown_submsg_id.bin', unknown_id)

# 17. 边界序列号
boundary_seq = make_rtps_header()
boundary_seq += make_submessage_header(0x15, 0x05, 28)
boundary_seq += struct.pack('<HH', 0, 16)
boundary_seq += make_entity_id([0, 0, 0], 0x00)
boundary_seq += make_entity_id([0, 0, 1], 0x02)
boundary_seq += make_sequence_number(0x7FFFFFFF, 0xFFFFFFFF)  # 最大值
boundary_seq += b'Max SeqNum'
write_seed('boundary_seqnum.bin', boundary_seq)

# 18. 负序列号
negative_seq = make_rtps_header()
negative_seq += make_submessage_header(0x15, 0x05, 28)
negative_seq += struct.pack('<HH', 0, 16)
negative_seq += make_entity_id([0, 0, 0], 0x00)
negative_seq += make_entity_id([0, 0, 1], 0x02)
negative_seq += make_sequence_number(-1, 0)  # 负高位
negative_seq += b'Neg SeqNum'
write_seed('negative_seqnum.bin', negative_seq)

# 19. DATA_FRAG submessage
data_frag = make_rtps_header()
data_frag += make_submessage_header(0x16, 0x05, 44)
# DATA_FRAG body
data_frag += struct.pack('<HH', 0, 28)  # extraFlags, octetsToInlineQos
data_frag += make_entity_id([0, 0, 0], 0x00)  # readerId
data_frag += make_entity_id([0, 0, 1], 0x02)  # writerId
data_frag += make_sequence_number(0, 1)  # writerSN
data_frag += struct.pack('<I', 1)  # fragmentStartingNum
data_frag += struct.pack('<HH', 1, 1024)  # fragmentsInSubmessage, fragmentSize
data_frag += struct.pack('<I', 4096)  # sampleSize
data_frag += b'Fragment'
write_seed('rtps_data_frag.bin', data_frag)

# 20. 安全 submessage
sec_msg = make_rtps_header()
# SEC_PREFIX
sec_msg += make_submessage_header(0x31, 0x01, 8)
sec_msg += bytes(8)
# SEC_BODY
sec_msg += make_submessage_header(0x30, 0x01, 32)
sec_msg += bytes(32)
# SEC_POSTFIX
sec_msg += make_submessage_header(0x32, 0x01, 16)
sec_msg += bytes(16)
write_seed('rtps_security.bin', sec_msg)

print(f"\nCreated {len([f for f in os.listdir(SEEDS_DIR) if f.endswith('.bin')])} seed files in {SEEDS_DIR}")

