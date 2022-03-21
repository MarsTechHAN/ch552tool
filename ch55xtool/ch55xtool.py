#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import argparse
import random

import usb.core
import usb.util

# ======= Some C-like static constants =======
DFU_ID_VENDOR	= 0x4348
DFU_ID_PRODUCT	= 0x55e0

EP_OUT_ADDR	= 0x02
EP_IN_ADDR	= 0x82

USB_MAX_TIMEOUT = 2000

CH55X_IC_REF = {}
CH55X_IC_REF[0x51] = {
	'device_name': 'CH551',
	'device_flash_size': 10240,
	'device_dataflash_size': 128,
	'chip_id': 0x51}
CH55X_IC_REF[0x52] = {
	'device_name': 'CH552',
	'device_flash_size': 16384,
	'device_dataflash_size': 128,
	'chip_id': 0x52}
CH55X_IC_REF[0x53] = {
	'device_name': 'CH553',
	'device_flash_size': 10240,
	'device_dataflash_size': 128,
	'chip_id': 0x53}
CH55X_IC_REF[0x54] = {
	'device_name': 'CH554',
	'device_flash_size': 14336,
	'device_dataflash_size': 128,
	'chip_id': 0x54}
CH55X_IC_REF[0x59] = {
	'device_name': 'CH559',
	'device_flash_size': 61440,
	'device_dataflash_size': 128,
	'chip_id': 0x59}
CH55X_IC_REF[0x68] = {
	'device_name': 'CH568',
	'device_flash_size': (128+64)*1024,
	'device_dataflash_size': 32*1024,
	'chip_id': 0x68}
# =============================================
WCH_CMDS = 	{	"Detect":		b'\xA1',
				"End":			b'\xA2',
				"SetKey":		b'\xA3',
				"FlashErase":	b'\xA4',
				"FlashWrite":	b'\xA5',
				"FlashVerify":	b'\xA6',
				"ReadConfig":	b'\xA7',
				"WriteConfig":	b'\xA8',
				"DataErase":	b'\xA9',
				"DataWrite":	b'\xAA',
				"DataRead":		b'\xAB',
			}

END_FLASH_CMD_V2 =   [0xa2, 0x01, 0x00] + [0x00]
RESET_RUN_CMD_V2 =   [0xa2, 0x01, 0x00] + [0x01]

# Meaning of those two values not yet clear :(
DETECT_PL_START = b'\x42\x10'
#DETECT_PL_START = b'\x52\x11'
DETECT_APP_ID_B = b'MCU ISP & WCH.CN'

# Unknown bits work only all together like 0x07 !!
CFG_FLAG_UNKN1   = 0x01
CFG_FLAG_UNKN2   = 0x02
CFG_FLAG_UNKN3   = 0x04
CFG_FLAG_UNKNs   = CFG_FLAG_UNKN1 | CFG_FLAG_UNKN2 | CFG_FLAG_UNKN3
# Those bits work individualy 
CFG_FLAG_BOOTVER = 0x08
CFG_FLAG_UID     = 0x10

# =============================================

def cmd_send(dev, cmd_bin, payload):
	pl_len = len(payload)
	packet = cmd_bin + pl_len.to_bytes(2,'little') + payload
	dev.write(EP_OUT_ADDR,packet)

def cmd_reply_receive(dev, cmd_bin):
	cfg = dev.get_active_configuration()
	intf = cfg[(0,0)]
	ep_in = usb.util.find_descriptor(intf, bEndpointAddress=EP_IN_ADDR)
	reply = ep_in.read(ep_in.wMaxPacketSize, USB_MAX_TIMEOUT)
	if((reply != None) and (reply[0] == cmd_bin[0])):
		reply_val = reply[1]
		reply_payload_len = int.from_bytes(reply[2:4],'little')
		if(reply_payload_len > 0):
			reply_payload = reply[4:4+reply_payload_len]
		else:
			reply_payload = None
	else:
		reply_val = None
		reply_payload = None
		
	return reply_val, reply_payload 

def cmd_exec(dev, cmd, payload):
	cmd_bin = WCH_CMDS.get(cmd)
	if(cmd_bin != None):
		cmd_send(dev, cmd_bin, payload)
		return cmd_reply_receive(dev, cmd_bin)
	else:
		return None,None

def __get_dfu_device(idVendor=DFU_ID_VENDOR, idProduct=DFU_ID_PRODUCT):
	dev = usb.core.find(idVendor=idVendor, idProduct=idProduct)
	if dev is None:
		return (None, 'NO_DEV_FOUND')
	try:
		if dev.is_kernel_driver_active(0):
			try:
				dev.detach_kernel_driver(0)
			except usb.core.USBError:
				return (None, 'USB_ERROR_CANNOT_DETACH_KERNEL_DRIVER')
	except BaseException:
		pass  # Windows dont need detach

	try:
		dev.set_configuration()
	except usb.core.USBError:
		return (None, 'USB_ERROR_CANNOT_SET_CONFIG')

	try:
		usb.util.claim_interface(dev, 0)
	except usb.core.USBError:
		return (None, 'USB_ERROR_CANNOT_CLAIM_INTERFACE')

	return (dev, '')

def __detect_ch5xx(dev):
	cmd_pl = DETECT_PL_START +  DETECT_APP_ID_B
	ret, ret_pl = cmd_exec(dev, 'Detect', cmd_pl)
	if(ret != None and len(ret_pl) == 2):
		chip_id    = ret_pl[0]
		chip_subid = ret_pl[1]
	else:
		chip_id    = 0
		chip_subid = 0
	return ret, chip_id, chip_subid

def __read_cfg_ch5xx(dev, req_fields, chip_id, chip_subid):
	predict_ret_pl_len = 2 # 2 byte for fields
	if(req_fields & CFG_FLAG_UNKN1):	predict_ret_pl_len += 4
	if(req_fields & CFG_FLAG_UNKN2):	predict_ret_pl_len += 4
	if(req_fields & CFG_FLAG_UNKN3):	predict_ret_pl_len += 4
	if(req_fields & CFG_FLAG_BOOTVER):	predict_ret_pl_len += 4
	if(req_fields & CFG_FLAG_UID):		predict_ret_pl_len += 8
	
	cmd_pl = req_fields.to_bytes(2,'little')
	ret, ret_pl = cmd_exec(dev, 'ReadConfig', cmd_pl)

	cfg_dict = {}
	if(ret is None):
		print("Get config failure!")
		return ret, cfg_dict

	reply_prc_bytes = 0
	reply_fields = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+2],'little')
	reply_prc_bytes += 2
	
	if(len(ret_pl) != predict_ret_pl_len or reply_fields != req_fields):
		print("Reply fields do not match requested!")
		
	cfg_dict["Fields"] = reply_fields
	if(reply_fields & CFG_FLAG_UNKN1):
		cfg_dict[CFG_FLAG_UNKN1] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4
		
	if(reply_fields & CFG_FLAG_UNKN2):
		cfg_dict[CFG_FLAG_UNKN2] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4
		
	if(reply_fields & CFG_FLAG_UNKN3):
		cfg_dict[CFG_FLAG_UNKN3] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4

	if(reply_fields & CFG_FLAG_BOOTVER):
		cfg_dict[CFG_FLAG_BOOTVER] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4])
		reply_prc_bytes += 4

	if(reply_fields & CFG_FLAG_UID):
		if((chip_subid == 0x11) and (chip_id not in [0x55, 0x56, 0x57])):
			cfg_dict[CFG_FLAG_UID] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4]) + b'\x00'*4
		else:
			cfg_dict[CFG_FLAG_UID] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+8])
		reply_prc_bytes += 8

	return ret, cfg_dict

def __write_cfg_ch5xx(dev, cfg_dict):
	cfg_fileds = cfg_dict.get("Fields")
	if(cfg_fileds is None):
		print("Not defined fields to set configuration.")
		return None, None
	set_fields	= 0
	cmd_pl 		= b''
	if(cfg_fields & CFG_FLAG_UNKN1):
		field_val = cfg_dict.get(CFG_FLAG_UNKN1)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= CFG_FLAG_UNKN1
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(CFG_FLAG_UNKN1))

	if(cfg_fields & CFG_FLAG_UNKN2):
		field_val = cfg_dict.get(CFG_FLAG_UNKN2)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= CFG_FLAG_UNKN2
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(CFG_FLAG_UNKN2))

	if(cfg_fields & CFG_FLAG_UNKN3):
		field_val = cfg_dict.get(CFG_FLAG_UNKN3)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= CFG_FLAG_UNKN3
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(CFG_FLAG_UNKN3))

	if(set_fields > 0):
		cmd_pl = set_fields.to_bytes(2,'little') + cmd_pl
		ret, ret_pl = cmd_exec(dev, 'WriteConfig', cmd_pl)
		return ret, cfg_dict
	else:
		print("No setable chip fields in given config.")
		return None, None

def __chip_uid_chk_sum(chip_subid, chip_uid):
	if(chip_subid == 0x11):
		return sum(chip_uid[:4]) & 0xFF
	else:
		return sum(chip_uid) & 0xFF

def __gen_key_values(chip_id, chip_uid_chksum):
	# In original soft KeyBase length = 30 + (random int)%31 
	key_base_len = random.randint(30,61)
	key_base = bytearray(key_base_len)
	for i in range(key_base_len):
		key_base[i] = random.randint(0,255)
	key = bytearray(8)
	key[0] = chip_uid_chksum ^ key_base[ 4 * (key_base_len // 7)]
	key[1] = chip_uid_chksum ^ key_base[      key_base_len // 5 ]
	key[2] = chip_uid_chksum ^ key_base[      key_base_len // 7 ]
	key[3] = chip_uid_chksum ^ key_base[ 6 * (key_base_len // 7)]
	key[4] = chip_uid_chksum ^ key_base[ 3 * (key_base_len // 7)]
	key[5] = chip_uid_chksum ^ key_base[ 3 * (key_base_len // 5)]
	key[6] = chip_uid_chksum ^ key_base[ 5 * (key_base_len // 7)]
	key[7] = (chip_id + key[0]) & 0xff
	return key, key_base

def __send_key_base(dev, key_base):
	ret, ret_pl = cmd_exec(dev, 'SetKey', key_base)
	if (ret != None and len(ret_pl)>0):
		return ret_pl[0] == 0
	else:
		return None

def __flash_ops_write_verify(dev, key_xor_chksum, data, func="Write",max_packet_size=64):
	if(func not in [ 'Write' , 'Verify'] ):
		return None
	data_length = len(data)
	curr_addr = 0
	max_data_len_perpack = max_packet_size - 3 - 5
	data_buff = bytearray(max_data_len_perpack)
	while curr_addr < data_length:
		left_len = data_length - curr_addr
		if (left_len) > max_data_len_perpack:
			pkt_length = max_data_len_perpack
			data_buff[:pkt_length] = data[curr_addr:curr_addr+pkt_length]
		else:
			pkt_length = left_len
			data_buff[:pkt_length] = data[curr_addr:curr_addr+pkt_length]
			tmp = left_len & 0x07
			if( tmp != 0):
				pad_len  = 8 - tmp
				pkt_length +=  pad_len
				data_buff[left_len:pkt_length] = b'\x00'* pad_len

		for index in range(pkt_length):
			data_buff[index] ^= key_xor_chksum[index & 0x07]
			
		cmd_pl = curr_addr.to_bytes(4,'little') + bytes([random.randint(0,255)]) + data_buff[:pkt_length]
		
		ret, ret_pl = cmd_exec(dev, 'Flash'+func, cmd_pl)
		if( ret == None or ret_pl[0] != 0x00):
			return None
		curr_addr = curr_addr + pkt_length
	if(curr_addr > data_length):
		return data_length
	else:
		return curr_addr

def __erase_chip_ch5xx(dev, chip_ref):
	# We assume pages size is 1kb
	erase_page_cnt = chip_ref['device_flash_size']>>10
	cmd_pl = erase_page_cnt.to_bytes(4,'little')
	ret, ret_pl = cmd_exec(dev,'FlashErase', cmd_pl)
	if ret_pl[0] == 0:
		return True
	else:
		return None

def __end_flash_ch55x_v2(dev):
	dev.write(EP_OUT_ADDR, END_FLASH_CMD_V2)
	ret = dev.read(EP_IN_ADDR, 6, USB_MAX_TIMEOUT)
	if ret[4] != 0x00:
		return None
	else:
		return True

def __restart_run_ch55x_v2(dev):
	dev.write(EP_OUT_ADDR, RESET_RUN_CMD_V2)

def main():
	parser = argparse.ArgumentParser(
		description="USBISP Tool For WinChipHead CH55x/CH56x .")
	parser.add_argument(
		'-f', '--flash', type=str, default='',
		help="The target file to be flashed. This must be a binary file (hex files are not supported).")
	parser.add_argument(
		'-e', '--erase', action='store_true', default=False,
		help="Erase chip program flash.")
	parser.add_argument(
		'-c', '--clean', action='store_true', default=False,
		help="Clean chip data eeprom.")

	parser.add_argument(
		'-r', '--reset_at_end', action='store_true', default=False,
		help="Reset as the end of operations.")
	parser.add_argument(
		'-l', '--list', action='store_true', default=False,
		help="List connected devices.")
	parser.add_argument(
		'-v', '--verbose', action='store_true', default=False,
		help="Verbose program process output.")

	args = parser.parse_args()


	ret = __get_dfu_device()
	if ret[0] is None:
		print('Failed to get device, please check your libusb installation.')
		sys.exit(-1)
		
	dev = ret[0]

	ret, chip_id, chip_subid = __detect_ch5xx(dev)
	if ret is None:
		print('Unable to detect CH5xx.')
		print('Welcome to report this issue with a screen shot from the official CH5xx tool.')
		sys.exit(-1)
	
	chip_ref = CH55X_IC_REF.get(chip_id)
	if chip_ref is None:
		print('Chip ID: %x is not known = not supported' % chip_id)
		print('Welcome to report this issue with a screen shot from the official CH5xx tool.')
		sys.exit(-1)

	print('Found %s with SubId:%d' % (chip_ref['device_name'], chip_subid))

	ret, chip_cfg = __read_cfg_ch5xx(dev, CFG_FLAG_BOOTVER | CFG_FLAG_UID | CFG_FLAG_UNKNs, chip_id, chip_subid)
	if ret is None:
		print('Cannot read chip configuration!')
		sys.exit(-1)
	else:
		bootver = chip_cfg.get(CFG_FLAG_BOOTVER)
		uid		= chip_cfg.get(CFG_FLAG_UID)
		if( bootver is None or uid is None):
			print('Cannot read chip bootloader version or uniqe ID.')
			sys.exit(-1)

	ver_str = '%d%d.%d%d' % (bootver[0], bootver[1], bootver[2], bootver[3])
	print('BTVER:%s' % ver_str)

	uid_str = '%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X' % (uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7])
	print('UID:%s' % uid_str)

	verb = True
	
	flash_file = args.flash
	
	if flash_file != '':
		file_data = list(open(flash_file, 'rb').read())
		if flash_file.endswith('.hex') or flash_file.endswith('.ihx') or file_data[0]==58:
			print("WARNING: This looks like a hex file. This tool only supports binary files.")
		if ver_str in ['02.30', '02.31', '02.40']:
			chk_sum = __chip_uid_chk_sum(chip_subid, uid)

			enc_key, key_b = __gen_key_values(chip_id, chk_sum)
			ret = __send_key_base(dev,key_b)
			if ret is None:
				sys.exit('Failed to write key for flash write to CH5xx.')

			ret = __erase_chip_ch5xx(dev,chip_ref)
			if ret is None:
				sys.exit('Failed to erase CH55x.')

			ret = __flash_ops_write_verify(dev, enc_key, file_data, func="Write")
			if ret is None:
				sys.exit('Failed to flash firmware of CH55x.')

			enc_key, key_b = __gen_key_values(chip_id, chk_sum)
			ret = __send_key_base(dev,key_b)
			if ret is None:
				sys.exit('Failed to write key for flash verify to CH5xx.')

			ret = __flash_ops_write_verify(dev, enc_key, file_data, func="Verify")
			if ret is None:
				sys.exit('Failed to verify firmware of CH55x.')
		else:
			sys.exit('Bootloader version not supported.')

		ret = __end_flash_ch55x_v2(dev)
		if ret is None:
			sys.exit('Failed to end flash process.')

		print('Flash done.')

		if args.reset_at_end:
			__restart_run_ch55x_v2(dev)
			print('Restart and run.')

if __name__ == '__main__':
	sys.exit(main())
