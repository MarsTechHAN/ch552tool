#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import time
import argparse
import random

import usb.core
import usb.util

import configparser
# ======= Some C-like static constants =======
DFU_ID_VENDOR	= 0x4348
DFU_ID_PRODUCT	= 0x55e0

EP_OUT_ADDR	= 0x02
EP_IN_ADDR	= 0x82

USB_MAX_TIMEOUT = 5000

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

# Meaning of those two values not yet clear :(
DETECT_PL_START = b'\x42\x10'
#DETECT_PL_START = b'\x52\x11'
DETECT_APP_ID_B = b'MCU ISP & WCH.CN'

# Unknown bits work only all together like 0x07 !!
FLAG_CFG1   = 0x01
FLAG_CFG2   = 0x02
FLAG_CFG3   = 0x04
FLAG_CFGs   = FLAG_CFG1 | FLAG_CFG2 | FLAG_CFG3
# Those bits work individualy 
FLAG_BOOTVER = 0x08
FLAG_UID     = 0x10

# =============================================
def get_chip_parameters(chip_id,wcfg_path):
	chip_params = {}
	params_ini = configparser.ConfigParser()
	params_ini.optionxform = lambda option: option
	params_ini.read(wcfg_path+'/typeall.wcfg')
	for section in params_ini.sections():
		if(params_ini.has_option(section,'chipid')):
			if(params_ini.getint(section,'chipid') == chip_id):
				chip_params.update({'name':section})
				chip_params.update({'chip_id':chip_id})
				chip_params.update({'flash_size':params_ini.getint(section,'MaxFlashSize')})
				chip_params.update({'dataflash_size':params_ini.getint(section,'MaxEepromSize')})
				chip_params.update({'McuType':params_ini.getint(section,'McuType')})
				break
	else:
		chip_params = None
	return chip_params

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
	if(req_fields & FLAG_CFG1):	predict_ret_pl_len += 4
	if(req_fields & FLAG_CFG2):	predict_ret_pl_len += 4
	if(req_fields & FLAG_CFG3):	predict_ret_pl_len += 4
	if(req_fields & FLAG_BOOTVER):	predict_ret_pl_len += 4
	if(req_fields & FLAG_UID):		predict_ret_pl_len += 8
	
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
	if(reply_fields & FLAG_CFG1):
		cfg_dict[FLAG_CFG1] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4
		
	if(reply_fields & FLAG_CFG2):
		cfg_dict[FLAG_CFG2] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4
		
	if(reply_fields & FLAG_CFG3):
		cfg_dict[FLAG_CFG3] = int.from_bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4],'little')
		reply_prc_bytes += 4

	if(reply_fields & FLAG_BOOTVER):
		cfg_dict[FLAG_BOOTVER] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4])
		reply_prc_bytes += 4

	if(reply_fields & FLAG_UID):
		if((chip_subid == 0x11) and (chip_id not in [0x55, 0x56, 0x57])):
			cfg_dict[FLAG_UID] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+4]) + b'\x00'*4
		else:
			cfg_dict[FLAG_UID] = bytes(ret_pl[reply_prc_bytes:reply_prc_bytes+8])
		reply_prc_bytes += 8

	return ret, cfg_dict

def __write_cfg_ch5xx(dev, cfg_dict):
	cfg_fileds = cfg_dict.get("Fields")
	if(cfg_fileds is None):
		print("Not defined fields to set configuration.")
		return None, None
	set_fields	= 0
	cmd_pl 		= b''
	if(cfg_fields & FLAG_CFG1):
		field_val = cfg_dict.get(FLAG_CFG1)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= FLAG_CFG1
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG1))

	if(cfg_fields & FLAG_CFG2):
		field_val = cfg_dict.get(FLAG_CFG2)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= FLAG_CFG2
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG2))

	if(cfg_fields & FLAG_CFG3):
		field_val = cfg_dict.get(FLAG_CFG3)
		if(field_val != None and len(field_val) == 4):
			set_fields	|= FLAG_CFG3
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG3))

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

def __flash_ops_write_verify(dev, key_xor_chksum, data, func="FlashWrite"):
	if(func not in [ 'FlashWrite' , 'FlashVerify', 'DataWrite'] ):
		return None
	data_length = len(data)
	curr_addr = 0
	cfg = dev.get_active_configuration()
	intf = cfg[(0,0)]
	ep_out = usb.util.find_descriptor(intf, bEndpointAddress=EP_OUT_ADDR)
	max_packet_size = ep_out.wMaxPacketSize
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
		
		ret, ret_pl = cmd_exec(dev, func, cmd_pl)
		if( ret == None or ret_pl[0] != 0x00):
			return None
		curr_addr = curr_addr + pkt_length
	if(curr_addr > data_length):
		return data_length
	else:
		return curr_addr

def __data_flash_read(dev, data_flash_size):
	curr_addr = 0
	read_data = b''
	cfg = dev.get_active_configuration()
	intf = cfg[(0,0)]
	ep_in = usb.util.find_descriptor(intf, bEndpointAddress=EP_IN_ADDR)
	max_packet_size = ep_in.wMaxPacketSize
	max_rcv_len_perpack = max_packet_size - 4 - 2
	while curr_addr < data_flash_size:
		left_len = data_flash_size - curr_addr
		if (left_len) > max_rcv_len_perpack:
			rcv_pkt_length = max_rcv_len_perpack
		else:
			rcv_pkt_length = left_len
		cmd_pl = curr_addr.to_bytes(4,'little') + rcv_pkt_length.to_bytes(2,'little')
		ret, ret_pl = cmd_exec(dev, 'DataRead', cmd_pl)
		if( ret == None or ret_pl[0] != 0x00):
			return None, read_data
		read_data += bytes(ret_pl[2:])
		curr_addr = curr_addr + len(ret_pl[2:])
	if(curr_addr > data_flash_size):
		return data_flash_size, read_data
	else:
		return curr_addr, read_data

def __erase_program_flash_ch5xx(dev, chip_ref):
	# We assume pages size is 1kb
	erase_page_cnt = chip_ref['flash_size']>>10
	cmd_pl = erase_page_cnt.to_bytes(4,'little')
	ret, ret_pl = cmd_exec(dev,'FlashErase', cmd_pl)
	if ret_pl[0] == 0:
		return True
	else:
		return None

def __erase_data_flash_ch5xx(dev, chip_ref):
	# We assume pages size is 1kb
	erase_page_cnt = chip_ref['dataflash_size']>>10
	if(erase_page_cnt == 0):
		erase_page_cnt = 1
	cmd_pl = int(0).to_bytes(4,'little') + erase_page_cnt.to_bytes(1,'little')
	ret, ret_pl = cmd_exec(dev,'DataErase', cmd_pl)
	if ret_pl[0] == 0:
		return True
	else:
		return None

def __end_flash_ch5xx(dev, restart_after = False):
	cmd_pl  = bytes([restart_after])
	if(restart_after):
		cmd_bin = WCH_CMDS.get("End")
		cmd_send(dev, cmd_bin, cmd_pl)
		return True,None
	else:
		return cmd_exec(dev, "End", cmd_pl)

def main():
	pathname = os.path.dirname(sys.argv[0])
	fullpath = os.path.abspath(pathname)

	parser = argparse.ArgumentParser(
		description="USBISP Tool For WinChipHead CH55x/CH56x .")

	parser.add_argument(
		'-f', '--flash', type=str, default='',
		help="The target file to be written to program flash. This must be a binary file (hex files are not supported). Flashing include chipe erase in front.")
	parser.add_argument(
		'-e', '--erase_flash', action='store_true', default=False,
		help="Erase chip program flash.")
	parser.add_argument(
		'--verify_flash', type=str, action='store', nargs='?', const='', default=None,
		help="Verify flash.")

	parser.add_argument(
		'-d', '--data', type=str, default='',
		help="The target file to be written to data flash. This must be a binary file (hex files are not supported). Flashing include chipe erase in front.")
	parser.add_argument(
		'-c', '--erase_dataflash', action='store_true', default=False,
		help="Clean chip data eeprom.")
	parser.add_argument(
		'-g', '--read_dataflash', type=str, default='',
		help="Read chip data eeprom.")
	parser.add_argument(
		'--verify_data', type=str, action='store', nargs='?', const='', default=None,
		help="Verify data flash.")

	parser.add_argument(
		'-p', '--print_chip_cfg', action='store_true', default=False,
		help="Read and print chip configuration bits 3 x 32bit values.")

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
	
	chip_ref = get_chip_parameters(chip_id, fullpath)
	if chip_ref is None:
		print('Chip ID: %x is not known = not supported' % chip_id)
		print('Welcome to report this issue with a screen shot from the official CH5xx tool.')
		sys.exit(-1)

	print('Found %s with SubId:%d' % (chip_ref['name'], chip_subid))

	ret, chip_cfg = __read_cfg_ch5xx(dev, FLAG_BOOTVER | FLAG_UID, chip_id, chip_subid)
	if ret is None:
		print('Cannot read chip bootloader version/uniqe ID.')
		sys.exit(-1)
	else:
		bootver = chip_cfg.get(FLAG_BOOTVER)
		uid		= chip_cfg.get(FLAG_UID)
		if( bootver is None or uid is None):
			print('Cannot read chip bootloader version or uniqe ID.')
			sys.exit(-1)

	ver_str = '%d%d.%d%d' % (bootver[0], bootver[1], bootver[2], bootver[3])
	print('BTVER:%s' % ver_str)

	uid_str = '%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X' % (uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7])
	print('UID:%s' % uid_str)

	if(float(ver_str)<2.3):
		sys.exit('Bootloader version not supported.')

	chk_sum = __chip_uid_chk_sum(chip_subid, uid)

	if(args.print_chip_cfg):
		ret, chip_cfg = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		if ret is None:
			print('Cannot read chip configs variables.')
			sys.exit(-1)
		else:
			cfg1 = chip_cfg.get(FLAG_CFG1)
			cfg2 = chip_cfg.get(FLAG_CFG2)
			cfg3 = chip_cfg.get(FLAG_CFG3)
			if( cfg1 is None or cfg2 is None or cfg3 is None):
				print('Cannot find chip configurations after read.')
				sys.exit(-1)
			print("Chip configs   0x%08X   0x%08X   0x%08X" % (cfg1, cfg2, cfg3) )

	if(args.read_dataflash !=''):
		ret, ret_data = __data_flash_read(dev, chip_ref['dataflash_size'])
		if(ret is not None):
			data_write_file = open(args.read_dataflash,'wb')
			data_write_file.write(ret_data)
			data_write_file.close()
	
	if(args.data != ''):
		dataflash_write_data = open(args.data, 'rb').read()
		if(args.data.endswith('.hex') or args.data.endswith('.ihx')):
			print("WARNING: This looks like a hex file. This tool only supports binary files.")
		if len(dataflash_write_data) > chip_ref['dataflash_size']:
			print('The binary for Data flashing is too large for the device.')
			print('Binary size: %d, DataFlash size: %d' % (len(dataflash_write_data),chip_ref['dataflash_size']))
			sys.exit(-1)
			
	if(args.data != '' or args.erase_dataflash==True):
		print('Erasing chip data flash.',end="")
		ret = __erase_data_flash_ch5xx(dev,chip_ref)
		if ret is None:
			sys.exit(' Failed.')
		else:
			print(' Done.')

	if(args.data != ''):
		if(len(dataflash_write_data)>0):
			if(dataflash_write_data[0]==58):
				print("WARNING: Flashing data looks like a hex file. This tool only supports binary files.")
			enc_key, key_b = __gen_key_values(chip_id, chk_sum)
			ret = __send_key_base(dev,key_b)
			if ret is None:
				sys.exit('Failed to write key for DataFlash write to CH5xx.')
			print('DataFlashing chip.',end='')
			ret = __flash_ops_write_verify(dev, enc_key, dataflash_write_data, func="DataWrite")
			if ret is None:
				sys.exit('Failed.')
			else:
				print(' Done.')
		else:
			print('Nothing to write to program flash.')

	if(args.verify_data != None):
		if(args.verify_data != ''):
			dataflash_verify_data = open(args.verify_data, 'rb').read()
			if(args.verify_data.endswith('.hex') or args.verify_data.endswith('.ihx')):
				print("WARNING: This looks like a hex file. This tool only supports binary files.")
			if len(dataflash_verify_data) > chip_ref['dataflash_size']:
				print('The binary for verifying is too large for the device.')
				print('Binary size: %d, DataFlash size: %d' % (len(dataflash_verify_data),chip_ref['dataflash_size']))
				sys.exit(-1)
		else:
			if(args.data == ''):
				dataflash_verify_data = b''
			else:
				dataflash_verify_data = dataflash_write_data

		if(len(dataflash_verify_data)>0):
			if(dataflash_verify_data[0]==58):
				print("WARNING: Verifying data looks like a hex file. This tool only supports binary files.")

			print('Verifying Dataflash.',end='')
			ret, ret_data = __data_flash_read(dev, len(dataflash_verify_data))
			if ret is None:
				sys.exit(' Data read failed.')
			elif(ret_data != dataflash_verify_data):
				print(ret_data)
				print(dataflash_verify_data)
				sys.exit(' Compare failed.')
			else:
				print(' Done.')
		else:
			print('Nothing to verifying with data flash.')

	flash_file = args.flash
	if(flash_file != ''):
		flash_write_data = open(flash_file, 'rb').read()
		if(flash_file.endswith('.hex') or flash_file.endswith('.ihx')):
			print("WARNING: This looks like a hex file. This tool only supports binary files.")
		if len(flash_write_data) > chip_ref['flash_size']:
			print('The binary for flashing is too large for the device.')
			print('Binary size: %d, Flash size: %d' % (len(flash_write_data),chip_ref['flash_size']))
			sys.exit(-1)

	if(flash_file != '' or args.erase_flash==True):
		print('Erasing chip flash.',end="")
		ret = __erase_program_flash_ch5xx(dev,chip_ref)
		if ret is None:
			sys.exit(' Failed.')
		else:
			print(' Done.')

	if(flash_file != ''):
		if(len(flash_write_data)>0):
			if(flash_write_data[0]==58):
				print("WARNING: Flashing data looks like a hex file. This tool only supports binary files.")
			enc_key, key_b = __gen_key_values(chip_id, chk_sum)
			ret = __send_key_base(dev,key_b)
			if ret is None:
				sys.exit('Failed to write key for flash write to CH5xx.')
			print('Flashing chip.',end='')
			ret = __flash_ops_write_verify(dev, enc_key, flash_write_data, func="FlashWrite")
			if ret is None:
				sys.exit('Failed to flash firmware of CH55x.')
			else:
				print(' Done.')
		else:
			print('Nothing to write to program flash.')

	if(args.verify_flash != None):
		if(args.verify_flash != ''):
			flash_verify_data = open(args.verify_flash, 'rb').read()
			if(args.verify_flash.endswith('.hex') or args.verify_flash.endswith('.ihx')):
				print("WARNING: This looks like a hex file. This tool only supports binary files.")
			if len(flash_verify_data) > chip_ref['flash_size']:
				print('The binary for verifying is too large for the device.')
				print('Binary size: %d, Flash size: %d' % (len(flash_verify_data),chip_ref['flash_size']))
				sys.exit(-1)
		else:
			if(flash_file == ''):
				flash_verify_data = b''
			else:
				flash_verify_data = flash_write_data

		if(len(flash_verify_data)>0):
			if(flash_verify_data[0]==58):
				print("WARNING: Verifying data looks like a hex file. This tool only supports binary files.")
			enc_key, key_b = __gen_key_values(chip_id, chk_sum)
			ret = __send_key_base(dev,key_b)
			if ret is None:
				sys.exit('Failed to write key for flash verify to CH5xx.')
			print('Verifying flash.',end='')
			ret = __flash_ops_write_verify(dev, enc_key, flash_verify_data, func="FlashVerify")
			if ret is None:
				sys.exit(' Failed to verify firmware of CH55x.')
			else:
				print(' Done.')
		else:
			print('Nothing to verifying with program flash.')

	print('Finalize communication.',end="")
	ret, ret_pl = __end_flash_ch5xx(dev, restart_after = args.reset_at_end)
	if(ret is True):
		print(' Restart and run.')
	elif(ret is None):
		sys.exit('Failed to finish communication. No response.')
	else:
		if(ret_pl != None):
			if ret_pl[0] != 0x00:
				resp_str = ' Response: %02x' % (ret_pl[0])
				sys.exit('Failed to finish communication.'+ resp_str)
			else:
				print(' Done.')
		else:
			sys.exit('Failed to finish communication. Response without value.')

if __name__ == '__main__':
	sys.exit(main())
