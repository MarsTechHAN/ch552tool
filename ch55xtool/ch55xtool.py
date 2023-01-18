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
				"ReadOTP":		b'\xC4',
				"WriteOTP":		b'\xC3',
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
def get_chip_parameters(chip_id,wcfg_path, user_param_file='' ):
	chip_params = {}
	params_ini = configparser.ConfigParser()
	#params_ini.optionxform = lambda option: option
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

	params_ini_ext = configparser.ConfigParser()
	#params_ini_ext.optionxform = lambda option: option
	params_ini_ext.read(wcfg_path+'/extended.wcfg')
	for section in params_ini_ext.sections():
		if(params_ini_ext.has_option(section,'chipid')):
			if(params_ini_ext.getint(section,'chipid') == chip_id):
				chip_params.update({'name':section})
				chip_params.update({'chip_id':chip_id})
				chip_params.update({'flash_size':params_ini_ext.getint(section,'MaxFlashSize')})
				chip_params.update({'dataflash_size':params_ini_ext.getint(section,'MaxEepromSize')})
				if(params_ini_ext.has_option(section,'McuType')):
					chip_params.update({'McuType':params_ini_ext.getint(section,'McuType')})
				break

	# Check we found any and all mandatory params exist
	if(chip_params.get('chip_id') == None or chip_params.get('name') == None):
		return None
	missing_defs = []
	if( chip_params.get('flash_size')     == None): missing_defs.append('MaxFlashSize')
	if( chip_params.get('dataflash_size') == None): missing_defs.append('MaxEepromSize')
	if(missing_defs):
		print('Chip configuration definitions shortage, mandatory fiels',missing_defs)
		return None

	section = chip_params.get('name')
	if(params_ini_ext.has_section(section)):
		if(params_ini_ext.has_option(section,'Tested')):
			chip_params.update({'tested':params_ini_ext.getboolean(section,'Tested')})
		if(params_ini_ext.has_option(section,'CFGs')):
			chip_params.update({'cfgs_bits':eval(params_ini_ext.get(section,'CFGs'))})

	if(user_param_file):
		params_ini_usr = configparser.ConfigParser()
		#params_ini_usr.optionxform = lambda option: option
		params_ini_usr.read(user_param_file)
		if(params_ini_usr.has_section(section)):
			if(params_ini_usr.has_option(section,'Tested')):
				chip_params.update({'tested':params_ini_usr.getboolean(section,'Tested')})
			if(params_ini_usr.has_option(section,'CFGs')):
				if(chip_params.get('cfgs_bits') == None):
					chip_params.update({'cfgs_bits':eval(params_ini_usr.get(section,'CFGs'))})
				else:
					chip_params['cfgs_bits'].update(eval(params_ini_usr.get(section,'CFGs')))
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
	cfg_fields = cfg_dict.get("Fields")
	if(cfg_fields is None):
		print("Not defined fields to set configuration.")
		return None, None
	set_fields	= 0
	cmd_pl 		= b''
	if(cfg_fields & FLAG_CFG1):
		field_val = cfg_dict.get(FLAG_CFG1)
		if(field_val != None):
			set_fields	|= FLAG_CFG1
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG1))

	if(cfg_fields & FLAG_CFG2):
		field_val = cfg_dict.get(FLAG_CFG2)
		if(field_val != None):
			set_fields	|= FLAG_CFG2
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG2))

	if(cfg_fields & FLAG_CFG3):
		field_val = cfg_dict.get(FLAG_CFG3)
		if(field_val != None):
			set_fields	|= FLAG_CFG3
			cmd_pl 		+= field_val.to_bytes(4,'little')
		else:
			print("Incorrect or no value for cfg field 0x%02X"%(FLAG_CFG3))

	if(set_fields > 0):
		cmd_pl = set_fields.to_bytes(2,'little') + cmd_pl
		ret, ret_pl = cmd_exec(dev, 'WriteConfig', cmd_pl)
		return ret, ret_pl
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
		return False, -1
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
			return False, curr_addr
			
		curr_addr = curr_addr + pkt_length
	if(curr_addr > data_length):
		return True, data_length
	else:
		return True, curr_addr

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
	return cmd_exec(dev, "End", cmd_pl)

def __get_list_from_given_options(options):
	opt_list = []
	for opt_l in options:
		for opt in opt_l:
			for spl_opt in opt.split(','):
				opt_list.append(spl_opt.split('='))
	return opt_list

def __check_option_list(opt_list, chip_ref, verbose=False):
		opt_good = True
		if(chip_ref.get('cfgs_bits')):
			for opt in opt_list:
				if(chip_ref['cfgs_bits'].get(opt[0]) == None):
					print("Chip %s do not have option: %s" % (chip_ref['name'], opt[0]) )
					opt_good = False
				elif(chip_ref['cfgs_bits'][opt[0]].get('need_value') and len(opt)<2 ):
					print("Chip %s option: %s need value be given by %s=value" % (chip_ref['name'], opt[0], opt[0]) )
					opt_good = False
				elif(len(opt)>1 and not chip_ref['cfgs_bits'][opt[0]].get('need_value') ):
					print("Chip %s option: %s do not accept value but given =%d" % (chip_ref['name'], opt[0], eval(opt[1]) ) )
					opt_good = False
				else:
					cfg_opt_dict = chip_ref['cfgs_bits'].get(opt[0])
					if(len(opt)>1):
						value = eval(opt[1])
						for cfg_flag in [FLAG_CFG1 , FLAG_CFG2, FLAG_CFG3]:
							cfg_flag_dict = chip_ref['cfgs_bits'][opt[0]].get(cfg_flag)
							if(cfg_flag_dict):
								cfg_flag_v = cfg_flag
								break
						if(cfg_flag_dict):
							#if(cfg_flag_dict.get('mask')):
							val_mask = chip_ref['cfgs_bits'][opt[0]][cfg_flag].get('mask')
							if(value & val_mask != value):
								print("Chip %s option: %s given value 0x%08x out of mask 0x%08x" % (chip_ref['name'], opt[0], value , val_mask) ) 
								opt_good = False
							elif(verbose):
								print("Chip %s Good option: %s value %d" % (chip_ref['name'], opt[0], eval(opt[1]) ) )
					else:
						if(verbose):
							print("Chip %s Good option: %s" % (chip_ref['name'], opt[0]) )
				if(not opt_good and not verbose):
					break
		else:
			print("Chip %s do not have any config options to use." % (chip_ref['name']))
			opt_good = False
		return opt_good

def __apply_option_list(opt_list, chip_ref, chip_cfgs, verbose=False):
	cfgs_changed = False
	result_d = {}
	result_d.update(chip_cfgs.copy())
	for opt in [['_reserved']] + opt_list:
		cfg_opt_dict = chip_ref['cfgs_bits'].get(opt[0])
		for cfg_flag in [FLAG_CFG1 , FLAG_CFG2, FLAG_CFG3]:
			cfg_flag_dict = cfg_opt_dict.get(cfg_flag)
			if(cfg_flag_dict and (chip_cfgs['Fields'] & cfg_flag == cfg_flag) ):
				if(cfg_opt_dict.get('need_value')):
					value = eval(opt[1])
				else:
					value = cfg_flag_dict.get('value')
				new_val = ( result_d[cfg_flag] & ( 0xffffffff ^ cfg_flag_dict.get('mask') ) ) | value 
				if(	opt[0] not in ['_reserved']):
					if(	result_d[cfg_flag] != new_val ):
						cfgs_changed = True
						print("Config get changed")
					else:
						print("Configuration option %s already in chip configs." % (opt[0]))
				result_d.update( { cfg_flag : new_val }  )
			if(cfg_opt_dict.get('need_value')):
				break
	return cfgs_changed, result_d

def main():
	pathname = os.path.dirname(__file__) if '__file__' in globals() else os.path.dirname(sys.argv[0])
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
		'--print_otp', type=int,
		help="Read and print OTP.")

	parser.add_argument(
		'-o', '--cfgs_options', action='append', nargs='+',
		help="Apply configuration options before operations.")
	parser.add_argument(
		'-a', '--cfgs_options_after', action='append', nargs='+',
		help="Apply configuration options after operations.")
	parser.add_argument(
		'--cfgs_options_force_action', action='store_true', default=False,
		help="!Warning! Use on own risk, configuration options enable action (writing).")
	parser.add_argument(
		'--cfgs_options_list', type=str, action='store', nargs='?', const='', default=None,
		help="List configuration options for detected chip or optional given chip name.")

	parser.add_argument(
		'-u', '--user_def', type=str, default='',
		help="Use additional user chip definition INI file.")

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

	verb = args.verbose
	addr = 0
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

	if(args.user_def):
		chip_ref = get_chip_parameters(chip_id, fullpath, args.user_def)
	else:
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

	# To prevent "detection break"
	_, _, _ = __detect_ch5xx(dev)

	ver_str = '%d%d.%d%d' % (bootver[0], bootver[1], bootver[2], bootver[3])
	print('BTVER:%s' % ver_str)

	uid_str = '%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X' % (uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7])
	print('UID:%s' % uid_str)

	if(float(ver_str)<2.3):
		sys.exit('Bootloader version not supported.')

	chk_sum = __chip_uid_chk_sum(chip_subid, uid)

	if(args.cfgs_options_list != None):
		if(args.cfgs_options_list != ''):
			print("Printing options for given name not supported")
		else:
			cfgs_opt_dict = chip_ref.get('cfgs_bits')
			if(cfgs_opt_dict):
				for opt_name in cfgs_opt_dict.keys():
					if(cfgs_opt_dict[opt_name].get('need_value')):
						val_str = '=xxx'
					else:
						val_str = ''
					if(opt_name in ['_reserved']):
						continue
					opt_help = cfgs_opt_dict[opt_name].get('help')
					if(opt_help):
						print("Option '%s'\t - %s" % (opt_name+val_str, opt_help))
					else:
						print("Option '%s'\t - no description" % (opt_name+val_str))
			else:
				print("No known options for found chip.")

	if(args.cfgs_options):
		if(args.cfgs_options_force_action):
			print(" Configuration options action is high RISK, you take action on YOUR OWN RISK !!")
		else:
			print(" Configuration options work in simulation mode. No real action (updating/writing).\r\n To force real action at YOUR OWN RISK use '--cfgs_options_force_action'!!")
		opt_list = __get_list_from_given_options(args.cfgs_options)
		# Check all options exist and meet defines
		if(not __check_option_list(opt_list,chip_ref, verb)):
			print('Config options error.')
			sys.exit(-1)

	if(args.cfgs_options_after):
		if(args.cfgs_options_force_action):
			print(" Configuration options action is high RISK, you take action on YOUR OWN RISK !!")
		else:
			print(" Configuration options work in simulation mode. No real action (updating/writing).\r\n To force real action at YOUR OWN RISK use '--cfgs_options_force_action'!!")

		opt_list_after = __get_list_from_given_options(args.cfgs_options_after)
		# Check all options exist and meet defines
		if(not __check_option_list(opt_list_after,chip_ref, verb)):
			print('Config after options error.')
			sys.exit(-1)
		ret, chip_cfg = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		if ret is None:
			print('Cannot read chip configs variables.')
			sys.exit(-1)

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
			
			# To prevent "detection break"
			_, _, _ = __detect_ch5xx(dev)

	if(args.print_otp is not None):
		cmd_pl = args.print_otp.to_bytes(1,"little")
		print("Reading OTP",end="")
		ret, chip_otp = cmd_exec(dev, "ReadOTP", cmd_pl)
		if(ret is None):
			print('Cannot read chip OTP.')
			sys.exit(-1)
		else:
			if(chip_otp[0] == 0 and chip_otp[1] == 0 and len(chip_otp)>2 ) :
				print(":", list(chip_otp[2:]))
			else:
				print(" Respond failure:",list(chip_otp) )

	if(args.cfgs_options):
		ret, chip_cfg = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		if(ret is None):
			print('Cannot read chip configs variables.')
			sys.exit(-1)
		if( chip_cfg.get(FLAG_CFG1) is None or
			chip_cfg.get(FLAG_CFG2) is None or
			chip_cfg.get(FLAG_CFG3) is None
			):
			print('Cannot find chip configurations after read.')
			sys.exit(-1)

		cfg_changed, new_cfg = __apply_option_list(opt_list,chip_ref,chip_cfg)

		if(verb):
			cfg1 = chip_cfg.get(FLAG_CFG1)
			cfg2 = chip_cfg.get(FLAG_CFG2)
			cfg3 = chip_cfg.get(FLAG_CFG3)
			
			ncfg1 = new_cfg.get(FLAG_CFG1)
			ncfg2 = new_cfg.get(FLAG_CFG2)
			ncfg3 = new_cfg.get(FLAG_CFG3)
			print("Chip configs before apply 0x%08X   0x%08X   0x%08X" % (cfg1, cfg2, cfg3) )
			print("Chip configs after apply  0x%08X   0x%08X   0x%08X" % (ncfg1, ncfg2, ncfg3) )

		if(args.cfgs_options_force_action and cfg_changed):
			ret, ret_pl = __write_cfg_ch5xx(dev, new_cfg)
			if(ret is None):
				print('Cannot write chip configs variables.')
				sys.exit(-1)
			elif(ret_pl[0]):
				print('Error at writing chip configs variables. Resp: ', ret_pl[:])
				sys.exit(-1)
			# To repeat original SW
			_, _ = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		elif(not cfg_changed):
			print('All given configuration options already set, nothing to realy write.')
		# To prevent "detection break"
		_, _, _ = __detect_ch5xx(dev)

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
			ret, addr = __flash_ops_write_verify(dev, enc_key, dataflash_write_data, func="DataWrite")
			if(ret):
				if(verb):
					print(' Done. Amount: %d ' % (addr) )
				else:
					print(' Done. ')
			else:
				sys.exit(' Failed. Address %d' %(addr) )
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
				sys.exit(' Data read failed. Read amount %d.' %(len(ret_data)))
			elif(len(ret_data) != len(dataflash_verify_data)):
				sys.exit(' Failed. Sizes differ: received %d to compare %d' %(len(ret_data), len(dataflash_verify_data)) )
			elif(ret_data != dataflash_verify_data):
				print(' Compare failed ', end='')
				for i in range(len(ret_data)):
					if(ret_data[i] != dataflash_verify_data[i]):
						print('at address %d.' %(i))
						break
				sys.exit(-1)
			else:
				if(verb):
					print(' Done. Amount: %d ' % (len(ret_data)) )
				else:
					print(' Done. ')
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
			ret, addr = __flash_ops_write_verify(dev, enc_key, flash_write_data, func="FlashWrite")
			if(ret):
				if(verb):
					print(' Done. Amount: %d ' % (addr) )
				else:
					print(' Done. ')
			else:
				sys.exit(' Failed. Address %d' %(addr) )
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
			ret, addr = __flash_ops_write_verify(dev, enc_key, flash_verify_data, func="FlashVerify")
			if(ret):
				if(verb):
					print(' Done. Amount: %d ' % (addr) )
				else:
					print(' Done. ')
			else:
				sys.exit(' Failed. Address %d' %(addr) )
		else:
			print('Nothing to verifying with program flash.')

	if(args.cfgs_options_after):
		ret, chip_cfg = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		if(ret is None):
			print('Cannot read chip configs variables.')
			sys.exit(-1)
		if( chip_cfg.get(FLAG_CFG1) is None or
			chip_cfg.get(FLAG_CFG2) is None or
			chip_cfg.get(FLAG_CFG3) is None
			):
			print('Cannot find chip configurations after read.')
			sys.exit(-1)

		cfg_changed, new_cfg = __apply_option_list(opt_list_after,chip_ref,chip_cfg)

		if(verb):
			cfg1 = chip_cfg.get(FLAG_CFG1)
			cfg2 = chip_cfg.get(FLAG_CFG2)
			cfg3 = chip_cfg.get(FLAG_CFG3)
			
			ncfg1 = new_cfg.get(FLAG_CFG1)
			ncfg2 = new_cfg.get(FLAG_CFG2)
			ncfg3 = new_cfg.get(FLAG_CFG3)
			print("Chip configs before apply 0x%08X   0x%08X   0x%08X" % (cfg1, cfg2, cfg3) )
			print("Chip configs after apply  0x%08X   0x%08X   0x%08X" % (ncfg1, ncfg2, ncfg3) )

		if(args.cfgs_options_force_action and cfg_changed):
			ret, ret_pl = __write_cfg_ch5xx(dev, new_cfg)
			if(ret is None):
				print('Cannot write chip configs variables.')
				sys.exit(-1)
			elif(ret_pl[0]):
				print('Error at writing chip configs variables. Resp: ', ret_pl[:])
				sys.exit(-1)
			# To repeat original SW
			_, _ = __read_cfg_ch5xx(dev, FLAG_CFGs, chip_id, chip_subid)
		elif(not cfg_changed):
			print('All given configuration options already set, nothing to realy write.')

		# To prevent "detection break"
		_, _, _ = __detect_ch5xx(dev)

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
